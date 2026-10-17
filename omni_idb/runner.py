"""Batch execution: drives headless IDA, streams its output and auth/test helpers."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .config import AppSettings, auth_script, cache_path, find_genesect_package_root, project_root, runner_script
from .discovery import Sample, SampleKind
from . import reporting

EVENT_PREFIX = "OMNI_EVENT "
LEGACY_EVENT_PREFIX = "GENESECT_EVENT "


@dataclass
class OmniEvent:
    sample_index: int
    kind: str
    level: Optional[str]
    stage: Optional[str]
    current: Optional[int]
    total: Optional[int]
    message: str
    raw: str


# Legacy alias
GenesectEvent = OmniEvent


@dataclass
class RunnerEvent:
    """Message posted to the UI queue. ``kind`` selects which fields are populated."""

    kind: str
    data: dict[str, Any] = field(default_factory=dict)

    def __getattr__(self, name: str) -> Any:  # convenient access to payload fields
        try:
            return self.__dict__["data"][name]
        except KeyError as error:
            raise AttributeError(name) from error


@dataclass
class RunRequest:
    settings: AppSettings
    api_key: str
    samples: list[Sample]
    fallback_api_key: str = ""


def _post(q: "queue.Queue[RunnerEvent]", kind: str, **data: Any) -> None:
    q.put(RunnerEvent(kind, data))


def start(request: RunRequest, q: "queue.Queue[RunnerEvent]") -> threading.Event:
    cancelled = threading.Event()
    threading.Thread(target=_run_all, args=(request, q, cancelled), daemon=True).start()
    return cancelled


def _run_all(request: RunRequest, q, cancelled: threading.Event) -> None:
    total = len(request.samples)
    _post(q, "batch_started", total=total)
    succeeded = failed = 0
    settings = request.settings
    initial_budget = int(getattr(settings, "token_budget", 0) or 0)
    remaining_budget = initial_budget if initial_budget > 0 else None
    batch_tokens = 0
    batch_cost = 0.0

    for index, sample in enumerate(request.samples):
        if cancelled.is_set():
            break
        _post(q, "sample_started", index=index, path=sample.path)
        init_msg = f"Processing {sample.path.name}" if sample.kind == SampleKind.DOTNET_ASSEMBLY else f"Opening {sample.path.name} in IDA"
        _post(q, "progress", current=index, total=total, message=init_msg)
        try:
            message, sample_result = _run_one(index, sample, request, q, cancelled, remaining_budget=remaining_budget)
            if sample_result and isinstance(sample_result, dict):
                usage = sample_result.get("usage")
                if usage:
                    billable = usage.get("billable_tokens", 0)
                    batch_tokens += usage.get("total_tokens", 0)
                    batch_cost += usage.get("estimated_cost_usd", 0.0)
                    if remaining_budget is not None:
                        remaining_budget = max(0, remaining_budget - billable)
                        if remaining_budget == 0:
                            _post(q, "log", message="Batch token budget has been fully consumed.")
        except Exception as error:  # noqa: BLE001 - every failure is reported per sample
            failed += 1
            message = f"{sample.path}: {error}"
            _post(q, "log", message=message)
            _post(q, "sample_finished", index=index, ok=False, message=message)
        else:
            succeeded += 1
            _post(q, "sample_finished", index=index, ok=True, message=message)
    was_cancelled = cancelled.is_set()
    if batch_tokens > 0:
        cost_str = f" (~${batch_cost:.3f})" if batch_cost > 0 else ""
        _post(q, "log", message=f"Batch AI totals: {batch_tokens:,} tokens{cost_str}")
    _post(
        q,
        "progress",
        current=succeeded + failed,
        total=total,
        message="Cancelled" if was_cancelled else "Complete",
    )
    _post(q, "batch_finished", succeeded=succeeded, failed=failed, cancelled=was_cancelled)


def sanitize(value: str) -> str:
    clean = "".join(ch if (ch.isascii() and ch.isalnum()) or ch in "-_" else "_" for ch in value)[:80]
    return clean or "sample"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ida_script_argument(script: Path | str, job: Path | str) -> str:
    # In IDA Pro, -S runs the IDAPython script. Job payload is safely communicated
    # via OMNI_IDB_JOB_FILE in the process environment to prevent argument splitting.
    return f'-S"{script}"'


def remove_previous_run_files(paths) -> None:
    for artifact in paths:
        try:
            Path(artifact).unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise OSError(f"Could not replace previous output {artifact}: {error}") from error


def _tail(text: str, maximum: int) -> str:
    return text if len(text) <= maximum else text[-maximum:]


def _spawn_ida(ida: Path, args: list[str], script_arg: str, sample_path: Path, env) -> subprocess.Popen:
    kwargs: dict[str, Any] = dict(
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, encoding="utf-8", errors="replace"
    )
    if sys.platform == "win32":
        # Pass the command line verbatim: IDA parses -S"script" "job" itself and
        # list2cmdline would backslash-escape the embedded quotes.
        cmdline = " ".join([subprocess.list2cmdline([str(ida), *args]), script_arg, subprocess.list2cmdline([str(sample_path)])])
        return subprocess.Popen(cmdline, **kwargs)
    return subprocess.Popen([str(ida), *args, script_arg, str(sample_path)], **kwargs)


def _tail_file(path: Path, stop: threading.Event, q, index: Optional[int] = None) -> None:
    handle = None
    pending = ""

    def drain(final: bool) -> None:
        nonlocal pending
        while True:
            chunk = handle.readline()
            if not chunk:
                break
            pending += chunk
            if pending.endswith("\n") or final:
                line = pending.rstrip("\r\n")
                pending = ""
                if line:
                    _post(q, "ida_log_line", message=line)
                    if index is not None:
                        _handle_ida_line(index, line, q)
            else:
                break

    while not stop.is_set():
        if handle is None:
            try:
                handle = open(path, "r", encoding="utf-8", errors="replace")
            except OSError:
                handle = None
        if handle is not None:
            drain(False)
        time.sleep(0.15)
    if handle is None:
        try:
            handle = open(path, "r", encoding="utf-8", errors="replace")
        except OSError:
            return
    drain(True)
    handle.close()


def _pipe_lines(stream, out: "queue.Queue[str]") -> None:
    def pump() -> None:
        try:
            for line in stream:
                out.put(line.rstrip("\r\n"))
        except (OSError, ValueError):
            pass

    threading.Thread(target=pump, daemon=True).start()


def _run_one(index: int, sample: Sample, request: RunRequest, q, cancelled: threading.Event, remaining_budget: Optional[int] = None) -> tuple[str, dict]:
    settings = request.settings
    digest = sha256_file(sample.path)
    folder = f"{sanitize(sample.path.stem)}-{digest[:12]}"
    output_root = Path(settings.output_root.strip()) / folder
    idb_dir = output_root / "IDB Files"
    workspace = output_root / "AI Workspace"
    report_dir = output_root / "report"
    logs = output_root / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    idb_path = idb_dir / "analyzed.i64"
    original_idb_path = idb_dir / "original.i64"
    result_path = output_root / "result.json"
    failure_path = logs / "failure.txt"
    ida_log = logs / "ida.log"

    # .NET Assembly special handling (does not require IDA Pro)
    if sample.kind == SampleKind.DOTNET_ASSEMBLY:
        # Older versions created this native-only directory before branching.
        # Remove it only when empty so a managed run never displays a fake IDB deliverable.
        try:
            idb_dir.rmdir()
        except (FileNotFoundError, OSError):
            pass
        dotnet_mode = getattr(settings, "dotnet_mode", "skip")
        should_analyze_workspace = settings.analyze_workspace

        # If user selected In-Database Agent Analysis, IDA cannot decompile .NET CIL bytecode.
        # Automatically fallback to Decompile & AI Workspace Analysis so the user still gets a full report.
        if settings.autonomous_investigation:
            if dotnet_mode == "skip":
                dotnet_mode = "decompile"
                _post(q, "log", message=f"[*] In-Database Agent Analysis does not apply to managed .NET ({sample.path.name}). Auto-falling back to Decompile & AI Workspace Analysis.")
            should_analyze_workspace = True

        if dotnet_mode == "skip":
            _post(q, "sample_status", index=index, status="Skipped (.NET)")
            _post(q, "sample_stage", index=index, stage="Skipped")
            skip_msg = f"Skipping {sample.path.name}: .NET assembly detected (IDA Pro Hex-Rays targets native binaries)."
            _post(q, "log", message=skip_msg)
            return f"Skipped .NET assembly ({sample.path.name})", {"status": "skipped", "reason": "dotnet_assembly"}
        elif dotnet_mode == "decompile":
            _post(q, "sample_status", index=index, status="Decompiling .NET")
            _post(q, "sample_stage", index=index, stage="Exporting .NET Workspace")
            _post(q, "log", message=f"Decompiling .NET assembly & exporting AI workspace: {sample.path.name}")
            from .dotnet_export import export_dotnet_workspace
            ws_meta = export_dotnet_workspace(sample.path, output_root, log_fn=lambda m: _post(q, "log", message=m))
            res = {
                "sample": str(sample.path),
                "is_dotnet": True,
                "workspace_path": ws_meta.get("workspace_dir", ""),
                "types_count": ws_meta.get("types_count", 0),
                "pinvokes_count": ws_meta.get("pinvokes_count", 0),
                "strings_count": ws_meta.get("strings_count", 0),
                "cs_count": ws_meta.get("cs_count", 0),
                "cil_count": ws_meta.get("cil_count", 0),
            }
            if should_analyze_workspace:
                _post(q, "sample_status", index=index, status="Analyzing .NET Workspace")
                _post(q, "sample_stage", index=index, stage="Analyzing AI Workspace")
                from .workspace_analysis import analyze_workspace

                analysis = analyze_workspace(
                    ws_meta["workspace_dir"],
                    {
                        "provider": settings.provider,
                        "api_url": settings.api_url,
                        "api_key": request.api_key,
                        "model": settings.model,
                        "executable": settings.executable,
                    },
                    {
                        "provider": settings.fallback_provider,
                        "api_url": settings.fallback_api_url,
                        "api_key": request.fallback_api_key,
                        "model": settings.fallback_model,
                        "executable": settings.fallback_executable,
                    } if settings.fallback_enabled else None,
                    genesect_root=settings.genesect_root,
                    ida_path=settings.ida_path,
                    token_budget=remaining_budget or 0,
                    log_fn=lambda message: _post(q, "log", message=message),
                    cancel_checker=cancelled.is_set,
                )
                res["workspace_analysis_report"] = analysis["report_path"]
                res["provider"] = {
                    "primary": settings.provider,
                    "active": analysis["provider"],
                    "used": list(dict.fromkeys([settings.provider, analysis["provider"]])),
                    "fallback_events": analysis["fallback_events"],
                }
                res["usage"] = analysis["usage"]
            result_path.write_text(json.dumps(res, indent=2), encoding="utf-8")
            parts = [
                f"{res['types_count']} types",
                f"{res['pinvokes_count']} P/Invokes",
                f"{res['strings_count']} strings",
            ]
            if res["cs_count"] > 0:
                parts.append(f"{res['cs_count']} C# files")
            if res.get("workspace_analysis_report"):
                parts.append("workspace analysis: done")
            return f"Completed .NET AI Workspace ({', '.join(parts)})", res

    idb_dir.mkdir(parents=True, exist_ok=True)
    ida = Path(settings.ida_path.strip())
    if not ida.is_file():
        raise FileNotFoundError(f"IDA executable not found: {ida}")
    genesect_root = Path(settings.genesect_root.strip())
    script = runner_script(genesect_root)
    if not script.is_file():
        raise FileNotFoundError(f"OmniIDB batch script not found: {script}")

    # Output folders are deterministic. IDA prompts instead of overwriting an
    # existing database and a stale failure file can mask a new failure, so
    # remove only the generated per-run files first.
    remove_previous_run_files([idb_path, original_idb_path, result_path, failure_path, ida_log])

    job = {
        "omni_root": str(project_root().resolve()),
        "sample_path": str(sample.path.resolve()),
        "genesect_root": str((find_genesect_package_root(genesect_root, ida.parent) or genesect_root).resolve()),
        "idb_path": str(idb_path),
        "original_idb_path": str(original_idb_path),
        "workspace_path": str(workspace),
        "report_dir": str(report_dir),
        "result_path": str(result_path),
        "failure_path": str(failure_path),
        "sample_kind": sample.kind.job_value,
        "shellcode_arch": settings.shellcode_arch,
        "rename_functions": settings.rename_functions,
        "rename_variables": settings.rename_variables,
        "generate_workspace": settings.generate_workspace,
        "analyze_workspace": settings.analyze_workspace,
        "autonomous_investigation": settings.autonomous_investigation,
        "investigation_turns": settings.investigation_turns,
        "batch_size": settings.batch_size,
        "cooldown_seconds": settings.cooldown_seconds,
        "asm_max_lines": 25,
        "use_rename_cache": getattr(settings, "use_rename_cache", True),
        "cache_path": str(cache_path().resolve()),
        "goresym_path": getattr(settings, "goresym_path", ""),
        "token_budget": remaining_budget if remaining_budget is not None else int(getattr(settings, "token_budget", 0) or 0),
        "provider": settings.provider,
        "profile": {
            "provider": settings.provider,
            "api_url": settings.api_url,
            "api_key": request.api_key,
            "model": settings.model,
            "executable": settings.executable,
        },
        "fallback_enabled": settings.fallback_enabled,
        "fallback_profile": {
            "provider": settings.fallback_provider,
            "api_url": settings.fallback_api_url,
            "api_key": request.fallback_api_key,
            "model": settings.fallback_model,
            "executable": settings.fallback_executable,
        },
    }

    fd, job_name = tempfile.mkstemp(prefix="omni-job-", suffix=".json")
    job_file = Path(job_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(job, handle, indent=2)

        args = ["-A", f"-L{ida_log}", f"-o{idb_path}"]
        if sample.kind == SampleKind.SHELLCODE:
            # Skip the loader dialog and use IDA's raw binary loader; the batch
            # script sets the exact segment/application bitness.
            args += ["-TBinary", "-pmetapc"]

        env = os.environ.copy()
        for name in ("VIRTUAL_ENV", "__PYVENV_LAUNCHER__", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONEXECUTABLE", "PYTHONINSPECT"):
            env.pop(name, None)
        env["OMNI_IDB_JOB_FILE"] = str(job_file.resolve())

        _post(q, "sample_status", index=index, status="Running in IDA")
        try:
            child = _spawn_ida(ida, args, ida_script_argument(script, job_file), sample.path, env)
        except OSError as error:
            raise OSError(f"Could not start {ida}: {error}") from error

        lines: "queue.Queue[str]" = queue.Queue()
        _pipe_lines(child.stdout, lines)
        _pipe_lines(child.stderr, lines)
        stop_tail = threading.Event()
        tail_thread = threading.Thread(target=_tail_file, args=(ida_log, stop_tail, q, index), daemon=True)
        tail_thread.start()

        def flush_lines() -> None:
            while True:
                try:
                    _handle_ida_line(index, lines.get_nowait(), q)
                except queue.Empty:
                    return

        while True:
            flush_lines()
            if cancelled.is_set():
                stop_tail.set()
                tail_thread.join()
                child.kill()
                child.wait()
                raise RuntimeError("Cancelled by user")
            code = child.poll()
            if code is not None:
                break
            time.sleep(0.12)
        stop_tail.set()
        tail_thread.join()
        time.sleep(0.05)
        flush_lines()
    finally:
        try:
            job_file.unlink()
        except OSError:
            pass

    if code != 0:
        details = "IDA did not provide error details."
        for source in (failure_path, ida_log):
            try:
                details = source.read_text(encoding="utf-8", errors="replace")
                break
            except OSError:
                continue
        raise RuntimeError(f"IDA exited with {code}\n{_tail(details, 5000)}")
    if not idb_path.is_file():
        raise RuntimeError(f"IDA completed but did not create {idb_path}")
    if not result_path.is_file():
        raise RuntimeError(f"IDA completed but did not create {result_path}")

    # Render publication-grade Markdown, HTML, and PDF reports if model JSON was produced.
    model_json = report_dir / "report_model.json"
    if model_json.is_file():
        try:
            _post(q, "log", message=f"Rendering report deliverables (MD, HTML, PDF) in {report_dir}")
            reporting.render_reports(model_json, report_dir, log_fn=lambda m: _post(q, "log", message=m))
        except Exception as exc:
            _post(q, "log", message=f"Warning: Failed to render reports: {exc}")

    result = json.loads(result_path.read_text(encoding="utf-8"))
    renamed = _dig(result, "function_rename", "renamed") or 0
    fn_skipped = _dig(result, "function_rename", "skipped")
    fn_text = "funcs: skipped" if fn_skipped else f"{renamed} functions"
    variables = _dig(result, "variable_rename", "variables_renamed") or 0
    var_skipped = _dig(result, "variable_rename", "skipped")
    var_text = "vars: skipped" if var_skipped else f"{variables} variables"
    parts = [fn_text, var_text]
    fn_cache_hits = _dig(result, "function_rename", "cache_hits") or 0
    var_cache_hits = _dig(result, "variable_rename", "cache_hits") or 0
    total_cache_hits = fn_cache_hits + var_cache_hits
    if total_cache_hits:
        parts.append(f"cache: {total_cache_hits} hits")
    findings = _dig(result, "autonomous_investigation", "findings_count")
    if findings is not None:
        turns = _dig(result, "autonomous_investigation", "turns_executed") or 0
        parts.append(f"agent: {findings} findings/{turns} turns")

    usage = result.get("usage")
    if usage and usage.get("total_tokens"):
        tokens_desc = f"{usage.get('total_tokens', 0):,} tok"
        if usage.get("estimated_cost_usd", 0) > 0:
            tokens_desc += f" (~${usage['estimated_cost_usd']:.3f})"
        parts.append(tokens_desc)

    idb_names = [idb_path.name]
    if original_idb_path.is_file():
        idb_names.append(original_idb_path.name)
    reports = [p.name for p in [report_dir / "report.md", report_dir / "report.html", report_dir / "report.pdf"] if p.is_file()]
    if reports:
        parts.append(f"reports: {', '.join(reports)}")
    if result.get("workspace_analysis_report"):
        parts.append("workspace analysis: done")
    return f"Saved {' & '.join(idb_names)} ({', '.join(parts)})", result


def _dig(value: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _as_int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


STAGE_NAMES = {
    "ida": "Opening in IDA",
    "scan": "Scanning Functions",
    "functions": "Renaming Functions",
    "variables": "Renaming Variables",
    "investigation": "Investigating Sample",
    "workspace": "Exporting AI Workspace",
    "workspace_analysis": "Analyzing AI Workspace",
    "report": "Generating Reports",
    "save": "Saving IDB Files",
    "shellcode": "Loading Shellcode",
}


def _handle_ida_line(index: int, line: str, q) -> None:
    trimmed = line.rstrip("\r\n")
    if not trimmed:
        return
    prefix = None
    if trimmed.startswith(EVENT_PREFIX):
        prefix = EVENT_PREFIX
    elif trimmed.startswith(LEGACY_EVENT_PREFIX):
        prefix = LEGACY_EVENT_PREFIX
    if not prefix:
        return
    payload = trimmed[len(prefix) :].strip()
    try:
        payload = json.loads(payload)
    except json.JSONDecodeError:
        return
    if isinstance(payload, dict):
        kind = payload.get("kind") if isinstance(payload.get("kind"), str) else "log"
        message = payload.get("message") if isinstance(payload.get("message"), str) else ""
        level = payload.get("level") if isinstance(payload.get("level"), str) else None
        stage = payload.get("stage") if isinstance(payload.get("stage"), str) else None
        event = OmniEvent(
            sample_index=index,
            kind=kind,
            level=level,
            stage=stage,
            current=_as_int(payload.get("current")),
            total=_as_int(payload.get("total")),
            message=message,
            raw=trimmed,
        )
        _post(q, "omni_event", event=event)
        _post(q, "genesect_event", event=event)
        if stage and stage in STAGE_NAMES:
            _post(q, "sample_stage", index=index, stage=STAGE_NAMES[stage])
        if kind == "provider_switch":
            _post(
                q,
                "provider_switch",
                message=message,
                provider_from=payload.get("provider_from"),
                provider_to=payload.get("provider_to"),
            )
        if kind in ("progress", "stage"):
            _post(q, "sample_status", index=index, status=message)
        if message:
            _post(q, "log", message=message)


# --------------------------------------------------------------------------
# Authentication / connection helpers
# --------------------------------------------------------------------------

def _python_cmd() -> list[str]:
    if getattr(sys, "frozen", False):
        for candidate in ("python", "python3", "py"):
            found = shutil.which(candidate)
            if found:
                return [found]
        return ["python"]
    return [sys.executable or "python"]


def _script_env(genesect_root, ida_path: str = "") -> dict:
    """Environment that lets scripts ``import genesect`` (found next to IDA, if needed)."""
    env = os.environ.copy()
    package_root = find_genesect_package_root(genesect_root, Path(ida_path).parent if ida_path.strip() else "")
    if package_root:
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(package_root), env.get("PYTHONPATH", "")]))
    return env


def _load_auth_cli_module(genesect_root: Path | str, ida_path: str = ""):
    """Dynamically load scripts/auth_cli.py for direct, in-process execution."""
    script = auth_script(genesect_root)
    package_root = find_genesect_package_root(genesect_root, Path(ida_path).parent if ida_path.strip() else "")
    if package_root and str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))

    if not script.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("omni_idb_auth_cli", str(script))
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    except Exception:
        pass
    return None


def start_chatgpt_auth(genesect_root: Path | str, q, ida_path: str = "") -> None:
    def work() -> None:
        try:
            mod = _load_auth_cli_module(genesect_root, ida_path)
            if mod:
                from genesect import chatgpt_oauth
                data = chatgpt_oauth.sign_in_interactive()
                _post(q, "auth_finished", ok=True, message="ChatGPT sign-in complete.")
                return
        except Exception:
            pass

        script = auth_script(genesect_root)
        try:
            out = subprocess.run(
                [*_python_cmd(), str(script), "sign-in"], env=_script_env(genesect_root, ida_path), capture_output=True, text=True, encoding="utf-8", errors="replace"
            )
        except OSError as error:
            _post(q, "auth_finished", ok=False, message=str(error))
            return
        text = (out.stdout if out.returncode == 0 else out.stderr).strip().splitlines()
        message = text[-1] if text else "ChatGPT authentication finished."
        _post(q, "auth_finished", ok=out.returncode == 0, message=message)

    threading.Thread(target=work, daemon=True).start()


def start_test_connection(genesect_root: Path | str, payload: dict, q, ida_path: str = "") -> None:
    def work() -> None:
        target = payload.get("target", "main")
        # 1. Prefer in-process execution (avoids re-invoking frozen executable)
        try:
            mod = _load_auth_cli_module(genesect_root, ida_path)
            if mod and hasattr(mod, "test_connection"):
                res = mod.test_connection(payload)
                if isinstance(res, dict):
                    _post(
                        q,
                        "test_connection_result",
                        ok=bool(res.get("ok", False)),
                        message=str(res.get("message", "Unknown result")),
                        resolved_model=res.get("model") if isinstance(res.get("model"), str) else None,
                        available_models=res.get("available_models") if isinstance(res.get("available_models"), list) else [],
                        target=target,
                    )
                    return
        except Exception:
            pass

        # 2. Subprocess fallback
        script = auth_script(genesect_root)
        try:
            out = subprocess.run(
                [*_python_cmd(), str(script), "test-connection", "-"],
                input=json.dumps(payload),
                env=_script_env(genesect_root, ida_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as error:
            _post(q, "test_connection_result", ok=False, message=f"Could not probe connection: {error}", resolved_model=None, target=target)
            return
        parsed = None
        for line in out.stdout.splitlines():
            try:
                candidate = json.loads(line.strip())
            except ValueError:
                continue
            if isinstance(candidate, dict):
                parsed = candidate
                break
        if parsed is not None:
            _post(
                q,
                "test_connection_result",
                ok=bool(parsed.get("ok", False)),
                message=str(parsed.get("message", "Unknown result")),
                resolved_model=parsed.get("model") if isinstance(parsed.get("model"), str) else None,
                available_models=parsed.get("available_models") if isinstance(parsed.get("available_models"), list) else [],
                target=target,
            )
        else:
            err = out.stderr.strip() or out.stdout.strip() or "No response received from test probe."
            _post(q, "test_connection_result", ok=False, message=err, resolved_model=None, target=target)

    threading.Thread(target=work, daemon=True).start()


def open_cli_sign_in(executable: str, extra_args: tuple[str, ...] = ()) -> None:
    exe = executable.strip() or "opencode"
    if sys.platform == "win32":
        subprocess.Popen(["cmd.exe", "/K", exe, *extra_args], creationflags=subprocess.CREATE_NEW_CONSOLE)
        return
    cmd = " ".join([exe, *extra_args])
    for terminal in (["x-terminal-emulator", "-e"], ["gnome-terminal", "--"], ["xterm", "-e"]):
        try:
            subprocess.Popen([*terminal, "bash", "-lc", f"{cmd}; exec bash"])
            return
        except OSError:
            continue
    raise OSError(f"Could not open a terminal for {exe}")


def get_opencode_auth_status() -> Optional[list[str]]:
    candidates: list[Path] = []
    home = os.environ.get("USERPROFILE") or os.environ.get("HOME")
    if home:
        candidates.append(Path(home) / ".local" / "share" / "opencode" / "auth.json")
        candidates.append(Path(home) / ".config" / "opencode" / "auth.json")
    for var in ("LOCALAPPDATA", "APPDATA"):
        if os.environ.get(var):
            candidates.append(Path(os.environ[var]) / "opencode" / "auth.json")
    for path in candidates:
        if path.is_file():
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(parsed, dict):
                return list(parsed.keys())
    return None
