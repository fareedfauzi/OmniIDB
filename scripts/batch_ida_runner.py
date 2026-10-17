# -*- coding: utf-8 -*-
"""Unattended IDAPython entry point used by OmniIDB (``python -m omni_idb``).

The Python application owns discovery, queuing, configuration, and process
lifecycle.  This module runs inside IDA, where the existing Genesect analysis
code and IDA APIs are available.  It deliberately reuses the same workers,
prompts, parsers, validation, IDB markers, and workspace exporter as the
interactive plugin.
"""

from __future__ import annotations

import json
import importlib
import importlib.util
import inspect
import os
import sys
import time
import traceback
from pathlib import Path


EVENT_PREFIX = "GENESECT_EVENT "


def emit(kind, message, **fields):
    payload = {"kind": str(kind), "message": str(message)}
    payload.update(fields)
    line = EVENT_PREFIX + json.dumps(payload, ensure_ascii=False, sort_keys=True)
    print(line, flush=True)


def load_args():
    env_job = os.environ.get("OMNI_IDB_JOB_FILE")
    if env_job and Path(env_job).is_file():
        return json.loads(Path(env_job).read_text(encoding="utf-8"))

    try:
        import idc
        if hasattr(idc, "ARGV") and len(idc.ARGV) > 1:
            for candidate in idc.ARGV[1:]:
                p = Path(candidate)
                if p.is_file() and p.suffix.lower() == ".json":
                    return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass

    for candidate in reversed(sys.argv[1:]):
        p = Path(candidate)
        if p.is_file() and p.suffix.lower() == ".json":
            return json.loads(p.read_text(encoding="utf-8"))

    if len(sys.argv) >= 2:
        args_path = Path(sys.argv[-1])
        if args_path.is_file():
            return json.loads(args_path.read_text(encoding="utf-8"))

    raise RuntimeError("Genesect batch runner did not receive a job JSON path.")


def load_repository_module(repo_root, module_name):
    """Load module from repo_root if present, otherwise import from installed genesect."""
    if repo_root:
        source_path = Path(repo_root).resolve() / "genesect" / (module_name + ".py")
        if source_path.is_file():
            unique_name = "_genesect_batch_%s" % module_name
            spec = importlib.util.spec_from_file_location(unique_name, str(source_path))
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[unique_name] = module
                spec.loader.exec_module(module)
                return module
    # Fallback to standard Python import from IDA's installed genesect plugin
    return importlib.import_module("genesect.%s" % module_name)


PROVIDER_MAPPING = {
    "OpenAI": ("openai_key", "openai_url", "openai_model"),
    "Anthropic": ("anthropic_key", "anthropic_url", "anthropic_model"),
    "DeepSeek": ("deepseek_key", "deepseek_url", "deepseek_model"),
    "GoogleGemini": ("custom_key", "custom_url", "custom_model"),
    "OpenRouter": ("custom_key", "custom_url", "custom_model"),
    "Groq": ("custom_key", "custom_url", "custom_model"),
    "Mistral": ("custom_key", "custom_url", "custom_model"),
    "Ollama": (None, "ollama_host", "ollama_model"),
    "LMStudio": ("lmstudio_key", "lmstudio_url", "lmstudio_model"),
    "OpenAICompatible": ("custom_key", "custom_url", "custom_model"),
    "ChatGPTAccount": (None, None, "chatgpt_account_model"),
    "ClaudeCode": ("claude_code_path", None, "claude_code_model"),
    "AntigravityCLI": ("antigravity_cli_path", None, "antigravity_cli_model"),
    "OpenCode": ("opencode_path", None, "opencode_model"),
    "CopilotCLI": ("copilot_cli_path", None, "copilot_cli_model"),
}
CLI_PROVIDERS = ("ClaudeCode", "AntigravityCLI", "OpenCode", "CopilotCLI")
WORKER_PROVIDER = {
    "OpenAI": "openai",
    "Anthropic": "anthropic",
    "DeepSeek": "deepseek",
    "GoogleGemini": "custom",
    "OpenRouter": "custom",
    "Groq": "custom",
    "Mistral": "custom",
    "Ollama": "ollama",
    "LMStudio": "lmstudio",
}

# Filled while the job runs; written to result.json and the report appendix.
PROVIDER_INFO = {"primary": "", "used": [], "fallback_events": [], "active": ""}
RENAMED = []
INVESTIGATION = {}


def apply_profile(profile, config):
    """Point the Genesect CONFIG at ``profile`` and return the worker-config fields."""
    provider = str(profile.get("provider") or "OpenAI")
    model = str(profile.get("model") or "").strip()
    api_key = str(profile.get("api_key") or "")
    api_url = str(profile.get("api_url") or "").strip()
    executable = str(profile.get("executable") or "").strip()
    config.active_provider = provider

    key_attr, url_attr, model_attr = PROVIDER_MAPPING.get(provider, PROVIDER_MAPPING["OpenAICompatible"])
    if key_attr:
        setattr(config, key_attr, executable if provider in CLI_PROVIDERS else api_key)
    if url_attr and api_url:
        setattr(config, url_attr, api_url)
    if model:
        setattr(config, model_attr, model)

    if provider in ("GoogleGemini", "OpenRouter", "Groq", "Mistral"):
        setattr(config, "custom_key", api_key)
        setattr(config, "custom_url", api_url)
        setattr(config, "custom_model", model)

    # The existing bulk workers consume this compact legacy mapping.  A
    # provider-aware adapter below handles account/CLI providers.
    return {
        "provider": WORKER_PROVIDER.get(provider, "custom"),
        "profile_name": provider,
        "api_url": api_url,
        "api_key": api_key,
        "model": model,
    }


def provider_chain(job):
    """Ordered provider profiles: the active one first, then the optional fallback."""
    primary = dict(job.get("profile") or {})
    fallback = dict(job.get("fallback_profile") or {})
    if job.get("fallback_enabled") and fallback.get("provider") and fallback.get("provider") != primary.get("provider"):
        if job.get("use_fallback_first"):
            return [fallback, primary]
        return [primary, fallback]
    return [primary]


def configure_provider(job, config):
    chain = provider_chain(job)
    worker = apply_profile(chain[0], config)
    PROVIDER_INFO["primary"] = str((job.get("profile") or {}).get("provider") or "OpenAI")
    PROVIDER_INFO["active"] = worker["profile_name"]
    PROVIDER_INFO["used"] = [worker["profile_name"]]
    worker.update({
        "batch_size": max(1, int(job.get("batch_size", 5))),
        "parallel_workers": 1,
        "cooldown_seconds": max(0, int(job.get("cooldown_seconds", 0))),
        "asm_max_lines": max(1, int(job.get("asm_max_lines", 25))),
        "force_bulk_rename": True,
        "var_force_rename": True,
        "use_custom_prompt": False,
        "custom_prompt": "",
    })
    return worker


def query_copilot_cli(executable, model, prompt, sys_prompt, timeout=120):
    import shutil
    import subprocess
    cmd = executable or shutil.which("copilot") or shutil.which("gh") or "copilot"
    full_prompt = ("%s\n\n%s" % (sys_prompt, prompt)).strip()
    is_gh = Path(cmd).stem.lower() == "gh"
    if is_gh:
        args = [cmd, "copilot", "explain", full_prompt]
    else:
        args = [cmd, "-p", full_prompt, "-s"]
        if model and str(model).lower() != "default":
            args.extend(["--model", str(model)])
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError("Copilot CLI exited with code %s: %s" % (proc.returncode, proc.stderr.strip() or proc.stdout.strip()))
    return proc.stdout.strip() or proc.stderr.strip()


def install_provider_adapter(config, worker_cfg, renamer, var_renamer, repo_root, job=None):
    original_request = renamer.ai_request
    chain = provider_chain(job or {})
    state = {"index": 0, "empty": 0}
    resolved_account_model = [None]
    account_oauth_module = [None]

    if len(chain) > 1:
        # genesect retries every failed request 5x with multi-minute cooldowns; with a fallback
        # available fail fast instead so the switch happens within seconds.
        for name, value in (("MAX_API_RETRIES", 2), ("INITIAL_COOLDOWN_SECONDS", 8)):
            if hasattr(renamer, name):
                setattr(renamer, name, value)
        emit("log", "Provider fallback armed: %s -> %s" % (
            chain[0].get("provider"), " -> ".join(str(c.get("provider")) for c in chain[1:])))

    def switch_provider(reason):
        if state["index"] + 1 >= len(chain):
            return False
        old = worker_cfg.get("profile_name")
        state["index"] += 1
        worker_cfg.update(apply_profile(chain[state["index"]], config))
        resolved_account_model[0] = None
        state["empty"] = 0
        new = worker_cfg.get("profile_name")
        PROVIDER_INFO["active"] = new
        if new not in PROVIDER_INFO["used"]:
            PROVIDER_INFO["used"].append(new)
        PROVIDER_INFO["fallback_events"].append({"from": old, "to": new, "reason": str(reason)[:300]})
        emit(
            "provider_switch",
            "Provider %s failed (%s); falling back to %s / %s" % (
                old, str(reason)[:160], new, worker_cfg.get("model") or "default"),
            level="warning", stage="provider", provider_from=old, provider_to=new,
        )
        return True

    def dispatch(cfg, prompt, sys_prompt, logger, on_chunk, max_tokens, cancel_checker):
        profile_name = worker_cfg.get("profile_name", "OpenAI")
        if logger:
            logger("Provider request: %s / %s" % (profile_name, worker_cfg.get("model") or "default"))

        if profile_name == "ChatGPTAccount":
            if account_oauth_module[0] is None:
                account_oauth_module[0] = load_repository_module(repo_root, "chatgpt_oauth")
            chatgpt_oauth = account_oauth_module[0]
            if not resolved_account_model[0]:
                requested = str(worker_cfg.get("model") or "")
                if hasattr(chatgpt_oauth, "resolve_model"):
                    selected, _available = chatgpt_oauth.resolve_model(requested)
                elif hasattr(chatgpt_oauth, "list_models"):
                    try:
                        slugs = [m.get("slug") for m in chatgpt_oauth.list_models() if isinstance(m, dict) and m.get("slug")]
                        selected = requested if requested in slugs else (slugs[0] if slugs else requested or "auto")
                    except Exception:
                        selected = requested or "auto"
                else:
                    selected = requested or "auto"
                resolved_account_model[0] = selected
                worker_cfg["model"] = selected
                if selected != requested and requested and requested != "auto":
                    emit(
                        "log",
                        "ChatGPT account model '%s' is unavailable; using '%s'."
                        % (requested or "auto", selected),
                        level="warning",
                    )
            if hasattr(chatgpt_oauth, "create_response"):
                result = chatgpt_oauth.create_response(
                    resolved_account_model[0],
                    [{"role": "user", "content": prompt}],
                    instructions=sys_prompt,
                    max_output_tokens=int(max_tokens or 1024),
                    timeout=180,
                    on_chunk=on_chunk,
                )
            else:
                import openai
                token = chatgpt_oauth.get_access_token()
                client = openai.OpenAI(api_key=token, base_url="https://api.openai.com/v1")
                resp = client.chat.completions.create(
                    model=resolved_account_model[0] if resolved_account_model[0] != "auto" else "gpt-4o",
                    messages=[{"role": "system", "content": sys_prompt}, {"role": "user", "content": prompt}],
                    max_tokens=int(max_tokens or 1024),
                )
                result = resp.choices[0].message.content or ""
        elif profile_name in CLI_PROVIDERS:
            if profile_name == "CopilotCLI":
                exe = str(getattr(config, "copilot_cli_path", "") or worker_cfg.get("executable") or "")
                mdl = str(getattr(config, "copilot_cli_model", "") or worker_cfg.get("model") or "")
                result = query_copilot_cli(exe, mdl, prompt, sys_prompt)
            else:
                from genesect.ai_client import SimpleAI
                client = SimpleAI(config)
                result = client._query_signed_in_cli([
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": prompt},
                ])
        else:
            result = original_request(
                cfg, prompt, sys_prompt, logger=logger, on_chunk=None,
                max_tokens=max_tokens, cancel_checker=cancel_checker,
            )
        return str(result or "").strip(), profile_name

    def request(cfg, prompt, sys_prompt, logger=None, on_chunk=None,
                on_cooldown=None, max_tokens=None, cancel_checker=None, **kwargs):
        del on_cooldown, kwargs
        while True:
            if cancel_checker and cancel_checker():
                return ""
            try:
                result, profile_name = dispatch(cfg, prompt, sys_prompt, logger, on_chunk, max_tokens, cancel_checker)
            except Exception as exc:  # noqa: BLE001 - any provider failure may trigger the fallback
                lowered = str(exc).lower()
                permanent = any(t in lowered for t in ("context length", "context window", "maximum context", "prompt is too long", "too many tokens"))
                if not permanent and switch_provider("%s: %s" % (type(exc).__name__, exc)):
                    continue
                raise
            if not result and not (cancel_checker and cancel_checker()):
                state["empty"] += 1
                # Quota/auth failures often surface as empty replies on CLI providers.
                if state["empty"] >= 3 and switch_provider("%d consecutive empty replies" % state["empty"]):
                    continue
            else:
                state["empty"] = 0
            if on_chunk and result and profile_name != "ChatGPTAccount":
                on_chunk(result)
            return result

    renamer.ai_request = request
    var_renamer.ai_request = request


def run_workspace_export(exporter, workspace_path):
    """Run either the current headless exporter API or a legacy exporter."""
    parameters = inspect.signature(exporter).parameters
    if "show_progress" in parameters:
        return exporter(
            workspace_path,
            show_progress=False,
            progress_callback=lambda label, current, total: emit(
                "progress", label, stage="workspace", current=current, total=total
            ),
        )
    emit(
        "log",
        "Repository exporter uses the legacy progress API; continuing in compatibility mode.",
        level="warning",
    )
    return exporter(workspace_path, None)


def collect_sub_functions(renamer):
    import idautils
    import idc

    result = []
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) or ""
        if name.startswith("sub_") and renamer.is_valid_seg(ea):
            result.append((int(ea), name))
    return result


def configure_raw_shellcode(job):
    """Apply the architecture metadata missing from a raw byte stream."""
    if job.get("sample_kind") != "shellcode":
        return

    import ida_auto
    import ida_funcs
    import ida_ida
    import ida_idaapi
    import ida_segment
    import idaapi

    arch = str(job.get("shellcode_arch") or "x64").lower()
    if arch not in ("x86", "x64"):
        raise RuntimeError("Unsupported raw shellcode architecture: %s" % arch)
    bits = 64 if arch == "x64" else 32
    segment_bitness = 2 if bits == 64 else 1

    try:
        ida_ida.inf_set_app_bitness(bits)
    except (AttributeError, TypeError):
        # Compatibility with IDA releases exposing the information structure.
        idaapi.get_inf_structure().set_app_bitness(bits)

    segment = ida_segment.get_first_seg()
    first_ea = ida_idaapi.BADADDR
    last_ea = ida_idaapi.BADADDR
    while segment:
        ida_segment.set_segm_addressing(segment, segment_bitness)
        if first_ea == ida_idaapi.BADADDR:
            first_ea = int(segment.start_ea)
        last_ea = int(segment.end_ea)
        segment = ida_segment.get_next_seg(segment.start_ea)

    if first_ea == ida_idaapi.BADADDR:
        raise RuntimeError("IDA's binary loader did not create a segment for the shellcode")

    # Raw blobs have no entry-point table. Seed a function at the first byte so
    # Genesect has a sub_* root to analyze and IDA can follow reachable code.
    ida_funcs.add_func(first_ea, ida_idaapi.BADADDR)
    if last_ea != ida_idaapi.BADADDR:
        ida_auto.plan_range(first_ea, last_ea)
    emit(
        "stage",
        "Configured raw %s shellcode at 0x%X" % (arch, first_ea),
        stage="shellcode",
    )


def all_existing_names():
    import idautils
    import idc

    return {
        name for name in (idc.get_func_name(ea) for ea in idautils.Functions())
        if name and not name.startswith("sub_")
    }


def apply_function_name(ea, name):
    import idaapi
    import ida_hexrays
    import ida_name
    import idc
    from genesect.idb_storage import load_from_idb, save_to_idb

    original = load_from_idb(ea, tag=82)
    if not original:
        current = idc.get_func_name(ea)
        if current and not current.startswith("sub_"):
            save_to_idb(ea, current, tag=82)
    candidate = str(name)
    owner = idc.get_name_ea_simple(candidate)
    suffix = 1
    while owner != idaapi.BADADDR and owner != ea:
        candidate = "%s_%d" % (name, suffix)
        suffix += 1
        owner = idc.get_name_ea_simple(candidate)
    ok = ida_name.set_name(ea, candidate, ida_name.SN_NOWARN | ida_name.SN_FORCE)
    if ok:
        save_to_idb(ea, "renamed_by_genesect", tag=83)
        try:
            ida_hexrays.clear_cached_cfuncs()
        except Exception:
            pass
    return bool(ok), candidate


def run_function_rename(sub_functions, cfg, renamer):
    pending = {}
    for ea, name in sub_functions:
        pending[ea] = renamer.FuncData(ea, name)
    existing = all_existing_names()
    renamed = 0
    failed = 0
    round_index = 0

    while pending:
        round_index += 1
        ready = []
        for index, func in enumerate(list(pending.values())):
            func.name = __import__("idc").get_func_name(func.ea) or func.name
            func.code = renamer.get_code_fast(func.ea, 50000, asm_max=1000)
            func.strings = renamer.get_strings_fast(func.ea)
            func.calls = renamer.get_calls_fast(func.ea)
            func.sub_count = renamer.count_sub_calls(func.code, own_name=func.name)
            func.queue = "clear" if func.sub_count == 0 else "blocked"
            if func.queue == "clear":
                ready.append((index, func))

        if not ready:
            minimum = min(func.sub_count for func in pending.values())
            candidates = [func for func in pending.values() if func.sub_count == minimum]
            candidates.sort(key=lambda f: (len(f.strings or []), len(f.calls or [])), reverse=True)
            for index, func in enumerate(candidates[:30]):
                func.status = "Pending (Cycle Breaker - %d sub_* remaining)" % func.sub_count
                ready.append((index, func))
            emit("log", "Dependency cycle detected; promoting %d cycle breaker(s)." % len(ready))

        emit(
            "progress",
            "Function rename round %d: %d ready, %d remaining" % (round_index, len(ready), len(pending)),
            stage="functions",
            current=len(sub_functions) - len(pending),
            total=len(sub_functions),
        )
        results = []
        worker = renamer.AnalyzeWorker(
            cfg, ready, existing,
            renamer.DEFAULT_BATCH_PROMPT if cfg["batch_size"] > 1 else renamer.DEFAULT_PROMPT,
            cfg["batch_size"], is_retry=True,
        )
        worker.batch_done.connect(lambda batch: results.extend(batch))
        worker.log.connect(lambda message, level: emit("log", message, level=level))
        worker.update_status.connect(lambda message: emit("log", message) if message else None)
        worker.run()

        processed = set()
        for _index, func, suggestion, score in results:
            processed.add(func.ea)
            if suggestion and suggestion not in ("DEFERRED", "DEFERRED_LOW_SCORE"):
                ok, final_name = apply_function_name(func.ea, suggestion)
                if ok:
                    renamed += 1
                    existing.add(final_name)
                    RENAMED.append({"address": "0x%X" % func.ea, "old": func.name, "new": final_name})
                    emit("log", "%s -> %s (%s)" % (func.name, final_name, score or "unscored"), level="ok")
                else:
                    failed += 1
                    emit("log", "IDA rejected function name %s at 0x%X" % (suggestion, func.ea), level="error")
            else:
                failed += 1
                emit("log", "No function rename produced for 0x%X" % func.ea, level="warning")

        # A worker emits one terminal result per item.  Guard against provider
        # or Qt failures so an unattended job cannot loop forever.
        for _index, func in ready:
            if func.ea not in processed:
                failed += 1
                emit("log", "Function worker produced no result for 0x%X" % func.ea, level="error")
            pending.pop(func.ea, None)

    return {"candidates": len(sub_functions), "renamed": renamed, "failed": failed}


def run_variable_rename(sub_functions, cfg, var_renamer):
    import idc

    items = []
    for index, (ea, original_name) in enumerate(sub_functions):
        items.append((index, var_renamer.FuncData(ea, idc.get_func_name(ea) or original_name)))
    results = []
    emit("progress", "Renaming variables in %d original sub_* function(s)" % len(items), stage="variables", current=0, total=len(items))
    worker = var_renamer.VarRenameWorker(cfg, items, is_retry=True)
    worker.batch_done.connect(lambda batch: results.extend(batch))
    worker.log.connect(lambda message, level: emit("log", message, level=level))
    worker.update_status.connect(lambda message: emit("log", message) if message else None)
    worker.run()

    functions_changed = 0
    variables_renamed = 0
    failed = 0
    for _index, func, suggestions in results:
        if not suggestions:
            continue
        applied, rejected, details = var_renamer.apply_var_renames(
            func.ea,
            suggestions,
            log_fn=lambda message, level="info": emit("log", message, level=level),
        )
        if applied:
            functions_changed += 1
        variables_renamed += applied
        failed += rejected
        emit(
            "log",
            "0x%X: %d variable(s) renamed, %d rejected" % (func.ea, applied, rejected),
            level="ok" if applied else "warning",
            details=details,
        )
    return {
        "candidates": len(items),
        "functions_changed": functions_changed,
        "variables_renamed": variables_renamed,
        "failed": failed,
    }


def run_autonomous_investigation(job, cfg, renamer):
    import idaapi
    import idc
    import idautils
    from genesect.agent_policy import AgentPolicy
    from genesect.agent_runtime import (
        AgentSession,
        build_system_prompt,
        normalize_tool_call,
        parse_agent_response,
    )
    from genesect.bridge_tools import AGENT_TOOL_CATALOG, execute_bridge_tool

    # 1. Determine entry point or primary target
    entry_ea = idaapi.get_entry(idaapi.get_entry_ordinal(0))
    if entry_ea != idaapi.BADADDR:
        func = idaapi.get_func(entry_ea)
        if func:
            entry_ea = int(func.start_ea)
    if entry_ea == idaapi.BADADDR:
        main_ea = idc.get_name_ea_simple("main")
        if main_ea != idaapi.BADADDR:
            entry_ea = int(main_ea)
    if entry_ea == idaapi.BADADDR:
        funcs = list(idautils.Functions())
        entry_ea = int(funcs[0]) if funcs else 0

    root_name = idc.get_func_name(entry_ea) or ("0x%X" % entry_ea if entry_ea else "unknown")
    max_turns = max(3, min(30, int(job.get("investigation_turns") or 10)))

    emit(
        "stage",
        "Autonomous Agentic Investigation (%d turns) on %s (0x%X)" % (max_turns, root_name, entry_ea),
        stage="investigation",
        total=max_turns,
    )
    emit(
        "log",
        "[Agent] Initializing autonomous investigation on %s at 0x%X (budget: %d turns)"
        % (root_name, entry_ea, max_turns),
    )

    policy = AgentPolicy(allow_mutations=False, max_steps=max_turns * 4, max_seconds=900)
    session = AgentSession(
        root_ea=entry_ea,
        function_name=root_name,
        mission="Perform evidence-driven autonomous malware reverse engineering and capability triage.",
    )
    sys_prompt = build_system_prompt(entry_ea, root_name, AGENT_TOOL_CATALOG)

    history = []
    initial_user_prompt = (
        "Begin autonomous reverse-engineering investigation. "
        "Root target function is %s at 0x%X. "
        "Investigate binary capabilities, key imports/strings, behavior, and record findings."
    ) % (root_name, entry_ea)
    history.append({"role": "user", "content": initial_user_prompt})

    final_report = ""
    turn_executed = 0

    for turn in range(1, max_turns + 1):
        turn_executed = turn
        emit(
            "progress",
            "Agent Turn %d/%d: Reasoning and tool planning" % (turn, max_turns),
            stage="investigation",
            current=turn,
            total=max_turns,
        )

        prompt_blocks = [
            "## Target Information",
            "Function: %s at 0x%X" % (root_name, entry_ea),
            "Current Turn: %d of %d\n" % (turn, max_turns),
            "## Session State Snapshot",
            session.snapshot(max_chars=12000),
            "\n## Recent Context",
        ]
        for item in history[-4:]:
            prompt_blocks.append("[%s]:\n%s" % (item["role"].upper(), item["content"]))

        if turn == max_turns:
            prompt_blocks.append(
                "\nCRITICAL: Maximum investigation turns reached (Turn %d/%d). "
                "Do not request more tools. Return action=final with a comprehensive executive dossier report in Markdown."
                % (turn, max_turns)
            )
        else:
            prompt_blocks.append(
                "\nDecide whether to query additional tools or finalize. "
                "Return exactly one JSON envelope with action='tools' or action='final'."
            )

        full_prompt = "\n".join(prompt_blocks)

        try:
            raw_response = renamer.ai_request(cfg, full_prompt, sys_prompt, max_tokens=4096)
        except Exception as exc:
            emit("log", "[Agent] Turn %d: Provider request failed: %s" % (turn, exc), level="error")
            break

        envelope, parse_err = parse_agent_response(raw_response)
        if parse_err or not envelope:
            emit("log", "[Agent] Turn %d: Parse warning: %s" % (turn, parse_err or "Invalid envelope"), level="warning")
            history.append({"role": "assistant", "content": raw_response})
            history.append({
                "role": "user",
                "content": "Protocol error: %s. Return a valid JSON envelope with action='tools' or action='final'." % parse_err,
            })
            continue

        if envelope["action"] == "final":
            final_report = envelope.get("report", "").strip()
            session.final_report = final_report
            emit("log", "[Agent] Turn %d: Completed with final report (%d chars)." % (turn, len(final_report)), level="ok")
            break

        calls = envelope.get("calls", [])
        emit("log", "[Agent] Turn %d: Requested %d tool call(s)" % (turn, len(calls)))
        session.begin_round()
        observations = []

        for call in calls:
            tool_name = str(call.get("tool") or "").strip()
            args = call.get("args") or {}
            normalized, val_err = normalize_tool_call(tool_name, args, entry_ea, AGENT_TOOL_CATALOG)
            if val_err:
                err_msg = "Error: " + val_err
                emit("log", "[Agent] Tool %s rejected: %s" % (tool_name, val_err), level="warning")
                session.record_result(tool_name, args, err_msg)
                session.record_observation(tool_name, args, err_msg)
                observations.append("[%s rejected: %s]" % (tool_name, val_err))
                continue

            t_name = normalized["tool"]
            t_args = normalized["args"]
            session.record_call(t_name, t_args)
            emit("log", "[Agent] Executing: %s(%s)" % (t_name, json.dumps(t_args, ensure_ascii=False)))

            if t_name == "record_finding":
                finding = session.add_finding(
                    t_args.get("claim", ""),
                    t_args.get("confidence", "low"),
                    t_args.get("evidence", []),
                    t_args.get("tags", []),
                )
                tool_res = "Recorded verified finding %s." % finding.finding_id
                session.record_result(t_name, t_args, tool_res)
                session.record_observation(t_name, t_args, tool_res)
                emit("log", "[Agent] Finding: %s [%s]" % (finding.claim[:100], finding.confidence), level="ok")
            elif t_name == "mark_examined":
                session.mark_examined(
                    t_args.get("ea", entry_ea),
                    t_args.get("disposition", "examined"),
                    t_args.get("summary", ""),
                )
                tool_res = "Marked address."
                session.record_result(t_name, t_args, tool_res)
                session.record_observation(t_name, t_args, tool_res)
            elif t_name == "record_function_analysis":
                session.remember_function(t_args.get("ea", entry_ea), t_args)
                tool_res = "Recorded function analysis."
                session.record_result(t_name, t_args, tool_res)
                session.record_observation(t_name, t_args, tool_res)
            else:
                tool_res = execute_bridge_tool(policy, t_name, t_args, address=entry_ea)
                session.record_result(t_name, t_args, tool_res)
                session.record_observation(t_name, t_args, tool_res)

            status_summary = tool_res[:160].replace("\n", " ").strip() if tool_res else "ok"
            emit("log", "[Agent] -> %s: %s" % (t_name, status_summary))
            observations.append(policy.untrusted_result(t_name, tool_res))

        history.append({"role": "assistant", "content": raw_response})
        history.append({
            "role": "user",
            "content": "Tool observation results:\n\n" + "\n\n".join(observations),
        })

    # If completed without final report, prompt for final synthesis
    if not final_report:
        emit("progress", "Synthesizing executive investigation dossier...", stage="investigation", current=max_turns, total=max_turns)
        synthesis_prompt = (
            "All investigation turns are complete. Based on all collected findings, observations, and evidence, "
            "produce a detailed Markdown Executive Investigation Dossier. "
            "Include:\n"
            "1. Executive Summary & Malware Triage\n"
            "2. Identified Capabilities & Behaviors\n"
            "3. Key Functions & Addresses Analyzed\n"
            "4. Concrete Indicators of Compromise (IOCs) / Strings\n"
            "5. Strategic Next Steps for Reverse Engineers.\n\n"
            "Return action=final."
        )
        try:
            synth_resp = renamer.ai_request(cfg, synthesis_prompt, sys_prompt, max_tokens=4096)
            env, _ = parse_agent_response(synth_resp)
            if env and env.get("action") == "final":
                final_report = env.get("report", "").strip()
            else:
                final_report = synth_resp.strip()
        except Exception as exc:
            final_report = "Autonomous investigation completed. (Error generating final summary: %s)" % exc

    session.final_report = final_report

    output_root = Path(job["result_path"]).resolve().parent
    output_root.mkdir(parents=True, exist_ok=True)
    dossier_path = output_root / "investigation_dossier.md"
    findings_path = output_root / "investigation_findings.json"

    dossier_lines = [
        "# Autonomous Agentic Investigation Dossier",
        "",
        "| Field | Value |",
        "|---|---|",
        "| **Sample** | `%s` |" % job.get("sample_path", ""),
        "| **Root Target** | `%s` (0x%X) |" % (root_name, entry_ea),
        "| **Turns Executed** | %d / %d |" % (turn_executed, max_turns),
        "| **Verified Findings** | %d |" % len(session.findings),
        "| **Timestamp** | %s |" % time.strftime("%Y-%m-%d %H:%M:%S"),
        "",
        "## Executive Summary & Analysis",
        "",
        final_report,
        "",
        "## Verified Findings",
        "",
    ]
    if session.findings:
        for idx, f in enumerate(session.findings, 1):
            dossier_lines.append(f"### {idx}. {f.claim}")
            dossier_lines.append(f"- **Confidence**: `{f.confidence.upper()}`")
            if f.tags:
                dossier_lines.append(f"- **Tags**: {', '.join(f.tags)}")
            if f.evidence:
                dossier_lines.append("- **Evidence / Citations**:")
                for ev in f.evidence:
                    dossier_lines.append(f"  - `{ev}`")
            dossier_lines.append("")
    else:
        dossier_lines.append("_No discrete findings were explicitly tagged during the investigation._\n")

    dossier_lines.extend([
        "## Agent Execution Audit",
        "",
        "| Step | Tool | Category | Status |",
        "|---|---|---|---|",
    ])
    for idx, event in enumerate(policy.timeline, 1):
        status_badge = "Allowed" if event.allowed else "Blocked"
        dossier_lines.append(f"| {idx} | `{event.tool}` | {event.category} | {status_badge} |")
    dossier_lines.append("")

    dossier_text = "\n".join(dossier_lines)
    dossier_path.write_text(dossier_text, encoding="utf-8")
    findings_path.write_text(session.to_json(), encoding="utf-8")

    emit("log", "Investigation dossier saved to: %s" % dossier_path, level="ok")
    emit("log", "Structured findings saved to: %s" % findings_path, level="ok")

    INVESTIGATION.update({
        "final_report": final_report,
        "turns_executed": turn_executed,
        "findings": [
            {"claim": f.claim, "confidence": str(f.confidence), "tags": list(f.tags or []), "evidence": [str(e) for e in (f.evidence or [])]}
            for f in session.findings
        ],
    })
    return {
        "dossier_path": str(dossier_path),
        "findings_path": str(findings_path),
        "turns_executed": turn_executed,
        "max_turns": max_turns,
        "findings_count": len(session.findings),
        "root_ea": "0x%X" % entry_ea,
        "root_name": root_name,
    }


def save_original_idb(job):
    """Persist the pristine database (right after auto-analysis, before any AI change)."""
    path = str(job.get("original_idb_path") or "")
    if not path:
        return ""
    import ida_loader

    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    emit("stage", "Saving original IDB before AI changes", stage="save")
    if not ida_loader.save_database(str(target), ida_loader.DBFL_COMP):
        raise RuntimeError("IDA could not save the original database to %s" % target)
    emit("log", "Original IDB saved: %s" % target, level="ok")
    return str(target)


def find_entry_ea():
    import idaapi
    import idc
    import idautils

    entry_ea = idaapi.get_entry(idaapi.get_entry_ordinal(0))
    if entry_ea != idaapi.BADADDR:
        func = idaapi.get_func(entry_ea)
        if func:
            entry_ea = func.start_ea
    if entry_ea == idaapi.BADADDR:
        main_ea = idc.get_name_ea_simple("main")
        if main_ea != idaapi.BADADDR:
            entry_ea = main_ea
    if entry_ea == idaapi.BADADDR:
        funcs = list(idautils.Functions())
        entry_ea = funcs[0] if funcs else 0
    return int(entry_ea)


def _file_digest(sample_path, algo):
    import hashlib

    digest = hashlib.new(algo)
    with open(str(sample_path), "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_facts(job, renamer, stats):
    """Gather verified facts (profile, imports, strings, key functions) from the open IDB."""
    import ida_ida
    import ida_kernwin
    import ida_nalt
    import idaapi
    import idautils
    import idc
    from omni_idb import report_model as rm

    sample_path = Path(job.get("sample_path") or "")

    def digest(ida_name, algo):
        try:
            raw = getattr(ida_nalt, ida_name)()
            if raw:
                return raw.hex() if isinstance(raw, (bytes, bytearray)) else str(raw)
        except Exception:
            pass
        try:
            return _file_digest(sample_path, algo)
        except Exception:
            return ""

    def attr(fn, default=""):
        try:
            return fn()
        except Exception:
            return default

    bitness = attr(lambda: ida_ida.inf_get_app_bitness(), 0) or (64 if attr(lambda: ida_ida.inf_is_64bit(), False) else 32)
    entry_ea = find_entry_ea()
    try:
        size = sample_path.stat().st_size
    except OSError:
        size = 0
    sample = {
        "filename": sample_path.name or "sample",
        "size": size,
        "md5": digest("retrieve_input_file_md5", "md5"),
        "sha256": digest("retrieve_input_file_sha256", "sha256"),
        "file_type": attr(lambda: idaapi.get_file_type_name()),
        "architecture": attr(lambda: ida_ida.inf_get_procname()),
        "bitness": bitness,
        "image_base": "0x%X" % attr(lambda: ida_nalt.get_imagebase(), 0),
        "entry": "0x%X" % entry_ea if entry_ea else "",
        "ida_version": str(attr(lambda: ida_kernwin.get_kernel_version())),
        "original_idb": "IDB Files/" + Path(job["original_idb_path"]).name if job.get("original_idb_path") else "",
        "analyzed_idb": "IDB Files/" + Path(job["idb_path"]).name,
    }

    imports = []
    imp_by_ea = {}
    for index in range(ida_nalt.get_import_module_qty()):
        module = ida_nalt.get_import_module_name(index) or ""

        def callback(ea, name, ordinal, module=module):
            label = name or ("ord%d" % ordinal)
            imports.append({"module": module, "name": label, "address": "0x%X" % ea})
            imp_by_ea[int(ea)] = label
            return True

        ida_nalt.enum_import_names(index, callback)
    categorized = rm.categorize_imports(imports)

    strmap = {}
    for item in idautils.Strings():
        try:
            value = str(item)
        except Exception:
            continue
        if len(value) >= 4:
            strmap[int(item.ea)] = value
        if len(strmap) >= 30000:
            break
    scored = []
    for ea, value in strmap.items():
        bonus = 2.0 if rm.extract_iocs([{"value": value}]) else 0.0
        scored.append((bonus + min(len(value), 80) / 80.0, ea, value))
    scored.sort(key=lambda row: -row[0])
    strings = [{"address": "0x%X" % ea, "value": value[:300]} for _score, ea, value in scored[:500]]

    # Key functions: entry point + renamed functions, ranked by suspicious API usage.
    targets = {entry_ea} if entry_ea else set()
    for item in RENAMED[:400]:
        targets.add(int(item["address"], 16))
    candidates = []
    for ea in targets:
        func = idaapi.get_func(ea)
        if not func:
            continue
        calls, apis, fstrings = [], [], []
        for head in idautils.FuncItems(func.start_ea):
            for ref in idautils.DataRefsFrom(head):
                text = strmap.get(int(ref))
                if text and text[:200] not in fstrings and len(fstrings) < 30:
                    fstrings.append(text[:200])
                api = imp_by_ea.get(int(ref))
                if api and api not in apis:
                    apis.append(api)
            if idaapi.is_call_insn(head):
                for target in idautils.CodeRefsFrom(head, False):
                    name = idc.get_name(target) or ""
                    base = rm.normalize_api_name(name)
                    if name and name not in calls and len(calls) < 40:
                        calls.append(name)
                    if base and rm.categorize_api(name) and name not in apis:
                        apis.append(name)
        suspicious = [a for a in apis if rm.categorize_api(a)]
        ioc_strings = sum(1 for t in fstrings if rm.extract_iocs([{"value": t}]))
        score = 2.0 * len(suspicious) + ioc_strings + 0.05 * len(calls) + (5 if func.start_ea == entry_ea else 0)
        candidates.append((score, int(func.start_ea), calls, apis, fstrings))
    candidates.sort(key=lambda row: -row[0])
    key_functions = []
    for score, ea, calls, apis, fstrings in candidates[:12]:
        try:
            code = renamer.get_code_fast(ea, 2500, asm_max=40)
        except Exception:
            code = ""
        key_functions.append({
            "name": idc.get_func_name(ea) or "0x%X" % ea,
            "address": "0x%X" % ea,
            "score": round(score, 2),
            "calls": calls,
            "api_calls": apis,
            "strings": fstrings,
            "code": code or "",
        })

    stats = dict(stats)
    stats["functions_total"] = len(list(idautils.Functions()))
    stats["functions_renamed"] = len(RENAMED)
    stats["imports_total"] = len(imports)
    stats["strings_total"] = len(strmap)
    return {
        "sample": sample,
        "stats": stats,
        "imports_categorized": categorized,
        "strings": strings,
        "renamed_functions": RENAMED[:500],
        "key_functions": key_functions,
    }


def run_report_generation(job, cfg, renamer, stats):
    """AI synthesis of the evidence-gated report model (rendered to md/html/pdf by the host)."""
    from omni_idb import report_model as rm

    report_dir = Path(job["report_dir"]).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    emit("stage", "Collecting evidence for the analysis report", stage="report")
    facts = collect_facts(job, renamer, stats)
    investigation = dict(INVESTIGATION) if INVESTIGATION else None
    prompt = rm.build_synthesis_prompt(facts, investigation)

    emit("progress", "Synthesizing analysis report (AI)", stage="report")
    synthesis, status = None, "ok"
    for _attempt in range(2):
        try:
            raw = renamer.ai_request(cfg, prompt, rm.SYNTHESIS_SYSTEM, max_tokens=6000)
        except Exception as exc:
            status = "failed: %s" % exc
            emit("log", "Report synthesis failed: %s" % exc, level="error")
            break
        synthesis = rm.parse_model_json(raw)
        if synthesis:
            status = "ok"
            break
        status = "failed: model reply was not a valid JSON object"
        emit("log", "Report synthesis reply was not valid JSON; retrying once.", level="warning")
        prompt += "\n\nYour previous reply was not a single valid JSON object. Reply again with ONLY the JSON object."
    if not synthesis:
        emit("log", "Using deterministic report content (no AI synthesis).", level="warning")

    model = rm.assemble_model(facts, synthesis, investigation, dict(PROVIDER_INFO), status)
    model_path = report_dir / "report_model.json"
    model_path.write_text(json.dumps(model, indent=2, ensure_ascii=False), encoding="utf-8")
    emit("log", "Report model saved: %s" % model_path, level="ok")
    return {"model_path": str(model_path), "synthesis_status": status}


def run_workspace_analysis(job, cfg, renamer, workspace_path):
    """Analyze the exported AI workspace and write a technical malware analysis report using a CLI Agent."""
    provider = job.get("provider") or ""
    if provider not in CLI_PROVIDERS:
        emit(
            "log",
            "Workspace analysis skipped: only available for CLI Agent providers (Claude Code, Antigravity CLI, OpenCode, GitHub Copilot) "
            "to prevent excessive API token consumption.",
            level="warning",
        )
        return None

    emit("stage", "Analyzing exported AI workspace with %s" % provider, stage="workspace_analysis")
    emit("log", "Invoking %s on exported workspace: %s" % (provider, workspace_path))
    ws = Path(workspace_path)

    system_prompt = (
        "You are an experienced malware analyst and threat intelligence researcher "
        "writing a technical malware analysis report for a cybersecurity audience."
    )
    prompt = (
        "Analyze the exported IDA decompilation files in this workspace directory: %s\n\n"
        "Start by reading AGENTS.md to understand the file structure. Then inspect the decompiled C files, "
        "strings, and imports to proceed with the analysis.\n\n"
        "Writing Style\n\n"
        "- Write in a natural, professional, human-written tone, similar to malware research reports "
        "published by Kaspersky GReAT, ESET Research, or Google Threat Intelligence Group.\n"
        "- Use descriptive section headings followed by clear, connected paragraphs explaining the malware's behavior.\n"
        "- Focus on explaining what the malware does, how it works, and why the behavior matters.\n"
        "- Write for security researchers, threat intelligence analysts, incident responders, and technically knowledgeable readers.\n"
        "- Keep explanations technically accurate but easy to follow.\n"
        "- Prefer concise paragraphs over lengthy explanations.\n"
        "- Explain complex mechanisms in straightforward language without oversimplifying important technical details.\n"
        "- Maintain a neutral, factual, evidence-based tone.\n"
        "- Include relevant decompiled code snippets when they help explain interesting, unusual, or technically significant malware behavior.\n\n"
        "Write the structured technical malware analysis report now:"
    ) % str(ws.resolve())

    emit("progress", "Synthesizing malware analysis report via %s..." % provider, stage="workspace_analysis")
    try:
        report_text = renamer.ai_request(cfg, prompt, system_prompt, max_tokens=8000)
    except Exception as exc:
        emit("log", "CLI Agent workspace analysis failed: %s" % exc, level="error")
        return None

    if not report_text or not report_text.strip():
        emit("log", "CLI Agent returned empty analysis report.", level="warning")
        return None

    out_file = ws / "malware_analysis_report.md"
    out_file.write_text(report_text, encoding="utf-8")
    emit("log", "Malware analysis report saved to: %s" % out_file, level="ok")
    if job.get("report_dir"):
        r_dir = Path(job["report_dir"])
        r_dir.mkdir(parents=True, exist_ok=True)
        r_file = r_dir / "workspace_analysis.md"
        r_file.write_text(report_text, encoding="utf-8")
        emit("log", "Workspace analysis mirrored to: %s" % r_file, level="ok")
    return str(out_file)


def main():
    job = load_args()
    repo_root = str(Path(job.get("genesect_root", "")).resolve()) if job.get("genesect_root") else ""
    if repo_root and repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    omni_root = str(job.get("omni_root") or "")
    if omni_root and omni_root not in sys.path:
        sys.path.insert(0, omni_root)

    import ida_auto
    import ida_loader
    import ida_pro
    from genesect.config import CONFIG
    from genesect import renamer, var_renamer

    configure_raw_shellcode(job)
    emit("stage", "Waiting for IDA auto-analysis", stage="ida")
    ida_auto.auto_wait()
    original_idb = save_original_idb(job)
    cfg = configure_provider(job, CONFIG)
    install_provider_adapter(CONFIG, cfg, renamer, var_renamer, repo_root, job)

    sub_functions = collect_sub_functions(renamer)
    emit("stage", "Found %d sub_* function(s)" % len(sub_functions), stage="scan", total=len(sub_functions))
    result = {
        "sample": job.get("sample_path"),
        "idb_path": job.get("idb_path"),
        "original_idb_path": original_idb,
        "workspace_path": "",
        "function_rename": None,
        "variable_rename": None,
        "autonomous_investigation": None,
    }

    if job.get("rename_functions"):
        result["function_rename"] = run_function_rename(sub_functions, cfg, renamer)
    if job.get("rename_variables"):
        result["variable_rename"] = run_variable_rename(sub_functions, cfg, var_renamer)
    if job.get("autonomous_investigation"):
        result["autonomous_investigation"] = run_autonomous_investigation(job, cfg, renamer)
    if job.get("autonomous_investigation") and job.get("report_dir"):
        try:
            report_stats = {
                "variables_renamed": (result.get("variable_rename") or {}).get("variables_renamed", 0),
                "turns_executed": (result.get("autonomous_investigation") or {}).get("turns_executed", 0),
            }
            result["report"] = run_report_generation(job, cfg, renamer, report_stats)
        except Exception as exc:
            emit("log", "Report generation failed: %s" % exc, level="error", traceback=traceback.format_exc())
            result["report"] = {"error": str(exc)}

    if job.get("generate_workspace"):
        exporter_module = load_repository_module(repo_root, "ai_workspace_export")
        export_ai_workspace = exporter_module.export_ai_workspace
        workspace_path = str(Path(job["workspace_path"]).resolve())
        emit("stage", "Exporting AI workspace", stage="workspace")
        export_result = run_workspace_export(export_ai_workspace, workspace_path)
        result["workspace_path"] = export_result["path"]
        result["workspace_counts"] = export_result["counts"]
        if job.get("analyze_workspace"):
            report_path = run_workspace_analysis(job, cfg, renamer, workspace_path)
            if report_path:
                result["workspace_analysis_report"] = report_path

    idb_path = str(Path(job["idb_path"]).resolve())
    Path(idb_path).parent.mkdir(parents=True, exist_ok=True)
    emit("stage", "Saving analyzed IDB", stage="save")
    if not ida_loader.save_database(idb_path, ida_loader.DBFL_COMP):
        raise RuntimeError("IDA could not save database to %s" % idb_path)

    result_path = Path(job["result_path"])
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    result["provider"] = dict(PROVIDER_INFO)
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    emit("complete", "Sample completed", result=result)
    ida_pro.qexit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        details = traceback.format_exc()
        emit("error", str(exc), traceback=details)
        try:
            args = load_args()
            failure_path = Path(args.get("failure_path") or "")
            if str(failure_path):
                failure_path.parent.mkdir(parents=True, exist_ok=True)
                failure_path.write_text(details, encoding="utf-8")
        except Exception:
            pass
        try:
            import ida_pro
            ida_pro.qexit(1)
        except Exception:
            raise
