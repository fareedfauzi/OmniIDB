"""Provider-aware analysis for exported native and .NET workspaces."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from .config import CLI_PROVIDERS, find_genesect_package_root
from .usage import BudgetExceeded, UsageTracker


SYSTEM_PROMPT = (
    "You are a senior malware analyst. Produce an evidence-based technical report in Markdown. "
    "Distinguish observed behavior from hypotheses, preserve useful indicators, and avoid unsupported claims."
)


def _analysis_prompt(workspace: Path) -> str:
    return (
        f"Analyze the exported reverse-engineering workspace at {workspace}. Inspect its C# or C/C++ source, "
        "IL/disassembly, metadata catalogs, imports, strings, resources, and agent guidance. Write a cohesive "
        "malware research report covering execution flow, capabilities, configuration and infrastructure, "
        "persistence/evasion where supported, notable implementation details, IOCs, uncertainty, and next steps."
    )


def build_workspace_context(workspace: Path, maximum_chars: int = 180_000) -> str:
    """Collect bounded workspace evidence for providers that cannot read local files."""
    workspace = Path(workspace).resolve()
    parts = [_analysis_prompt(workspace), "\n\n=== EXPORTED WORKSPACE EVIDENCE ==="]
    remaining = max(10_000, int(maximum_chars))
    preferred = [
        workspace / "AGENTS.md",
        workspace / "README.md",
        workspace / "catalog" / "assembly.json",
        workspace / "catalog" / "triage_indicators.json",
        workspace / "catalog" / "imports.json",
        workspace / "catalog" / "strings.json",
        workspace / "catalog" / "types.json",
    ]
    source_files = sorted((workspace / "src").rglob("*.cs")) if (workspace / "src").is_dir() else []
    if not source_files:
        source_files = sorted((workspace / "modules").rglob("*.c"))
    if not source_files:
        source_files = sorted((workspace / "cil").rglob("*.il"))

    seen = set()
    for path in [*preferred, *source_files]:
        if path in seen or not path.is_file() or remaining <= 0:
            continue
        seen.add(path)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        excerpt = content[:remaining]
        rel = path.relative_to(workspace).as_posix()
        parts.append(f"\n## {rel}\n```\n{excerpt}\n```")
        remaining -= len(excerpt)
    return "\n".join(parts)


def _run_cli(profile: dict, workspace: Path, prompt: str, timeout: int = 600) -> str:
    provider = str(profile.get("provider") or "")
    executable = str(profile.get("executable") or "").strip()
    model = str(profile.get("model") or "").strip()
    if provider == "AntigravityCLI":
        command = [executable or shutil.which("agy") or "agy", "--dangerously-skip-permissions", "-p", prompt]
    elif provider == "ClaudeCode":
        command = [executable or shutil.which("claude") or "claude", "-p", prompt, "--dangerously-skip-permissions"]
    elif provider == "OpenCode":
        command = [executable or shutil.which("opencode") or "opencode", "run", prompt]
    elif provider == "CopilotCLI":
        cmd = executable or shutil.which("copilot") or shutil.which("gh") or "copilot"
        command = [cmd, "copilot", "explain", prompt] if Path(cmd).stem.lower() == "gh" else [cmd, "-p", prompt, "-s"]
    else:
        raise ValueError(f"Unsupported CLI provider: {provider}")
    if provider != "CopilotCLI" and model.lower() not in ("", "auto", "default"):
        command.extend(["--model", model])
    elif provider == "CopilotCLI" and Path(command[0]).stem.lower() != "gh" and model.lower() not in ("", "auto", "default"):
        command.extend(["--model", model])
    result = subprocess.run(
        command, cwd=str(workspace), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}")
    return (result.stdout or result.stderr).strip()


def _query_chatgpt_account(profile: dict, prompt: str, genesect_root: str, ida_path: str) -> str:
    package_root = find_genesect_package_root(genesect_root, Path(ida_path).parent if ida_path else "")
    if package_root and str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))
    from genesect import chatgpt_oauth

    requested = str(profile.get("model") or "auto")
    if hasattr(chatgpt_oauth, "resolve_model"):
        model = chatgpt_oauth.resolve_model(requested)[0]
    else:
        available = []
        if hasattr(chatgpt_oauth, "list_models"):
            available = [
                item.get("slug") for item in chatgpt_oauth.list_models()
                if isinstance(item, dict) and item.get("slug")
            ]
        model = requested if requested in available else (available[0] if available else requested)
    if hasattr(chatgpt_oauth, "create_response"):
        return str(chatgpt_oauth.create_response(
            model, [{"role": "user", "content": prompt}], instructions=SYSTEM_PROMPT,
            max_output_tokens=8000, timeout=600,
        ) or "").strip()

    # ChatGPT-plan OAuth tokens are authorized for the Responses API, not the
    # API-key Chat Completions route. Stream just as the Genesect client does.
    import openai

    def request(access_token: str) -> str:
        client = openai.OpenAI(api_key=access_token, base_url="https://api.openai.com/v1")
        stream = client.responses.create(
            model=model,
            input=[{"role": "user", "content": prompt}],
            instructions=SYSTEM_PROMPT,
            max_output_tokens=8000,
            store=False,
            stream=True,
        )
        output = []
        completed = False
        with stream:
            for event in stream:
                event_type = getattr(event, "type", "")
                if event_type == "response.output_text.delta":
                    output.append(str(getattr(event, "delta", "") or ""))
                elif event_type == "response.completed":
                    completed = True
                elif event_type == "response.failed":
                    error = getattr(getattr(event, "response", None), "error", None)
                    raise RuntimeError(f"ChatGPT account response failed: {getattr(error, 'code', None) or 'unknown'}")
        if not completed:
            raise RuntimeError("ChatGPT account stream ended without response.completed")
        return "".join(output).strip()

    try:
        return request(chatgpt_oauth.get_access_token())
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        if status != 401 or not hasattr(chatgpt_oauth, "refresh_credentials"):
            raise
        refreshed = chatgpt_oauth.refresh_credentials(force=True)
        token = refreshed.get("access_token") if isinstance(refreshed, dict) else ""
        if not token:
            raise
        return request(token)


def _query_http(profile: dict, prompt: str) -> str:
    provider = str(profile.get("provider") or "OpenAI")
    url = str(profile.get("api_url") or "").rstrip("/")
    key = str(profile.get("api_key") or "")
    model = str(profile.get("model") or "")
    if provider == "Anthropic":
        if url.endswith("/v1/messages"):
            endpoint = url
        elif url.endswith("/v1"):
            endpoint = f"{url}/messages"
        else:
            endpoint = f"{url}/v1/messages"
        headers = {"Content-Type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01"}
        body = {"model": model, "max_tokens": 8000, "messages": [{"role": "user", "content": SYSTEM_PROMPT + "\n\n" + prompt}]}
    else:
        endpoint = url if url.endswith("/chat/completions") else f"{url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        body = {"model": model, "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]}
        token_field = "max_completion_tokens" if any(name in model.lower() for name in ("o1", "o3", "gpt-5")) else "max_tokens"
        body[token_field] = 8000
    request = urllib.request.Request(endpoint, json.dumps(body).encode("utf-8"), headers, method="POST")
    with urllib.request.urlopen(request, timeout=600) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if provider == "Anthropic":
        return "".join(str(item.get("text") or "") for item in payload.get("content", []) if isinstance(item, dict)).strip()
    message = (payload.get("choices") or [{}])[0].get("message") or {}
    return str(message.get("content") or message.get("reasoning_content") or "").strip()


def _query_profile(profile: dict, workspace: Path, context_prompt: str, genesect_root: str, ida_path: str) -> str:
    provider = str(profile.get("provider") or "OpenAI")
    if provider in CLI_PROVIDERS:
        return _run_cli(profile, workspace, _analysis_prompt(workspace))
    if provider == "ChatGPTAccount":
        return _query_chatgpt_account(profile, context_prompt, genesect_root, ida_path)
    return _query_http(profile, context_prompt)


def analyze_workspace(
    workspace: Path | str,
    primary: dict,
    fallback: Optional[dict] = None,
    *,
    genesect_root: str = "",
    ida_path: str = "",
    token_budget: int = 0,
    log_fn: Optional[Callable[[str], None]] = None,
    cancel_checker: Optional[Callable[[], bool]] = None,
) -> dict:
    """Analyze a workspace using primary first, then one configured fallback."""
    log = log_fn or (lambda _message: None)
    workspace = Path(workspace).resolve()
    chain = [dict(primary)]
    if fallback and fallback.get("provider") and fallback.get("provider") != primary.get("provider"):
        chain.append(dict(fallback))
    tracker = UsageTracker(token_budget)
    context_prompt = build_workspace_context(workspace)
    events = []
    last_error = None
    for index, profile in enumerate(chain):
        if cancel_checker and cancel_checker():
            raise RuntimeError("Cancelled by user")
        provider = str(profile.get("provider") or "OpenAI")
        api_url = str(profile.get("api_url") or "")
        if not tracker.allowed(provider, api_url):
            last_error = BudgetExceeded(f"Token budget reached ({tracker.budget_tokens} billable tokens)")
        else:
            try:
                log(f"Analyzing exported workspace with {provider} / {profile.get('model') or 'default'}")
                report = _query_profile(profile, workspace, context_prompt, genesect_root, ida_path)
                if not report:
                    raise RuntimeError("provider returned an empty response")
                tracker.record(provider, str(profile.get("model") or "default"), api_url, context_prompt, report)
                output = workspace / "malware_analysis_report.md"
                output.write_text(report, encoding="utf-8")
                log(f"Workspace analysis report saved to: {output}")
                return {"report_path": str(output), "provider": provider, "usage": tracker.snapshot(), "fallback_events": events}
            except Exception as exc:
                last_error = exc
        if index + 1 < len(chain):
            next_provider = str(chain[index + 1].get("provider") or "OpenAI")
            reason = str(last_error)[:300]
            events.append({"from": provider, "to": next_provider, "reason": reason})
            log(f"Provider {provider} failed ({reason}); falling back to {next_provider}")
    raise RuntimeError(f"Workspace analysis failed: {last_error}")
