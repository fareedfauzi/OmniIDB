# -*- coding: utf-8 -*-
"""Small standalone entry point for Genesect account authentication.

This intentionally imports only the existing ChatGPT OAuth implementation.  It
can be started by the OmniIDB launcher with the user's regular Python interpreter,
without starting IDA first.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _bootstrap_repo():
    package_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(package_dir)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    ida_plugin_candidates = [
        Path(r"C:\Program Files\IDA Professional 9.3\plugins"),
        Path(r"C:\Program Files\IDA Professional 9.2\plugins"),
        Path(r"C:\Program Files\IDA Professional 9.1\plugins"),
        Path(r"C:\Program Files\IDA Professional 9.0\plugins"),
        Path(os.environ.get("APPDATA", "")) / "Hex-Rays" / "IDA Pro" / "plugins",
    ]
    for candidate in ida_plugin_candidates:
        if candidate.is_dir() and str(candidate) not in sys.path:
            sys.path.append(str(candidate))


def _opencode_status():
    try:
        from genesect import opencode_auth
        return opencode_auth.credential_status()
    except (ImportError, AttributeError):
        pass
    candidates = []
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
                if isinstance(parsed, dict) and parsed:
                    return {"signed_in": True, "providers": list(parsed.keys())}
            except Exception:
                continue
    return {"signed_in": False, "providers": []}


def _opencode_sign_in(exe_arg=None):
    try:
        from genesect import opencode_auth
        return opencode_auth.launch_sign_in_terminal(executable=exe_arg)
    except (ImportError, AttributeError):
        pass
    import shutil
    import subprocess
    cmd = exe_arg or shutil.which("opencode") or "opencode"
    try:
        if sys.platform == "win32":
            subprocess.Popen(["cmd.exe", "/c", "start", cmd, "auth", "login"], shell=False)
        else:
            subprocess.Popen([cmd, "auth", "login"])
        return True, "Launched OpenCode sign-in terminal."
    except Exception as exc:
        return False, str(exc)


def test_connection(cfg):
    import time
    import urllib.request
    import urllib.error

    provider = str(cfg.get("provider") or "OpenAI")
    api_url = str(cfg.get("api_url") or "").strip()
    api_key = str(cfg.get("api_key") or "").strip()
    model = str(cfg.get("model") or "").strip()
    executable = str(cfg.get("executable") or "").strip()
    t0 = time.time()

    if provider == "ChatGPTAccount":
        from genesect import chatgpt_oauth
        status = chatgpt_oauth.credential_status()
        if not status.get("signed_in"):
            return {"ok": False, "message": "Not signed in to ChatGPT Account. Click 'Sign In' first."}
        try:
            available_models = []
            if hasattr(chatgpt_oauth, "list_models"):
                try:
                    raw_m = chatgpt_oauth.list_models()
                    available_models = [m.get("slug") for m in raw_m if isinstance(m, dict) and m.get("slug")]
                except Exception:
                    pass

            selected_model = model or (available_models[0] if available_models else "auto")
            if hasattr(chatgpt_oauth, "resolve_model"):
                selected_model, _available = chatgpt_oauth.resolve_model(model)
                if not available_models and _available:
                    available_models = list(_available)

            if hasattr(chatgpt_oauth, "create_response"):
                chatgpt_oauth.create_response(
                    selected_model,
                    [{"role": "user", "content": "Reply with OK."}],
                    instructions="Connection test.",
                    max_output_tokens=32,
                    timeout=30,
                )
            else:
                token = chatgpt_oauth.get_access_token()
                if not token:
                    return {"ok": False, "message": "Could not retrieve access token for ChatGPT Account."}
                if hasattr(chatgpt_oauth, "list_models"):
                    chatgpt_oauth.list_models()

            elapsed = int((time.time() - t0) * 1000)
            message = f"Connected to ChatGPT Account using {selected_model} ({elapsed}ms)"
            return {
                "ok": True,
                "message": message,
                "model": selected_model,
                "available_models": available_models,
            }
        except Exception as exc:
            return {"ok": False, "message": f"ChatGPT Account error: {exc}"}

    elif provider == "OpenCode":
        st = _opencode_status()
        elapsed = int((time.time() - t0) * 1000)
        available_models = ["default"]
        if st.get("providers"):
            for prov in st["providers"]:
                if prov == "openai":
                    available_models.extend(["openai/gpt-4o", "openai/gpt-4o-mini", "openai/o3-mini", "openai/o1"])
                elif prov == "anthropic":
                    available_models.extend(["anthropic/claude-3-7-sonnet", "anthropic/claude-3-5-sonnet"])
                elif prov == "deepseek":
                    available_models.extend(["deepseek/deepseek-chat", "deepseek/deepseek-reasoner"])
        import shutil
        import subprocess
        cmd_name = executable or shutil.which("opencode") or "opencode"
        try:
            res_m = subprocess.run([cmd_name, "models"], capture_output=True, text=True, timeout=10)
            if res_m.returncode == 0:
                parsed_models = [line.strip().split()[0] for line in res_m.stdout.splitlines() if line.strip()]
                if parsed_models:
                    available_models = parsed_models
        except Exception:
            pass

        if st.get("signed_in"):
            provs = ", ".join(st.get("providers", []))
            return {
                "ok": True,
                "message": f"Connected to OpenCode (providers: {provs}) ({elapsed}ms)",
                "available_models": available_models,
            }
        try:
            res = subprocess.run([cmd_name, "--version"], capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                ver = (res.stdout.strip() or res.stderr.strip()).splitlines()[0] if res.stdout or res.stderr else "ready"
                return {
                    "ok": True,
                    "message": f"OpenCode ready: {ver} ({elapsed}ms), but no saved accounts in auth.json",
                    "available_models": available_models,
                }
            return {"ok": False, "message": "Not signed in to OpenCode. Click 'Sign In' to authenticate."}
        except Exception:
            return {"ok": False, "message": "Not signed in to OpenCode. Click 'Sign In' or run 'opencode auth login'."}

    elif provider in ("ClaudeCode", "AntigravityCLI", "CopilotCLI"):
        import subprocess
        cmd_name = executable or ("claude" if provider == "ClaudeCode" else ("copilot" if provider == "CopilotCLI" else "agy"))
        try:
            res = subprocess.run([cmd_name, "--version"], capture_output=True, text=True, timeout=10)
            elapsed = int((time.time() - t0) * 1000)
            if res.returncode != 0 and provider == "CopilotCLI" and not executable:
                res_gh = subprocess.run(["gh", "copilot", "--version"], capture_output=True, text=True, timeout=10)
                if res_gh.returncode == 0:
                    cmd_name = "gh copilot"
                    res = res_gh
            if res.returncode != 0:
                return {"ok": False, "message": f"{cmd_name} returned code {res.returncode}: {res.stderr.strip()[:100]}"}

            ver = (res.stdout.strip() or res.stderr.strip()).splitlines()[0] if res.stdout or res.stderr else "ready"
            available_models = ["default"]
            if provider == "AntigravityCLI":
                try:
                    res_m = subprocess.run([cmd_name, "models"], capture_output=True, text=True, timeout=10)
                    if res_m.returncode == 0:
                        for line in res_m.stdout.splitlines():
                            line = line.strip()
                            if line and not line.lower().startswith("fetching") and not line.lower().startswith("available"):
                                parts = line.split()
                                if parts and parts[0] not in available_models:
                                    available_models.append(parts[0])
                except Exception:
                    pass
            elif provider == "ClaudeCode":
                available_models = ["default", "claude-3-7-sonnet", "claude-3-5-sonnet", "claude-3-5-haiku", "claude-3-opus"]
            elif provider == "CopilotCLI":
                available_models = ["default", "gpt-4o", "claude-3.5-sonnet", "o1"]

            return {
                "ok": True,
                "message": f"{provider} ready: {ver} ({elapsed}ms)",
                "available_models": available_models,
            }
        except Exception as exc:
            if provider == "CopilotCLI" and not executable:
                try:
                    res_gh = subprocess.run(["gh", "--version"], capture_output=True, text=True, timeout=10)
                    if res_gh.returncode == 0:
                        ver = (res_gh.stdout.strip() or "").splitlines()[0]
                        return {
                            "ok": True,
                            "message": f"GitHub CLI ready: {ver} ({int((time.time() - t0) * 1000)}ms)",
                            "available_models": ["default", "gpt-4o", "claude-3.5-sonnet", "o1"],
                        }
                except Exception:
                    pass
            return {"ok": False, "message": f"Could not run {cmd_name}: {exc}"}

    elif provider == "Anthropic":
        url = api_url.rstrip("/") or "https://api.anthropic.com"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        available_models = []
        try:
            req_m = urllib.request.Request(f"{url}/v1/models", headers=headers, method="GET")
            with urllib.request.urlopen(req_m, timeout=10) as resp_m:
                m_data = json.loads(resp_m.read().decode("utf-8"))
                available_models = [
                    item["id"] for item in m_data.get("data", [])
                    if isinstance(item, dict) and item.get("id")
                ]
        except Exception:
            pass

        req_url = f"{url}/v1/messages"
        probe_model = model or (available_models[0] if available_models else "claude-sonnet-4-5")
        body = {
            "model": probe_model,
            "max_tokens": 5,
            "messages": [{"role": "user", "content": "ping"}],
        }
        try:
            req = urllib.request.Request(req_url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "ok": True,
                    "message": f"Connected to Anthropic ({probe_model}, {elapsed}ms)",
                    "available_models": available_models or ["claude-sonnet-4-5", "claude-3-7-sonnet-latest", "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest"],
                }
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")[:120]
            if available_models:
                return {
                    "ok": True,
                    "message": f"Connected to Anthropic ({len(available_models)} models retrieved)",
                    "available_models": available_models,
                }
            return {"ok": False, "message": f"Anthropic HTTP {exc.code}: {err_body}"}
        except Exception as exc:
            return {"ok": False, "message": f"Anthropic error: {exc}"}

    else:
        # OpenAI, DeepSeek, GoogleGemini, OpenRouter, Groq, Mistral, Ollama, LMStudio, OpenAICompatible
        default_url_map = {
            "OpenAI": "https://api.openai.com/v1",
            "DeepSeek": "https://api.deepseek.com/v1",
            "GoogleGemini": "https://generativelanguage.googleapis.com/v1beta/openai",
            "OpenRouter": "https://openrouter.ai/api/v1",
            "Groq": "https://api.groq.com/openai/v1",
            "Mistral": "https://api.mistral.ai/v1",
            "Ollama": "http://localhost:11434/v1",
            "LMStudio": "http://localhost:1234/v1",
            "OpenAICompatible": "http://localhost:1234/v1",
        }
        default_probe_map = {
            "OpenAI": "gpt-5.1",
            "DeepSeek": "deepseek-chat",
            "GoogleGemini": "gemini-2.0-flash",
            "OpenRouter": "anthropic/claude-3.7-sonnet",
            "Groq": "llama-3.3-70b-versatile",
            "Mistral": "codestral-latest",
            "Ollama": "llama3.2",
            "LMStudio": "local-model",
            "OpenAICompatible": "local-model",
        }
        fallback_url = default_url_map.get(provider, "https://api.openai.com/v1")
        url = api_url.rstrip("/") or fallback_url
        base_url = url
        for suffix in ("/chat/completions", "/completions", "/models"):
            if base_url.endswith(suffix):
                base_url = base_url[:-len(suffix)].rstrip("/")

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        available_models = []
        model_endpoints = []
        if base_url.endswith("/v1") or base_url.endswith("/openai"):
            model_endpoints.append(f"{base_url}/models")
        else:
            model_endpoints.extend([f"{base_url}/v1/models", f"{base_url}/models"])
        if provider == "Ollama":
            ollama_host = base_url[:-3] if base_url.endswith("/v1") else base_url
            model_endpoints.append(f"{ollama_host}/api/tags")

        for m_url in model_endpoints:
            try:
                req_m = urllib.request.Request(m_url, headers=headers, method="GET")
                with urllib.request.urlopen(req_m, timeout=10) as resp_m:
                    m_data = json.loads(resp_m.read().decode("utf-8"))
                    items = m_data.get("data") or m_data.get("models") or []
                    for item in items:
                        if isinstance(item, dict):
                            mid = item.get("id") or item.get("name") or item.get("model")
                            if mid and mid not in available_models:
                                available_models.append(mid)
                    if available_models:
                        break
            except Exception:
                continue

        req_url = f"{base_url}/chat/completions" if (base_url.endswith("/v1") or base_url.endswith("/openai")) else f"{base_url}/v1/chat/completions"
        probe_model = model or (available_models[0] if available_models else default_probe_map.get(provider, "gpt-4o"))
        body = {
            "model": probe_model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 5,
        }
        try:
            req = urllib.request.Request(req_url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                elapsed = int((time.time() - t0) * 1000)
                return {
                    "ok": True,
                    "message": f"Connected to {provider} ({probe_model}, {elapsed}ms)",
                    "available_models": available_models,
                }
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")[:120]
            if available_models:
                return {
                    "ok": True,
                    "message": f"Connected to {provider} ({len(available_models)} models retrieved)",
                    "available_models": available_models,
                }
            return {"ok": False, "message": f"HTTP {exc.code}: {err_body}"}
        except Exception as exc:
            if available_models:
                return {
                    "ok": True,
                    "message": f"Connected to {provider} ({len(available_models)} models available)",
                    "available_models": available_models,
                }
            return {"ok": False, "message": f"Connection error: {exc}"}


def main(argv=None):
    _bootstrap_repo()

    args = list(argv if argv is not None else sys.argv[1:])
    command = args[0].lower() if args else "status"

    if command in ("sign-in", "sign-out", "status"):
        try:
            from genesect import chatgpt_oauth
        except ImportError as exc:
            print(json.dumps({"ok": False, "message": f"ChatGPT OAuth module not found: {exc}"}))
            return 1
        if command == "sign-in":
            data = chatgpt_oauth.sign_in_interactive()
            print(json.dumps({
                "ok": True,
                "email": data.get("email", ""),
                "message": "ChatGPT sign-in complete.",
            }))
            return 0
        if command == "sign-out":
            chatgpt_oauth.sign_out()
            print(json.dumps({"ok": True, "message": "ChatGPT signed out."}))
            return 0
        if command == "status":
            print(json.dumps(chatgpt_oauth.credential_status(), sort_keys=True))
            return 0
    if command == "opencode-status":
        print(json.dumps(_opencode_status(), sort_keys=True))
        return 0
    if command == "opencode-sign-in":
        exe_arg = args[1] if len(args) > 1 else None
        ok, msg = _opencode_sign_in(exe_arg=exe_arg)
        print(json.dumps({"ok": ok, "message": msg}))
        return 0 if ok else 1
    if command == "test-connection":
        raw = sys.stdin.read().strip() if (len(args) <= 1 or args[1] == "-") else args[1]
        payload = json.loads(raw) if raw else {}
        print(json.dumps(test_connection(payload)))
        return 0
    print(json.dumps({"ok": False, "message": "Expected sign-in, sign-out, status, opencode-status, opencode-sign-in, or test-connection."}))
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"ok": False, "message": str(exc)}))
        raise SystemExit(1)
