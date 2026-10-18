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


EVENT_PREFIX = "OMNI_EVENT "


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

    raise RuntimeError("OmniIDB batch runner did not receive a job JSON path.")


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
        "batch_size": max(1, int(job.get("batch_size", 15))),
        "parallel_workers": max(1, min(8, int(job.get("workers") or job.get("parallel_workers", 3)))),
        "low_score_rescan": bool(job.get("low_score_rescan", False)),
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
    state = {"index": 0}
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

    tracker = (job or {}).get("_tracker")
    import threading
    request_lock = threading.Lock()

    def request(cfg, prompt, sys_prompt, logger=None, on_chunk=None,
                on_cooldown=None, max_tokens=None, cancel_checker=None, **kwargs):
        del on_cooldown, kwargs
        while True:
            if cancel_checker and cancel_checker():
                return ""
            profile_name = worker_cfg.get("profile_name", "OpenAI")
            api_url = worker_cfg.get("api_url") or ""
            if tracker:
                with request_lock:
                    allowed = tracker.allowed(profile_name, api_url)
                if not allowed:
                    with request_lock:
                        switched = switch_provider("token budget reached")
                    if switched:
                        continue
                    from omni_idb.usage import BudgetExceeded
                    raise BudgetExceeded("Token budget reached (%d billable tokens)" % tracker.budget_tokens)
            try:
                result, profile_name = dispatch(cfg, prompt, sys_prompt, logger, on_chunk, max_tokens, cancel_checker)
            except Exception as exc:  # noqa: BLE001 - any provider failure may trigger the fallback
                lowered = str(exc).lower()
                permanent = any(t in lowered for t in ("context length", "context window", "maximum context", "prompt is too long", "too many tokens"))
                with request_lock:
                    switched = switch_provider("%s: %s" % (type(exc).__name__, exc))
                if not permanent and switched:
                    continue
                raise
            if not result and not (cancel_checker and cancel_checker()):
                # Quota/auth failures often surface as empty replies on CLI providers.
                # Retry this request on the fallback instead of returning a lost result.
                with request_lock:
                    switched = switch_provider("empty response")
                if switched:
                    continue
            if tracker and result:
                try:
                    with request_lock:
                        tracker.record(
                            provider=profile_name,
                            model=worker_cfg.get("model") or "default",
                            api_url=api_url,
                            input_text=(sys_prompt or "") + "\n\n" + (prompt or ""),
                            output_text=result,
                        )
                except Exception:
                    pass
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


def pre_process_rust_symbols():
    """Detect and demangle Rust symbols into clean IDA function names before LLM analysis."""
    import idautils
    import idc
    import ida_name
    from omni_idb import rust_support as rs

    candidates = []
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) or ""
        if rs.looks_like_rust_mangled(name):
            candidates.append((ea, name))

    if not candidates:
        return 0

    emit("log", "Detected %d mangled Rust symbols; applying automated demangling..." % len(candidates), level="info")
    renamed = 0
    for ea, name in candidates:
        demangled = rs.demangle_rust_symbol(name)
        if demangled and demangled != name:
            safe_name = rs.ida_safe_rust_name(demangled, ea)
            ok = ida_name.set_name(ea, safe_name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
            if ok:
                renamed += 1
    if renamed > 0:
        emit("log", "Successfully demangled %d Rust symbols" % renamed, level="ok")
    return renamed


def pre_process_go_symbols(sample_path, goresym_path=""):
    """Detect Go binary and restore pclntab symbols if GoReSym is available."""
    from omni_idb import go_support as gs
    import ida_name

    goresym_exe = gs.resolve_goresym(goresym_path)
    if not goresym_exe:
        return 0

    emit("log", "GoReSym detected; recovering pclntab function names and types...", level="info")
    data = gs.run_goresym_restore(sample_path, goresym_exe)
    if not data:
        return 0

    renamed = 0
    funcs = data.get("UserFunctions") or []
    if not funcs and data.get("StdFunctions"):
        funcs = data.get("StdFunctions") or []
    for f in funcs:
        ea = f.get("Start")
        fullname = f.get("FullName")
        if ea and fullname:
            safe = fullname.replace(" ", "_").replace("(", "").replace(")", "").replace("*", "")
            if ida_name.set_name(ea, safe, ida_name.SN_NOWARN | ida_name.SN_FORCE):
                renamed += 1
    if renamed > 0:
        emit("log", "GoReSym restored %d Go function symbols" % renamed, level="ok")
    return renamed


def detect_sample_language():
    """Detect if the current IDB represents a Go or Rust binary using symbols or strings."""
    import idautils
    import idc
    from omni_idb import rust_support as rs
    from omni_idb import go_support as gs

    func_names = []
    for i, ea in enumerate(idautils.Functions()):
        name = idc.get_func_name(ea) or ""
        if name:
            func_names.append(name)
        if i >= 5000:
            break

    for name in func_names:
        if rs.looks_like_rust_mangled(name):
            return "Rust"
        if "." in name and not name.startswith(gs.IDA_PREFIXES):
            pkg_info = gs.classify_go_symbol(name)
            if pkg_info:
                return "Go"

    sample_strings = []
    try:
        strings = idautils.Strings()
        strings.setup(strtypes=getattr(idautils.Strings, "STR_C", 0))
    except Exception:
        strings = idautils.Strings()
    for item in strings:
        try:
            text = str(item)
            if text:
                sample_strings.append(text)
        except Exception:
            continue
        if len(sample_strings) >= 4000:
            break

    rust_triage = rs.detect_rust_confidence(sample_strings, func_names)
    if rust_triage.get("is_rust"):
        return "Rust"

    go_triage = gs.detect_go_confidence(sample_strings, func_names)
    if go_triage.get("is_go"):
        return "Go"

    return None


def detect_protectors_and_packers():
    """Comprehensively detect code virtualization, commercial protectors, packers, and obfuscators."""
    import math
    from collections import Counter
    import ida_bytes
    import ida_segment
    import idautils

    findings = []
    seg_names = []
    high_entropy_segs = []

    def calc_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((n / total) * math.log2(n / total) for n in counts.values())

    for start in idautils.Segments():
        seg = ida_segment.getseg(start)
        if not seg:
            continue
        name = (ida_segment.get_segm_name(seg) or "").lower()
        seg_names.append(name)
        size = int(seg.end_ea) - int(seg.start_ea)
        if size > 4096:
            sample_size = min(size, 65536)
            buf = ida_bytes.get_bytes(int(seg.start_ea), sample_size)
            if buf:
                ent = calc_entropy(buf)
                if ent >= 7.2:
                    high_entropy_segs.append((name, ent, size))

    sample_strings = []
    try:
        strings = idautils.Strings()
        strings.setup(strtypes=getattr(idautils.Strings, "STR_C", 0))
    except Exception:
        strings = idautils.Strings()
    for item in strings:
        try:
            s = str(item).lower()
            if s:
                sample_strings.append(s)
        except Exception:
            continue
        if len(sample_strings) >= 2000:
            break

    def match_sec(marker: str, section_name: str) -> bool:
        # Match section names without substring false positives.
        # Compare normalized section names (e.g. '.upx0' or 'upx0')
        s_clean = section_name.lower().strip()
        m_clean = marker.lower().strip()
        if s_clean == m_clean:
            return True
        # If marker starts with dot, also match without leading dot
        if m_clean.startswith(".") and s_clean == m_clean[1:]:
            return True
        if not m_clean.startswith(".") and s_clean == "." + m_clean:
            return True
        # Allow numbered suffix matches like 'upx0', 'upx1', 'mpress1' if marker ends with wildcard or prefix
        if m_clean in (".upx", "upx", ".mpress", "mpress", ".nsp", "nsp", ".aspack", "aspack", ".vmp", "vmp", ".themida", "themida", ".enigma", "enigma"):
            prefix = m_clean.lstrip(".")
            s_noprefix = s_clean.lstrip(".")
            if s_noprefix.startswith(prefix) and s_noprefix[len(prefix):].isdigit():
                return True
        return False

    def match_marker(marker: str, target: str) -> bool:
        # Match whole word to avoid substring false positives (e.g. 'mpress' in 'compress', 'petite' in 'appetite')
        return bool(re.search(r'(?<![a-zA-Z0-9_])' + re.escape(marker) + r'(?![a-zA-Z0-9_])', target))

    # 1. Code Virtualizers & Heavy Commercial Protectors
    virtualizers = [
        ("VMProtect", (".vmp0", ".vmp1", ".vmp2", "vmp0", "vmp1", "vmp2"), ("vmprotect",)),
        ("Themida / WinLicense", (".themida", "themida", ".winlicense", "winlicense", ".wl", ".oreans"), ("themida", "winlicense", "oreans")),
        ("Enigma Protector", (".enigma1", ".enigma2", "enigma1", "enigma2", ".enigma"), ("enigma protector",)),
        ("Obsidium", (".obsid", "obsid", ".obsidium"), ("obsidium",)),
        ("Code Virtualizer", (".cvirtual", ".virtual"), ("code virtualizer",)),
        ("Safengine / Shielden", (".shield", ".secur", "safengine", ".pedb"), ("safengine", "shielden")),
        ("StarForce", (".sforce", ".peloader"), ("starforce",)),
        ("Denuvo", (".denuvo",), ("denuvo",)),
        ("KoiVM", ("koivm",), ("koivm",)),
    ]

    for name, sec_markers, str_markers in virtualizers:
        hit_secs = [s for s in seg_names if any(match_sec(m, s) for m in sec_markers)]
        hit_strs = [m for m in str_markers if any(match_marker(m, s) for s in sample_strings)]
        if hit_secs or hit_strs:
            detail = ("sections: %s" % ", ".join(hit_secs)) if hit_secs else ("string: '%s'" % hit_strs[0])
            findings.append(("Code Virtualization", "%s (%s)" % (name, detail)))
            break

    # 2. Known Native Packers & Crypter Stubs
    packers = [
        ("UPX", (".upx", "upx0", "upx1", "upx2", "upx!"), ("upx!",)),
        ("ASPack", (".aspack", "aspack", ".adata"), ("aspack",)),
        ("MPRESS", (".mpress", "mpress1", "mpress2"), ("mpress",)),
        ("PECompact", ("pec1", "pec2", "pecompact2", ".pec"), ("pecompact",)),
        ("FSG", ("fsg!", "fsga", "fsg"), ()),
        ("NSPack", (".nsp0", ".nsp1", ".nsp2", "nsp0", "nsp1"), ()),
        ("MEW", ("mew", ".mew"), ()),
        ("Petite", (".petite", "petite"), ("petite",)),
        ("Yoda's Protector", (".yp", ".yoda", "yoda"), ()),
        ("Morphine", (".morph", "morphine"), ()),
        ("Telock", (".telock", "telock"), ()),
        ("Armadillo", (".armidr", "armadillo"), ("armadillo",)),
        ("ASProtect", (".aspr", ".asprot", "asprotect"), ("asprotect",)),
        ("ExeStealth", (".stealth", "stealth"), ()),
        ("eXPressor", (".express", "expressor"), ()),
        ("Packman", (".packman",), ()),
        ("RLPack", (".rlp", "rlpack"), ()),
        ("Molebox", (".box", "molebox"), ()),
        ("kkrunchy", ("kkrunchy",), ()),
        ("UPack", (".upack", "upack"), ()),
        ("Neolite", (".neolite", "neolite"), ()),
        ("SVK Protector", (".svk", "svk"), ()),
        ("ExeCryptor", (".excrypt", "execryptor"), ()),
        ("WWPACK", (".wwpack", "wwpack"), ()),
        ("Generic Crypter Stub", (".stub", ".crypt", ".crypted", ".crp", ".enc", ".payload"), ()),
    ]

    if not any(f[0] == "Code Virtualization" for f in findings):
        for name, sec_markers, str_markers in packers:
            hit_secs = [s for s in seg_names if any(match_sec(m, s) for m in sec_markers)]
            hit_strs = [m for m in str_markers if any(match_marker(m, s) for s in sample_strings)]
            if hit_secs or hit_strs:
                detail = ("sections: %s" % ", ".join(hit_secs)) if hit_secs else ("string: '%s'" % hit_strs[0])
                findings.append(("Packed", "%s (%s)" % (name, detail)))
                break

    # 3. .NET Obfuscators & Protectors
    dotnet_obfuscators = [
        ("ConfuserEx", ("confuserex", "confuser.core", "confusedbyattribute")),
        ("Eazfuscator.NET", ("eazfuscator",)),
        ("SmartAssembly", ("smartassembly", "poweredbyattribute")),
        (".NET Reactor", (".net reactor", "dotnetpaging")),
        ("Agile.NET", ("agile.net", "clisecure")),
        ("Crypto Obfuscator", ("cryptoobfuscator",)),
        ("Babel .NET", ("babel.net", "babelattribute")),
        ("DeepSea Obfuscator", ("deepsea",)),
        ("Goliath.NET", ("goliath.net",)),
    ]

    for name, str_markers in dotnet_obfuscators:
        hit_strs = [m for m in str_markers if any(match_marker(m, s) for s in sample_strings)]
        if hit_strs:
            findings.append(("Obfuscated .NET", "%s (detected '%s')" % (name, hit_strs[0])))
            break

    # 4. Fallback to Shannon Entropy if no specific signature matched
    if not findings and high_entropy_segs:
        highest = max(high_entropy_segs, key=lambda s: s[1])
        findings.append(("Packed / High Entropy", "Section '%s' entropy %.2f (size %d bytes)" % (highest[0], highest[1], highest[2])))

    return findings


IGNORE_CALL_LIST = {
    "rtlntstatustodoserror", "getlasterror", "setlasterror", "rtlgetlastwin32error",
    "rtlsetlastwin32error", "gettickcount", "gettickcount64", "queryperformancecounter",
    "queryperformancefrequency", "rtlzeromemory", "rtlfillmemory", "rtlcomparememory",
    "memset", "memcpy", "memmove", "memcmp", "strlen", "strcpy", "strcat", "strcmp",
    "strncmp", "sprintf", "vsprintf", "printf", "malloc", "free", "realloc", "calloc",
    "entercriticalsection", "leavecriticalsection", "initializecriticalsection",
    "deletecriticalsection", "sleep", "closehandle", "getcurrentprocess",
    "getcurrentthread", "getcurrentprocessid", "getcurrentthreadid", "abort",
}


def filter_high_signal_sub_functions(sub_functions, renamer, max_ceiling=150):
    """Filter and rank sub_* functions for Go/Rust binaries based on API taxonomy & triage signals.

    Instead of an arbitrary small limit that might cut off legitimate capabilities,
    this includes all functions with observable behavioral signals (network, crypto,
    injection, stealer, persistence, commands, URLs, IPs, registry) while skipping
    the thousands of zero-signal compiler runtime and memory allocation functions.
    """
    from omni_idb import classify as cl

    scored = []
    zero_signal = []

    for ea, name in sub_functions:
        calls = renamer.get_calls_fast(ea) if hasattr(renamer, "get_calls_fast") else []
        strings = renamer.get_strings_fast(ea) if hasattr(renamer, "get_strings_fast") else []

        score = 0

        # 1. API Taxonomy & Capabilities (ignoring common runtime/utility noise)
        for call_name in calls:
            clean = cl.normalize_import(call_name).lower()
            if clean in IGNORE_CALL_LIST:
                continue
            caps = cl.capabilities_of_import(call_name)
            for cap in caps:
                if cap in ("injection", "stealer", "persistence", "lateral", "driver"):
                    score += 4
                elif cap in ("dynamic_resolve", "crypto", "network", "anti_debug", "resource"):
                    score += 3
                elif cap in ("process", "registry", "input_capture", "discovery"):
                    score += 2
                elif cap in ("file", "memory", "service", "compression"):
                    score += 1

        # 2. String Triage (commands, URLs, IPs, registry, LOLBins, persistence)
        for s in strings:
            cats = cl.classify_string(s)
            for cat in cats:
                if cat in ("command", "stealer_target", "persistence", "device_driver"):
                    score += 3
                elif cat in ("url", "ip", "domain", "named_pipe"):
                    score += 2
                elif cat in ("registry", "base64_alphabet"):
                    score += 1

        # 3. Call Centrality / Fan-out bonus (functions orchestrating multiple external calls)
        valid_calls = [c for c in calls if cl.normalize_import(c).lower() not in IGNORE_CALL_LIST]
        if len(valid_calls) >= 3:
            score += min(len(valid_calls) // 2, 4)

        if score > 0:
            scored.append((score, len(calls), len(strings), ea, name))
        else:
            zero_signal.append((len(calls), len(strings), ea, name))

    if scored:
        # Sort descending by score, then calls, then strings
        scored.sort(key=lambda item: (-item[0], -item[1], -item[2], item[3]))
        selected = scored[:max_ceiling]
        return [(item[3], item[4]) for item in selected]

    # Fallback if no functions scored > 0: take top 25 with highest activity
    zero_signal.sort(key=lambda item: (-item[0], -item[1], item[2]))
    fallback = zero_signal[:25]
    return [(item[2], item[3]) for item in fallback]


def collect_sub_functions(renamer):
    import idautils
    import idc
    from omni_idb import rust_support as rs
    from omni_idb import go_support as gs

    result = []
    skipped_rust_noise = 0
    skipped_go_noise = 0
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) or ""
        if name.startswith("sub_") and renamer.is_valid_seg(ea):
            # If function is identifiable as Rust stdlib/runtime boilerplate, skip it
            if rs.is_rust_noise_function(name):
                skipped_rust_noise += 1
                continue
            # If function is identifiable as Go stdlib/runtime boilerplate, skip it
            if gs.is_go_noise_function(name):
                skipped_go_noise += 1
                continue
            result.append((int(ea), name))

    if skipped_rust_noise > 0:
        emit("log", "Pruned %d Rust stdlib/runtime boilerplate function(s) from AI queue" % skipped_rust_noise, level="info")
    if skipped_go_noise > 0:
        emit("log", "Pruned %d Go stdlib/runtime boilerplate function(s) from AI queue" % skipped_go_noise, level="info")
    return result


def all_existing_names():
    import idautils
    import idc

    return {
        name for name in (idc.get_func_name(ea) for ea in idautils.Functions())
        if name and not name.startswith("sub_")
    }


def apply_function_name(ea, name, append_address=False):
    import idaapi
    import ida_hexrays
    import ida_name
    import idc
    from genesect.idb_storage import load_from_idb, save_to_idb

    original = load_from_idb(ea, tag=82)
    current = idc.get_func_name(ea)
    if not original:
        if current and not current.startswith("sub_"):
            save_to_idb(ea, current, tag=82)
    candidate = str(name)
    if append_address:
        # Determine address suffix matching IDA convention (e.g. sub_100 -> 100, or hex EA without 0x)
        addr_str = current[4:] if (current and current.startswith("sub_")) else ("%X" % ea)
        if addr_str:
            suffix_pattern = "_" + addr_str.lower()
            if not candidate.lower().endswith(suffix_pattern):
                candidate = "%s_%s" % (candidate, addr_str)
    base_candidate = candidate
    owner = idc.get_name_ea_simple(candidate)
    suffix = 1
    while owner != idaapi.BADADDR and owner != ea:
        candidate = "%s_%d" % (base_candidate, suffix)
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


def run_function_rename(sub_functions, cfg, renamer, cache=None, tracker=None, append_address=False):
    emit("stage", "Renaming functions", stage="functions")
    import idaapi
    import idc
    from omni_idb.rename_cache import fingerprint, is_cacheable_name

    try:
        image_range = (int(idaapi.inf_get_min_ea()), int(idaapi.inf_get_max_ea()))
    except Exception:
        image_range = None

    pending = {}
    for ea, name in sub_functions:
        pending[ea] = renamer.FuncData(ea, name)
    existing = all_existing_names()
    renamed = 0
    failed = 0
    round_index = 0
    cache_hits = 0

    if cache:
        for func in list(pending.values()):
            func.name = idc.get_func_name(func.ea) or func.name
            func.code = renamer.get_code_fast(func.ea, 50000, asm_max=1000)
            fp = fingerprint(func.code, own_name=func.name, user_functions=existing, image_range=image_range)
            hit = cache.lookup_function(fp)
            if hit:
                hit_name, match_type = hit
                ok, final_name = apply_function_name(func.ea, hit_name, append_address=append_address)
                if ok:
                    renamed += 1
                    cache_hits += 1
                    existing.add(final_name)
                    RENAMED.append({"address": "0x%X" % func.ea, "old": func.name, "new": final_name})
                    emit("log", "[cache %s] %s -> %s" % (match_type, func.name, final_name), level="ok")
                    pending.pop(func.ea, None)
        if cache_hits:
            emit("log", "Function rename cache: reused %d name(s)" % cache_hits, level="ok")

    while pending:
        if tracker and not tracker.allowed(cfg.get("profile_name", "OpenAI"), cfg.get("url") or ""):
            emit("log", "Token budget reached; stopping function rename pass early", level="warning")
            break

        round_index += 1
        ready = []
        for index, func in enumerate(list(pending.values())):
            func.name = idc.get_func_name(func.ea) or func.name
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
        batch_sz = max(1, int(cfg.get("batch_size") or 15))
        num_workers = max(1, min(8, int(cfg.get("parallel_workers") or cfg.get("workers") or 3)))
        allow_rescan = bool(cfg.get("low_score_rescan", False))

        worker = renamer.AnalyzeWorker(
            cfg, ready, existing,
            renamer.DEFAULT_BATCH_PROMPT if batch_sz > 1 else renamer.DEFAULT_PROMPT,
            batch_sz, is_retry=True,
            is_low_score_rescan=not allow_rescan,
        )
        if not allow_rescan:
            # Bypass single-function rescan cascade for significantly faster processing
            worker._rescan_low_score_results = lambda res: res

        worker.batch_done.connect(lambda batch: results.extend(batch))
        worker.log.connect(lambda message, level: emit("log", message, level=level))
        worker.update_status.connect(lambda message: emit("log", message) if message else None)

        batches = [ready[i:i + batch_sz] for i in range(0, len(ready), batch_sz)]

        if num_workers > 1 and len(batches) > 1:
            import concurrent.futures
            import threading

            emit("log", "Processing %d batch(es) in parallel across %d worker threads (batch size %d)..." % (
                len(batches), min(num_workers, len(batches)), batch_sz), level="info")
            existing_lock = threading.Lock()
            orig_process_batch = worker.process_batch

            def _process_one_batch(b):
                if not getattr(worker, "running", True):
                    return []
                res = orig_process_batch(b)
                if allow_rescan and not getattr(worker, "is_low_score_rescan", False):
                    res = worker._rescan_low_score_results(res)
                with existing_lock:
                    for _idx, _f, _name, _score in res:
                        if _name and _name not in ("DEFERRED", "DEFERRED_LOW_SCORE"):
                            worker.existing.add(_name)
                return res

            with concurrent.futures.ThreadPoolExecutor(max_workers=min(num_workers, len(batches))) as executor:
                futures = [executor.submit(_process_one_batch, b) for b in batches]
                done_count = 0
                for f in concurrent.futures.as_completed(futures):
                    try:
                        b_res = f.result()
                        if b_res:
                            results.extend(b_res)
                            done_count += len(b_res)
                            emit("progress", "Batch completed (%d/%d functions in round)" % (done_count, len(ready)),
                                 stage="functions", current=len(sub_functions) - len(pending) + done_count, total=len(sub_functions))
                    except Exception as e:
                        emit("log", "Parallel batch error: %s" % e, level="error")
        else:
            worker.run()

        processed = set()
        for _index, func, suggestion, score in results:
            processed.add(func.ea)
            if suggestion and suggestion not in ("DEFERRED", "DEFERRED_LOW_SCORE"):
                ok, final_name = apply_function_name(func.ea, suggestion, append_address=append_address)
                if ok:
                    renamed += 1
                    existing.add(final_name)
                    RENAMED.append({"address": "0x%X" % func.ea, "old": func.name, "new": final_name})
                    emit("log", "%s -> %s (%s)" % (func.name, final_name, score or "unscored"), level="ok")
                    if cache and is_cacheable_name(suggestion):
                        try:
                            fp = fingerprint(func.code, own_name=func.name, user_functions=existing, image_range=image_range)
                            cache.store_function(fp, suggestion, score=score)
                        except Exception:
                            pass
                else:
                    failed += 1
                    emit("log", "IDA rejected function name %s at 0x%X" % (suggestion, func.ea), level="error")
            else:
                failed += 1
                emit("log", "No function rename produced for 0x%X" % func.ea, level="warning")

        # A worker emits one terminal result per item. Guard against provider
        # or Qt failures so an unattended job cannot loop forever.
        for _index, func in ready:
            if func.ea not in processed:
                failed += 1
                emit("log", "Function worker produced no result for 0x%X" % func.ea, level="error")
            pending.pop(func.ea, None)

    return {"candidates": len(sub_functions), "renamed": renamed, "failed": failed, "cache_hits": cache_hits}


def run_variable_rename(sub_functions, cfg, var_renamer, cache=None, tracker=None):
    emit("stage", "Renaming variables", stage="variables")
    import idc
    import ida_hexrays
    import idaapi
    from omni_idb.rename_cache import fingerprint

    try:
        image_range = (int(idaapi.inf_get_min_ea()), int(idaapi.inf_get_max_ea()))
    except Exception:
        image_range = None
    existing = all_existing_names()

    all_items = []
    for index, (ea, original_name) in enumerate(sub_functions):
        all_items.append((index, var_renamer.FuncData(ea, idc.get_func_name(ea) or original_name)))

    functions_changed = 0
    variables_renamed = 0
    failed = 0
    cache_hits = 0
    remaining_items = []

    for index, func in all_items:
        cached = False
        if cache:
            try:
                cfunc = ida_hexrays.decompile(func.ea)
                if cfunc:
                    code = str(cfunc)
                    lvars = [v.name for v in cfunc.get_lvars() if v.name]
                    fp = fingerprint(code, lvar_names=lvars, own_name=func.name, user_functions=existing, image_range=image_range)
                    res = cache.lookup_variables(fp)
                    if res:
                        mapping, kind = res
                        name_map = {fp.var_order[idx]: name for idx, name in mapping.items() if idx < len(fp.var_order)}
                        if name_map:
                            applied, rejected, details = var_renamer.apply_var_renames(
                                func.ea,
                                name_map,
                                log_fn=lambda message, level="info": emit("log", message, level=level),
                            )
                            if applied:
                                functions_changed += 1
                                variables_renamed += applied
                                cache_hits += applied
                                cached = True
                                emit("log", "[cache %s] 0x%X: reused %d variable(s)" % (kind, func.ea, applied), level="ok")
            except Exception:
                pass
        if not cached:
            remaining_items.append((len(remaining_items), func))

    if cache_hits:
        emit("log", "Variable rename cache: reused %d variable(s)" % cache_hits, level="ok")

    if tracker and not tracker.allowed(cfg.get("profile_name", "OpenAI"), cfg.get("url") or ""):
        emit("log", "Token budget reached; skipping LLM variable renaming", level="warning")
        remaining_items = []

    if remaining_items:
        results = []
        emit(
            "progress",
            "Renaming variables in %d remaining function(s)" % len(remaining_items),
            stage="variables",
            current=0,
            total=len(remaining_items),
        )
        worker = var_renamer.VarRenameWorker(cfg, remaining_items, is_retry=True)
        worker.batch_done.connect(lambda batch: results.extend(batch))
        worker.log.connect(lambda message, level: emit("log", message, level=level))
        worker.update_status.connect(lambda message: emit("log", message) if message else None)
        worker.run()

        for _index, func, suggestions in results:
            if not suggestions:
                continue
            pre_rename_fp = None
            if cache:
                try:
                    cfunc = ida_hexrays.decompile(func.ea)
                    if cfunc:
                        code = str(cfunc)
                        lvars = [v.name for v in cfunc.get_lvars() if v.name]
                        pre_rename_fp = fingerprint(code, lvar_names=lvars, own_name=func.name, user_functions=existing, image_range=image_range)
                except Exception:
                    pass
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
            if cache and applied and pre_rename_fp:
                try:
                    canonical_map = {name: i for i, name in enumerate(pre_rename_fp.var_order)}
                    to_store = {canonical_map[old]: new for old, new in suggestions.items() if old in canonical_map}
                    if to_store:
                        cache.store_variables(pre_rename_fp, to_store)
                except Exception:
                    pass

    return {
        "candidates": len(all_items),
        "functions_changed": functions_changed,
        "variables_renamed": variables_renamed,
        "failed": failed,
        "cache_hits": cache_hits,
    }


def run_autonomous_investigation(job, cfg, renamer):
    emit("stage", "Investigating sample", stage="investigation")
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
                "Do not request more tools. Return action=final with a comprehensive executive report in Markdown."
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
        emit("progress", "Synthesizing executive investigation report...", stage="investigation", current=max_turns, total=max_turns)
        synthesis_prompt = (
            "All investigation turns are complete. Based on all collected findings, observations, and evidence, "
            "produce a detailed Markdown Executive Investigation Report. "
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
    report_md_path = output_root / "investigation_report.md"
    dossier_path = output_root / "investigation_dossier.md"
    findings_path = output_root / "investigation_findings.json"

    dossier_lines = [
        "# Autonomous Agent Investigation Report",
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
    report_md_path.write_text(dossier_text, encoding="utf-8")
    dossier_path.write_text(dossier_text, encoding="utf-8")
    findings_path.write_text(session.to_json(), encoding="utf-8")

    emit("log", "Investigation report saved to: %s" % report_md_path, level="ok")
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
        alt_ext = ".idb" if str(target).lower().endswith(".i64") else ".i64"
        alt_target = target.with_suffix(alt_ext)
        if not ida_loader.save_database(str(alt_target), ida_loader.DBFL_COMP):
            raise RuntimeError("IDA could not save the original database to %s" % target)
        target = alt_target
        job["original_idb_path"] = str(alt_target)
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


def _run_cli_agent_workspace(provider, executable, model, ws_path, prompt, timeout=300):
    import shutil
    import subprocess

    ws = Path(ws_path).resolve()
    args = []
    if provider == "AntigravityCLI":
        cmd = executable or shutil.which("agy") or "agy"
        args = [cmd, "--dangerously-skip-permissions", "-p", prompt]
        if model and str(model).lower() not in ("default", "auto", ""):
            args.extend(["--model", str(model)])
    elif provider == "ClaudeCode":
        cmd = executable or shutil.which("claude") or "claude"
        args = [cmd, "-p", prompt, "--dangerously-skip-permissions"]
        if model and str(model).lower() not in ("default", "auto", ""):
            args.extend(["--model", str(model)])
    elif provider == "OpenCode":
        cmd = executable or shutil.which("opencode") or "opencode"
        args = [cmd, "run", prompt]
        if model and str(model).lower() not in ("default", "auto", ""):
            args.extend(["--model", str(model)])
    elif provider == "CopilotCLI":
        cmd = executable or shutil.which("copilot") or shutil.which("gh") or "copilot"
        is_gh = Path(cmd).stem.lower() == "gh"
        if is_gh:
            args = [cmd, "copilot", "explain", prompt]
        else:
            args = [cmd, "-p", prompt, "-s"]
            if model and str(model).lower() not in ("default", "auto", ""):
                args.extend(["--model", str(model)])
    else:
        return None

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    proc = subprocess.run(
        args,
        cwd=str(ws),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=creationflags,
    )
    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError("%s exited with code %s: %s" % (provider, proc.returncode, err))

    raw_output = proc.stdout.strip() or proc.stderr.strip()

    # Detect if agent (e.g. Antigravity CLI / agy) wrote an artifact report file and only printed a summary
    # e.g.: [report_name.md](file:///C:/Users/.../report_name.md)
    import re
    import urllib.parse
    artifact_pattern = re.search(r"\[([^\]]+\.md)\]\((file:///[^\)]+)\)", raw_output, re.IGNORECASE)
    if artifact_pattern:
        file_url = artifact_pattern.group(2)
        try:
            parsed = urllib.parse.urlparse(file_url)
            local_path = urllib.parse.unquote(parsed.path)
            if local_path.startswith("/") and len(local_path) > 3 and local_path[2] == ":":
                local_path = local_path[1:]
            art_file = Path(local_path)
            if art_file.is_file() and art_file.stat().st_size > len(raw_output):
                full_content = art_file.read_text(encoding="utf-8", errors="replace")
                if full_content.strip():
                    emit("log", "Resolved full report from agent artifact: %s (%d bytes)" % (art_file.name, len(full_content)), level="ok")
                    return full_content
        except Exception:
            pass

    return raw_output



def _build_workspace_context_prompt(ws, base_prompt):
    """Collect key facts and triage code from the exported workspace into a comprehensive prompt."""
    sections = [base_prompt, "\n\n=== EXPORTED WORKSPACE CONTEXT ==="]
    agents_file = ws / "AGENTS.md"
    if agents_file.is_file():
        sections.append("\n## Sample Overview (AGENTS.md)\n" + agents_file.read_text(encoding="utf-8", errors="replace")[:2000])

    triage_file = ws / "catalog" / "triage_indicators.json"
    if triage_file.is_file():
        sections.append("\n## Triage Indicators\n" + triage_file.read_text(encoding="utf-8", errors="replace")[:4000])

    imports_file = ws / "catalog" / "imports.json"
    if imports_file.is_file():
        sections.append("\n## Key Imports\n" + imports_file.read_text(encoding="utf-8", errors="replace")[:3000])

    strings_file = ws / "catalog" / "strings.json"
    if strings_file.is_file():
        sections.append("\n## Suspicious Strings\n" + strings_file.read_text(encoding="utf-8", errors="replace")[:3000])

    try:
        if triage_file.is_file():
            tdata = json.loads(triage_file.read_text(encoding="utf-8", errors="replace"))
            ranked = tdata.get("ranked_functions") or []
            budget = 12000
            for item in ranked[:5]:
                mod = item.get("module") or ""
                fn_name = item.get("name") or ""
                clean_name = fn_name.lstrip("_")
                for candidate in (
                    ws / "modules" / mod / (clean_name + ".c"),
                    ws / "modules" / mod / (fn_name + ".c"),
                ):
                    if candidate.is_file():
                        content = candidate.read_text(encoding="utf-8", errors="replace")
                        if len(content) > budget:
                            content = content[:budget] + "\n/* ... truncated ... */"
                        sections.append("\n## Decompiled Function: %s (%s)\n```c\n%s\n```" % (fn_name, item.get("address"), content))
                        budget -= len(content)
                        break
                if budget <= 1000:
                    break
    except Exception:
        pass

    return "\n".join(sections)


def run_workspace_analysis(job, cfg, renamer, workspace_path):
    """Analyze an exported workspace, preserving primary-first provider order."""
    profile = job.get("profile") or {}

    provider = str(profile.get("provider") or job.get("provider") or PROVIDER_INFO.get("active") or "").strip()
    executable = str(profile.get("executable") or job.get("executable") or "").strip()
    model = str(profile.get("model") or job.get("model") or "").strip()

    ws = Path(workspace_path)

    emit("stage", "Analyzing exported AI workspace with %s" % (provider or "AI"), stage="workspace_analysis")
    emit("log", "Invoking %s on exported workspace: %s" % (provider or "AI", workspace_path))


    system_prompt = (
        "You are a senior malware analyst and threat intelligence researcher specializing in "
        "reverse engineering and technical threat reporting."
    )
    prompt = (
        "Analyze the exported IDA decompilation files and triage artifacts in this workspace directory: %s\n\n"
        "Write a clear, concise, and professionally written technical threat intelligence report "
        "based on the evidence in this workspace. The result should read like research written by an experienced "
        "malware analyst, not AI-generated reverse engineering documentation.\n\n"
        "## 1. Writing Style\n"
        "- Write naturally using clear, connected paragraphs and a logical narrative.\n"
        "- Use a professional, human writing style without robotic, academic, or overly formal language.\n"
        "- Avoid repetitive sentence structures, generic AI phrases, unnecessary jargon, and filler.\n"
        "- Remove excessive labels such as 'Confirmed' and 'Hypothesis'. Express uncertainty naturally when needed.\n"
        "- Explain malware behaviour directly without overexplaining implementation details.\n"
        "- Avoid exaggeration, unsupported speculation, and repetitive conclusions.\n"
        "- Prioritize readability without sacrificing technical accuracy.\n\n"
        "## 2. Technical Content\n"
        "- Focus on what the malware does, how it operates, and why its behaviour matters.\n"
        "- If the sample is packed, encrypted, uses code virtualization (VMProtect/Themida), or acts as a crypter/shellcode loader: clearly state this. Document what the packer stub, shellcode, crypter, and process injection actually DO (execution flow, APIs called, memory allocations, and targeted processes) based strictly on observable evidence, without speculating on unextracted payloads.\n"
        "- Explain relevant mechanisms without documenting every function, API parameter, variable, or memory address.\n"
        "- Include technical details such as APIs, commands, file paths, and registry keys only when they contribute to understanding the malware.\n"
        "- Exclude compiler-generated code, runtime initialization, and irrelevant implementation details.\n"
        "- Preserve significant findings, unusual techniques, execution conditions, limitations, and implementation mistakes.\n"
        "- Distinguish observed behaviour from intended behaviour. Never present attempted actions as successfully executed without evidence.\n"
        "- Avoid function-by-function walkthroughs unless necessary to explain a complex mechanism.\n\n"
        "## 3. Report Structure\n"
        "- Do not follow a fixed report template or mandatory section headings.\n"
        "- Determine the report structure based on the malware's actual capabilities, execution flow, and noteworthy findings.\n"
        "- Use meaningful, descriptive headings that naturally fit the analysis.\n"
        "- Combine related behaviours into coherent sections rather than creating unnecessary subsections.\n"
        "- Do not force sections such as Persistence, C2, or Defense Evasion when unsupported or irrelevant.\n"
        "- Use paragraphs as the primary format. Include lists, tables, or diagrams only when they improve clarity.\n"
        "- Ensure the report reads as a cohesive research article rather than a checklist of malware capabilities.\n\n"
        "## 4. Code Snippets\n"
        "- Include short decompiled code snippets only when they illustrate interesting or significant mechanisms.\n"
        "- Prioritize unusual execution methods, encryption, communication protocols, anti-analysis techniques, and implementation mistakes.\n"
        "- Avoid dumping complete functions or including code that adds little analytical value.\n"
        "- Briefly introduce each snippet and explain its significance.\n"
        "- Preserve the original code's technical meaning without fabricating or silently altering behaviour.\n\n"
        "## 5. Evidence and Accuracy\n"
        "- Verify findings against available analysis artifacts, decompiled code, and disassembly.\n"
        "- Preserve important technical evidence and indicators of compromise (IOCs).\n"
        "- Clearly distinguish confirmed observations from assumptions or hypotheses.\n"
        "- Do not infer capabilities or malicious intent from isolated APIs or strings.\n"
        "- Avoid unsupported classifications, such as treating every HTTP request as C2 or ordinary delays as sandbox evasion.\n"
        "- Retain useful source references without excessive inline citations.\n"
        "## 6. Output Format\n"
        "- Output the ENTIRE full, complete technical research report directly in Markdown format.\n"
        "- Do NOT write just a brief summary or redirect to an artifact file; output the entire comprehensive document from title to conclusions.\n\n"
        "## 7. Mandatory IDB Navigation Section\n"
        "- At the end of the report, you MUST include a dedicated section titled '## Key Functions for Reverse Engineering & IDB Navigation'.\n"
        "- Present a markdown table with columns: | Address | Function Name | Original Name | Classification | Assessment & What to Inspect in IDB |\n"
        "- Classify each function as Malicious, Suspicious, or Core Functionality (include both renamed functions and unnamed sub_* routines).\n"
        "- In 'Assessment & What to Inspect in IDB', provide concrete instructions for reverse engineers navigating the IDB in IDA Pro (e.g., F5 decompile hints, cross-references, API parameters, decryption loops).\n\n"
        "Write the publication-quality malware research report now in Markdown format:"
    ) % str(ws.resolve())


    report_text = None
    if provider in CLI_PROVIDERS:
        emit("progress", "Autonomous CLI Agent (%s) inspecting workspace..." % provider, stage="workspace_analysis")
        try:
            report_text = _run_cli_agent_workspace(provider, executable, model, ws, prompt, timeout=300)
        except Exception as exc:
            emit("log", "Autonomous CLI Agent invocation failed (%s); falling back to context synthesis" % exc, level="warning")
            report_text = None

    if not report_text or not report_text.strip():
        emit("progress", "Synthesizing malware analysis report from workspace context...", stage="workspace_analysis")
        context_prompt = _build_workspace_context_prompt(ws, prompt)
        try:
            report_text = renamer.ai_request(cfg, context_prompt, system_prompt, max_tokens=8000)
        except Exception as exc:
            emit("log", "Workspace analysis synthesis failed: %s" % exc, level="error")
            return None

    if not report_text or not report_text.strip():
        emit("log", "Workspace analysis returned empty report.", level="warning")
        return None

    try:
        from omni_idb.workspace_analysis import ensure_report_navigation
        report_text = ensure_report_navigation(report_text, ws, is_dotnet=False, renamed_list=RENAMED)
    except Exception as exc:
        emit("log", "Note: Navigation table check skipped: %s" % exc, level="debug")

    out_file = ws / "malware_analysis_report.md"
    out_file.write_text(report_text, encoding="utf-8")
    emit("log", "Malware analysis report saved to: %s" % out_file, level="ok")
    if job.get("report_dir"):
        r_dir = Path(job["report_dir"])
        r_dir.mkdir(parents=True, exist_ok=True)
        r_file = r_dir / "workspace_analysis.md"
        r_file.write_text(report_text, encoding="utf-8")
        emit("log", "Workspace analysis mirrored to: %s" % r_file, level="ok")

    try:
        from omni_idb import reporting
        sample_path_str = str(job.get("sample_path") or "sample")
        sample_meta = {
            "filename": Path(sample_path_str).name,
            "sha256": job.get("sample_sha256") or "",
            "file_type": job.get("sample_kind", "binary"),
        }
        model_meta = {
            "sample": sample_meta,
            "category": "Malware Analysis Report",
            "provider": {"used": [provider] if provider else []},
            "badges": ["Exported AI Workspace", provider] if provider else ["Exported AI Workspace"],
        }
        reporting.render_markdown_deliverables(
            report_text,
            ws,
            model=model_meta,
            base_name="malware_analysis_report",
            log_fn=lambda m: emit("log", m),
        )
        if job.get("report_dir"):
            r_dir = Path(job["report_dir"])
            reporting.render_markdown_deliverables(
                report_text,
                r_dir,
                model=model_meta,
                base_name="workspace_analysis",
                log_fn=lambda m: emit("log", m),
            )
            reporting.render_markdown_deliverables(
                report_text,
                r_dir,
                model=model_meta,
                base_name="report",
                log_fn=lambda m: emit("log", m),
            )
    except Exception as render_exc:
        emit("log", "Note: Deliverables will be finalized by host process (%s)" % render_exc, level="info")

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

    emit("stage", "Waiting for IDA auto-analysis", stage="ida")
    ida_auto.auto_wait()
    original_idb = save_original_idb(job)

    tracker = None
    try:
        from omni_idb.usage import UsageTracker
        tracker = UsageTracker(
            budget_tokens=int(job.get("token_budget") or 0),
            price_overrides=job.get("pricing"),
        )
        job["_tracker"] = tracker
    except Exception as exc:
        emit("log", "Could not initialize usage tracker: %s" % exc, level="warning")

    cache = None
    cache_path_str = job.get("cache_path")
    if job.get("use_rename_cache", True) and cache_path_str:
        try:
            from omni_idb.rename_cache import RenameCache
            cache = RenameCache(cache_path_str)
        except Exception as exc:
            emit("log", "Could not open rename cache (%s); proceeding without cache" % exc, level="warning")
            cache = None

    cfg = configure_provider(job, CONFIG)
    install_provider_adapter(CONFIG, cfg, renamer, var_renamer, repo_root, job)

    # Demangle or recover Rust / Go symbols before building call graph and rename queue
    rust_detected = False
    go_detected = False

    try:
        if pre_process_rust_symbols() > 0:
            rust_detected = True
    except Exception as exc:
        emit("log", "Rust symbol pre-processing skipped: %s" % exc, level="warning")

    try:
        sample_file = job.get("sample_path", "")
        if sample_file:
            if pre_process_go_symbols(sample_file, job.get("goresym_path", "")) > 0:
                go_detected = True
    except Exception as exc:
        emit("log", "Go symbol pre-processing skipped: %s" % exc, level="warning")

    detected_lang = None
    if rust_detected:
        detected_lang = "Rust"
    elif go_detected:
        detected_lang = "Go"
    else:
        try:
            detected_lang = detect_sample_language()
        except Exception as exc:
            emit("log", "Sample language detection check encountered error: %s" % exc, level="warning")

    # Detect packers, code virtualization, and protectors
    protections = []
    try:
        protections = detect_protectors_and_packers()
        for kind, detail in protections:
            emit("log", "[!] Detected %s: %s" % (kind, detail), level="warning")
    except Exception as exc:
        emit("log", "Protector detection check skipped: %s" % exc, level="warning")

    emit("stage", "Scanning functions", stage="scan")
    sub_functions = collect_sub_functions(renamer)
    emit("progress", "Found %d sub_* function(s)" % len(sub_functions), stage="scan", total=len(sub_functions))
    result = {
        "sample": job.get("sample_path"),
        "idb_path": job.get("idb_path"),
        "original_idb_path": original_idb,
        "workspace_path": "",
        "protections": protections,
        "function_rename": None,
        "variable_rename": None,
        "autonomous_investigation": None,
    }

    is_virtualized = any(kind == "Code Virtualization" for kind, _ in protections)
    is_packed = any("Packed" in kind for kind, _ in protections)
    is_obfuscated_dotnet = any(kind == "Obfuscated .NET" for kind, _ in protections)

    if job.get("rename_functions"):
        if is_virtualized or is_obfuscated_dotnet:
            reason = "Code Virtualization" if is_virtualized else "Obfuscated .NET"
            emit(
                "log",
                "[*] %s detected: auto-skipping function renaming to avoid token waste on obfuscated handlers." % reason,
                level="ok",
            )
            result["function_rename"] = {
                "renamed": 0,
                "skipped": True,
                "reason": "Auto-skipped for %s" % reason,
            }
        else:
            if detected_lang in ("Go", "Rust") and len(sub_functions) > 100:
                emit(
                    "log",
                    "[*] Detected %s binary with %d sub_* functions; running behavioral triage filtering..."
                    % (detected_lang, len(sub_functions)),
                    level="info",
                )
                filtered_subs = filter_high_signal_sub_functions(sub_functions, renamer, max_ceiling=150)
                skipped_count = len(sub_functions) - len(filtered_subs)
                emit(
                    "log",
                    "[*] Prioritized %d high-signal functions (skipped %d zero-signal runtime/allocator functions) to conserve tokens."
                    % (len(filtered_subs), skipped_count),
                    level="ok",
                )
                sub_functions = filtered_subs
            elif is_packed and len(sub_functions) > 25:
                emit(
                    "log",
                    "[*] Packed binary detected with %d sub_* functions; prioritizing top high-signal stub functions..."
                    % len(sub_functions),
                    level="info",
                )
                filtered_subs = filter_high_signal_sub_functions(sub_functions, renamer, max_ceiling=25)
                sub_functions = filtered_subs

            append_addr = bool(job.get("rename_functions_with_address"))
            result["function_rename"] = run_function_rename(
                sub_functions, cfg, renamer, cache=cache, tracker=tracker, append_address=append_addr
            )

    if job.get("rename_variables"):
        if is_virtualized or is_packed or is_obfuscated_dotnet:
            reason = "Code Virtualization" if is_virtualized else ("Packed binary" if is_packed else "Obfuscated .NET")
            emit(
                "log",
                "[*] %s detected: auto-skipping variable rename to avoid token waste on decompiler temporaries." % reason,
                level="ok",
            )
            result["variable_rename"] = {
                "functions_changed": 0,
                "variables_renamed": 0,
                "skipped": True,
                "reason": "Auto-skipped for %s" % reason,
            }
        elif detected_lang in ("Go", "Rust"):
            emit(
                "log",
                "[*] Detected %s binary: auto-skipping variable rename to conserve tokens and avoid runtime noise." % detected_lang,
                level="ok",
            )
            result["variable_rename"] = {
                "functions_changed": 0,
                "variables_renamed": 0,
                "skipped": True,
                "reason": "Auto-skipped for %s binary (token conservation)" % detected_lang,
            }
        else:
            result["variable_rename"] = run_variable_rename(sub_functions, cfg, var_renamer, cache=cache, tracker=tracker)
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
        workspace_path = str(Path(job["workspace_path"]).resolve())
        emit("stage", "Exporting AI workspace", stage="workspace")
        original_names_map = {int(item["address"], 16): item["old"] for item in RENAMED if item.get("address") and item.get("old")}
        try:
            from omni_idb.workspace_export import export_workspace
            export_result = export_workspace(
                workspace_path,
                progress_callback=lambda label, current, total: emit(
                    "progress", label, stage="workspace", current=current, total=total
                ),
                original_names=original_names_map,
            )
            result["workspace_path"] = export_result["path"]
            result["workspace_counts"] = export_result["counts"]
        except Exception as exc:
            emit("log", "Modern workspace export fallback (%s); using legacy exporter" % exc, level="warning")
            exporter_module = load_repository_module(repo_root, "ai_workspace_export")
            export_ai_workspace = exporter_module.export_ai_workspace
            export_result = run_workspace_export(export_ai_workspace, workspace_path)
            result["workspace_path"] = export_result["path"]
            result["workspace_counts"] = export_result["counts"]
        if job.get("analyze_workspace"):
            report_path = run_workspace_analysis(job, cfg, renamer, workspace_path)
            if report_path:
                result["workspace_analysis_report"] = report_path

    if tracker:
        result["usage"] = tracker.snapshot()
        try:
            from omni_idb.usage import describe_usage
            emit("log", describe_usage(result["usage"]), level="info")
        except Exception:
            pass
    if cache:
        try:
            result["cache"] = cache.stats()
            cache.close()
            emit("log", "Rename cache: %d functions, %d variables, %d total hits" % (
                result["cache"]["function_entries"],
                result["cache"]["variable_entries"],
                result["cache"]["total_hits"],
            ), level="info")
        except Exception:
            pass

    idb_path = str(Path(job["idb_path"]).resolve())
    Path(idb_path).parent.mkdir(parents=True, exist_ok=True)
    emit("stage", "Saving analyzed IDB", stage="save")
    if not ida_loader.save_database(idb_path, ida_loader.DBFL_COMP):
        alt_ext = ".idb" if idb_path.lower().endswith(".i64") else ".i64"
        alt_path = str(Path(idb_path).with_suffix(alt_ext))
        if not ida_loader.save_database(alt_path, ida_loader.DBFL_COMP):
            raise RuntimeError("IDA could not save database to %s" % idb_path)
        idb_path = alt_path
        job["idb_path"] = alt_path
    result["idb_path"] = idb_path

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
