"""Persistent settings, provider defaults and tool auto-detection."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Optional

PROVIDERS = [
    "OpenAI",
    "Anthropic",
    "DeepSeek",
    "GoogleGemini",
    "OpenRouter",
    "Groq",
    "Mistral",
    "OpenAICompatible",
    "Ollama",
    "LMStudio",
    "ChatGPTAccount",
    "ClaudeCode",
    "AntigravityCLI",
    "OpenCode",
    "CopilotCLI",
]

SIGNED_IN_PROVIDERS = {"ChatGPTAccount", "ClaudeCode", "AntigravityCLI", "OpenCode", "CopilotCLI"}
CLI_PROVIDERS = ("ClaudeCode", "AntigravityCLI", "OpenCode", "CopilotCLI")
KEYLESS_PROVIDERS = {"Ollama", "LMStudio"}

# provider -> (api_url, model, executable)
_PROVIDER_DEFAULTS = {
    "OpenAI": ("https://api.openai.com/v1", "gpt-5.1", ""),
    "Anthropic": ("https://api.anthropic.com", "claude-sonnet-4-5", ""),
    "DeepSeek": ("https://api.deepseek.com/v1", "deepseek-chat", ""),
    "GoogleGemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.0-flash", ""),
    "OpenRouter": ("https://openrouter.ai/api/v1", "anthropic/claude-3.7-sonnet", ""),
    "Groq": ("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", ""),
    "Mistral": ("https://api.mistral.ai/v1", "codestral-latest", ""),
    "OpenAICompatible": ("http://localhost:1234/v1", "local-model", ""),
    "Ollama": ("http://localhost:11434/v1", "llama3.2", ""),
    "LMStudio": ("http://localhost:1234/v1", "local-model", ""),
    "ChatGPTAccount": ("", "auto", ""),
    "ClaudeCode": ("", "default", "claude"),
    "AntigravityCLI": ("", "default", "agy"),
    "OpenCode": ("", "default", "opencode"),
    "CopilotCLI": ("", "default", "copilot"),
}

DEFAULT_PROVIDER_MODELS = {
    "OpenAI": ["gpt-5.1", "gpt-4o", "gpt-4o-mini", "o3-mini", "o1"],
    "Anthropic": ["claude-sonnet-4-5", "claude-3-7-sonnet-latest", "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest"],
    "DeepSeek": ["deepseek-chat", "deepseek-reasoner"],
    "GoogleGemini": ["gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-pro", "gemini-1.5-flash"],
    "OpenRouter": ["anthropic/claude-3.7-sonnet", "deepseek/deepseek-r1", "openai/gpt-4o", "meta-llama/llama-3.3-70b-instruct", "qwen/qwen-2.5-coder-32b-instruct"],
    "Groq": ["llama-3.3-70b-versatile", "deepseek-r1-distill-llama-70b", "qwen-2.5-coder-32b", "llama-3.1-8b-instant"],
    "Mistral": ["codestral-latest", "mistral-large-latest", "mistral-small-latest", "ministral-8b-latest"],
    "OpenAICompatible": ["local-model"],
    "Ollama": ["llama3.2", "llama3.1", "qwen2.5-coder", "deepseek-r1"],
    "LMStudio": ["local-model"],
    "ChatGPTAccount": ["auto", "gpt-6.1-sol", "gpt-6-astra", "gpt-6-sol", "gpt-5.6-sol", "gpt-4o"],
    "ClaudeCode": ["default", "claude-3-7-sonnet", "claude-3-5-sonnet", "claude-3-5-haiku", "claude-3-opus"],
    "AntigravityCLI": [
        "default",
        "gemini-4-argon-medium",
        "gemini-4-argon-high",
        "gemini-3.8-flash-high",
        "claude-sonnet-5-5-high",
        "gpt-oss-120b-medium",
    ],
    "OpenCode": ["default", "openai/gpt-4o", "anthropic/claude-3-5-sonnet"],
    "CopilotCLI": ["default", "gpt-4o", "claude-3.5-sonnet", "o1"],
}


def provider_defaults(provider: str) -> tuple[str, str, str]:
    return _PROVIDER_DEFAULTS.get(provider, ("https://api.openai.com/v1", "gpt-5.1", ""))


def default_models_for_provider(provider: str) -> list[str]:
    return list(DEFAULT_PROVIDER_MODELS.get(provider, []))


def is_signed_in_provider(provider: str) -> bool:
    return provider in SIGNED_IN_PROVIDERS


def is_cli_provider(provider: str) -> bool:
    return provider in CLI_PROVIDERS


def project_root() -> Path:
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass and Path(meipass).is_dir():
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def app_dir() -> Path:
    """Return the actual directory where the executable or script is installed/located.

    Unlike project_root(), this does NOT point to PyInstaller's temporary _MEIPASS extraction folder.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent



def _config_dir(app: str) -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / app


def settings_path() -> Path:
    path = _config_dir("OmniIDB") / "settings.json"
    if path.is_file():
        return path
    legacy = _config_dir("Genesector") / "settings.json"
    return legacy if legacy.is_file() else path


def cache_path() -> Path:
    return _config_dir("OmniIDB") / "rename_cache.sqlite3"


def path_text(path) -> str:
    return str(path)


def runner_script(root: Path | str) -> Path:
    """Locate batch_ida_runner.py under an engine root (``scripts/`` or ``genesect/``)."""
    root = Path(root)
    for sub in ("scripts", "genesect"):
        candidate = root / sub / "batch_ida_runner.py"
        if candidate.is_file():
            return candidate
    return root / "scripts" / "batch_ida_runner.py"


def auth_script(root: Path | str) -> Path:
    root = Path(root)
    for sub in ("scripts", "genesect"):
        candidate = root / sub / "auth_cli.py"
        if candidate.is_file():
            return candidate
    return root / "scripts" / "auth_cli.py"


def find_genesect_package_root(*hints: Path | str) -> Optional[Path]:
    """Return the directory containing the ``genesect`` package (the analysis library).

    The batch/auth scripts do ``from genesect import ...``; the package normally lives
    in IDA's ``plugins`` folder rather than next to this project.
    """
    candidates: list[Path] = []
    for hint in hints:
        text = str(hint or "").strip()
        if not text:
            continue
        p = Path(text)
        candidates += [p, p / "plugins", p.parent / "plugins"]
    candidates += [project_root(), project_root().parent]
    for name in ("IDA Professional", "IDA Pro", "IDA Home", "IDA Free"):
        for version in ("9.3", "9.2", "9.1", "9.0", "8.4", "8.3", "8.2", "8.1", "8.0", "7.7", "7.6", "7.5"):
            candidates.append(Path(rf"C:\Program Files\{name} {version}\plugins"))
            candidates.append(Path(rf"C:\Program Files (x86)\{name} {version}\plugins"))
    for candidate in candidates:
        if (candidate / "genesect" / "__init__.py").is_file():
            return candidate
    return None


def detect_engine_root() -> Optional[Path]:
    starts = [project_root(), Path.cwd()]
    for start in starts:
        for directory in [start, *list(start.parents)[:8]]:
            if runner_script(directory).is_file():
                return directory
    for version in ("9.3", "9.2", "9.1", "9.0", "8.4", "8.3"):
        plugin = Path(rf"C:\Program Files\IDA Professional {version}\plugins")
        if (plugin / "genesect").is_dir():
            return plugin
    return None


def detect_ida() -> Optional[Path]:
    import shutil
    for exe in ("ida.exe", "ida64.exe", "ida", "ida64"):
        found = shutil.which(exe)
        if found and Path(found).is_file():
            return Path(found)

    names = ["IDA Professional", "IDA Pro", "IDA Home", "IDA Free", "IDA"]
    versions = ("9.3", "9.2", "9.1", "9.0", "8.4", "8.3", "8.2", "8.1", "8.0", "7.7", "7.6", "7.5", "7.0")
    for base in (r"C:\Program Files", r"C:\Program Files (x86)"):
        for version in versions:
            for name in names:
                for exe in ("ida.exe", "ida64.exe"):
                    candidate = Path(rf"{base}\{name} {version}\{exe}")
                    if candidate.is_file():
                        return candidate
        for name in names:
            for exe in ("ida.exe", "ida64.exe"):
                candidate = Path(rf"{base}\{name}\{exe}")
                if candidate.is_file():
                    return candidate
    return None


@dataclass
class AppSettings:
    input_path: str = ""
    output_root: str = ""
    ida_path: str = ""
    genesect_root: str = ""
    provider: str = "OpenAI"
    api_url: str = "https://api.openai.com/v1"
    model: str = "gpt-5.1"
    executable: str = ""
    rename_functions: bool = True
    rename_functions_with_address: bool = False
    rename_variables: bool = True
    generate_workspace: bool = False
    analyze_workspace: bool = False
    autonomous_investigation: bool = False
    dotnet_mode: str = "skip"  # "skip" | "decompile"
    goresym_path: str = ""
    investigation_turns: int = 10
    recursive: bool = True
    batch_size: int = 15
    workers: int = 3
    low_score_rescan: bool = False
    cooldown_seconds: int = 0
    use_rename_cache: bool = True
    token_budget: int = 0
    fallback_enabled: bool = False
    fallback_provider: str = "Ollama"
    fallback_api_url: str = "http://localhost:11434/v1"
    fallback_model: str = "llama3.2"
    fallback_executable: str = ""

    @classmethod
    def default(cls) -> "AppSettings":
        ida = detect_ida()
        root = detect_engine_root()
        return cls(ida_path=str(ida) if ida else "", genesect_root=str(root) if root else "")

    @classmethod
    def load(cls) -> "AppSettings":
        settings = cls.default()
        try:
            data = json.loads(settings_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return settings
        if not isinstance(data, dict):
            return settings
        known = {f.name: f for f in fields(cls)}
        for key, value in data.items():
            if key in known and isinstance(value, type(getattr(settings, key))):
                setattr(settings, key, value)
        return settings

    def save(self) -> None:
        path = _config_dir("OmniIDB") / "settings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        # The API key is intentionally not part of this dataclass.
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    def apply_provider_defaults(self) -> None:
        self.api_url, self.model, self.executable = provider_defaults(self.provider)

    def apply_fallback_provider_defaults(self) -> None:
        self.fallback_api_url, self.fallback_model, self.fallback_executable = provider_defaults(
            self.fallback_provider
        )

    def infer_output_root(self) -> None:
        text = self.input_path.strip()
        if not text:
            return
        p = Path(text)
        base = p if p.is_dir() else p.parent
        self.output_root = str(base / "omni-idb-output")
