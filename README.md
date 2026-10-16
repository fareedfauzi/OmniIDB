<p align="center">
  <img src="omni-IDB-logo.png" alt="OmniIDB Logo" width="160">
</p>

# OmniIDB

<p align="center">
  <strong>Autonomous Bulk AI Reverse Engineering & IDB Enrichment Workbench for Hex-Rays IDA Pro</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=flat&logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/GUI-Tkinter%20(Zero--Dependency)-0F172A?style=flat" alt="Tkinter">
  <img src="https://img.shields.io/badge/IDA%20Pro-8.3%20|%209.x-006699?style=flat" alt="IDA Pro">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat" alt="License">
</p>

---

**OmniIDB** is a standalone, pure-Python desktop workbench and headless batch orchestrator for automated reverse engineering and database enrichment in **Hex-Rays IDA Pro**. It processes single binaries or entire malware sample repositories unattended, executing semantic subroutine renaming, Hex-Rays variable recovery, offline AI workspace generation, and autonomous multi-turn investigations.

OmniIDB requires **no third-party pip dependencies** to run its GUI or core engine—it runs on the standard Python distribution bundled with Windows or IDA Pro.

---

## Table of Contents

- [Key Features](#key-features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Analysis Operations](#analysis-operations)
  - [1. Semantic Function Renaming](#1-semantic-function-renaming)
  - [2. Local Variable & Parameter Recovery](#2-local-variable--parameter-recovery)
  - [3. Export AI Workspace & Context Pack](#3-export-ai-workspace--context-pack)
  - [4. Proceed Analysis of Exported AI Workspace (CLI Agents)](#4-proceed-analysis-of-exported-ai-workspace-cli-agents)
  - [5. Autonomous Agentic Investigation (Multi-Turn REAI)](#5-autonomous-agentic-investigation-multi-turn-reai)
- [Supported AI Providers & Model Discovery](#supported-ai-providers--model-discovery)
  - [Direct API Providers](#direct-api-providers)
  - [Local Self-Hosted LLMs](#local-self-hosted-llms)
  - [Signed-In CLI Agent Providers](#signed-in-cli-agent-providers)
  - [⚡ Dynamic Live Model Retrieval](#-dynamic-live-model-retrieval)
  - [Automatic Provider Fallback & Failover](#automatic-provider-fallback--failover)
- [Workbench UI & Navigation](#workbench-ui--navigation)
- [Input Filtering & Shellcode Support](#input-filtering--shellcode-support)
- [Output Directory Structure](#output-directory-structure)
- [Testing & Verification](#testing--verification)
- [Troubleshooting & FAQ](#troubleshooting--faq)

---

## Key Features

- **Pristine & Enriched IDB Output**: Automatically archives `original.i64` immediately following IDA's initial auto-wait, followed by `analyzed.i64` containing all AI modifications.
- **Dependency-Aware Deobfuscation**: Traverses call graphs from leaf routines upwards to resolve semantics before naming parent dispatchers.
- **Real-Time Sample Queue Telemetry**: Displays per-sample status, elapsed execution time (`mm:ss`), and live pipeline stages (*Rename functions*, *Rename variables*, *Export AI Workspace*, *Analyze AI Workspace*, *Perform Autonomous Investigation*).
- **Auto-Failover Protection**: Auto-switches to a secondary fallback provider if primary tokens or rate limits are exceeded.
- **Offline Workspace Packaging**: Dumps decompiled C code, notable strings, imported APIs, and graph models into an offline context folder with `AGENTS.md`.
- **Publication-Grade Reports**: Generates technical intelligence dossiers in Markdown, styled dark-mode HTML, and vector PDF (ReportLab or built-in standard-library PDF generator).
- **Zero PIP Bloat**: Core engine, GUI, and batch runners utilize only Python standard library modules (`tkinter`, `urllib`, `sqlite3`, `subprocess`, `queue`).

---

## Requirements

1. **Operating System**: Windows 10/11 (or Linux/macOS with standard Tkinter support).
2. **IDA Pro**: IDA Pro 8.3, 8.4, 9.0, 9.1, 9.2, or 9.3 with Hex-Rays Decompiler (`idat.exe` or `ida.exe`).
3. **Python**: Python 3.9+ with Tkinter.
4. **AI Connectivity**: At least one of the following:
   - An API key for **OpenAI**, **Anthropic**, or **DeepSeek**.
   - A local instance of **Ollama** or **LMStudio**.
   - A signed-in CLI session (**Antigravity CLI**, **ChatGPT Account**, **Claude Code**, or **OpenCode**).

---

## Quick Start

### 1. Installation (Optional Dependencies)

OmniIDB's core engine runs on the Python standard library. To install enhanced packages (high-resolution icon rendering, vector ReportLab PDFs, OpenAI SDK):

```powershell
pip install -r requirements.txt
```

### 2. Launching the GUI

Clone or extract OmniIDB and run:

```powershell
# From PowerShell or Command Prompt
python -m omni_idb

# Or using the Windows batch launcher
.\omni-idb.bat
```

To pre-load a sample file or directory on launch:

```powershell
python -m omni_idb C:\Malware\Samples
# or a specific binary:
python -m omni_idb C:\Malware\Samples\payload.exe
```

The GUI automatically launches in **maximized full-screen mode** with modern JetBrains Mono typography.

### 3. Compiling to Standalone Windows Executable (.exe)

OmniIDB includes an automated build script `build_exe.bat` that bundles Python, the Tkinter user interface, IDA automation scripts, and the high-resolution application icon into a single, self-contained `OmniIDB.exe`:

```powershell
# Double-click in Windows Explorer or run from terminal:
.\build_exe.bat
```

The build script automatically:
1. Verifies Python 3.10+ and `pip`.
2. Installs or checks build prerequisites (`pyinstaller`, `pillow`, `reportlab`, `openai`).
3. Generates the multi-resolution icon (`omni-IDB-logo.ico`) from `omni-IDB-logo.png`.
4. Compiles the binary with the embedded logo icon and offline runtime assets.
5. Moves `OmniIDB.exe` directly to the project root and automatically removes all intermediate build clutter (`build/`, `dist/`, `.spec` files).

---

## Analysis Operations

OmniIDB allows granular control over which reverse-engineering tasks to run across queued binaries:

```
[✓] Rename sub_* functions (semantic naming)
[✓] Rename local variables & parameters
[ ] Export OmniIDB AI workspace & context pack
    └── [ ] Proceed analysis of the Exported AI workspace (CLI Agents only)
[ ] Autonomous Agentic Investigation (multi-turn AI analysis)
```

### 1. Semantic Function Renaming
- Runs dependency-aware, bottom-up function naming on unnamed routines (`sub_*`).
- Analyzes control flow, localized string references, and imported APIs to produce clear, descriptive names (e.g. `aes256_decrypt_payload`, `inject_thread_remote_process`).
- Leaves user-defined names and standard runtime thunks untouched.

### 2. Local Variable & Parameter Recovery
- Invokes Hex-Rays decompilation on modified functions to rename stack variables, registers, and function parameters.
- Replaces generic identifiers (`v1`, `v2`, `a1`) with descriptive domain names (`buffer_len`, `pCiphertext`, `hTargetProcess`).

### 3. Export OmniIDB AI Workspace & Context Pack
- *(Off by default)*
- Extracts an offline, portable AI context pack:
  - `decompiled/*.c`: Clean C decompilations with IDA metadata.
  - `strings.tsv`: Notable strings with deduplication and IOC classification.
  - `imports.tsv`: Categorized API imports.
  - `manifest.json`: Architecture, bitness, entry point, and compiler details.
  - `AGENTS.md`: Technical instruction layout enabling external agents to navigate the project.

### 4. Proceed Analysis of Exported AI Workspace (CLI Agents)
- When **Export OmniIDB AI workspace** is enabled, this nested sub-option becomes available.
- **Direct API Safety Guard**: Disabled for direct API providers (`OpenAI`, `Anthropic`, etc.) to prevent dumping hundreds of thousands of tokens into web APIs.
- **CLI Agent Execution**: Available when using autonomous agents like **Antigravity CLI (`agy`)**, **Claude Code (`claude`)**, or **OpenCode**.
- Instructs the agent to explore the exported workspace folder directly on disk, analyze `AGENTS.md` and decompiled code, and author a technical report structured in the writing style of **Kaspersky GReAT**, **ESET Research**, and **Google Threat Intelligence Group**.

### 5. Autonomous Agentic Investigation (Multi-Turn REAI)
- *(Off by default, configurable from 3 to 30 turns)*
- Conducts an interactive investigation loop where the model queries IDA memory, extracts cross-references, validates hypotheses, and synthesizes an executive dossier.
- Produces:
  - `report/report.md`: Markdown technical report with MITRE ATT&CK mappings.
  - `report/report.html`: Interactive dark-mode styled HTML report.
  - `report/report.pdf`: Publication-grade vector PDF.

---

## Supported AI Providers & Model Discovery

OmniIDB supports 10 distinct AI backends:

| Provider | Type | Authentication | Model Discovery |
| :--- | :--- | :--- | :--- |
| **OpenAI** | Cloud API | API Key (`sk-...`) | Dynamic via `GET /v1/models` |
| **Anthropic** | Cloud API | API Key (`sk-ant-...`) | Dynamic via `GET /v1/models` |
| **DeepSeek** | Cloud API | API Key (`sk-...`) | Dynamic via `GET /v1/models` |
| **OpenAICompatible** | Local/Remote API | Optional API Key | Dynamic via `GET /v1/models` |
| **Ollama** | Local LLM | Keyless (Default: `localhost:11434`) | Dynamic via `GET /api/tags` |
| **LMStudio** | Local LLM | Keyless (Default: `localhost:1234`) | Dynamic via `GET /v1/models` |
| **ChatGPTAccount** | Browser Session | Interactive Browser OAuth | Dynamic via `list_models()` |
| **AntigravityCLI** | Local Agent CLI | Signed-in session (`agy`) | Dynamic via `agy models` |
| **ClaudeCode** | Local Agent CLI | Signed-in session (`claude`) | Curated Claude 3.5 / 3.7 models |
| **OpenCode** | Local Agent CLI | `auth.json` provider store | Dynamic via `auth.json` providers |

### ⚡ Dynamic Live Model Retrieval

OmniIDB features live model discovery. When you select a provider and click **⚡ Test Connection**:

1. The test runner authenticates against the service.
2. It actively fetches the live catalogue of models from the provider's endpoint or CLI engine.
3. The **Model** dropdown (`ttk.Combobox`) is dynamically updated with all available models.
4. The resolved active model is automatically selected and saved to your configuration.

### Automatic Provider Fallback & Failover

Network instability, cloud token limits, or API rate limits (`HTTP 429`) can disrupt batch runs. OmniIDB solves this with **Automatic Failover**:

1. In the **AI Engine Configuration** card, check **Enable Fallback Provider**.
2. Select your fallback backend (e.g. Primary: `OpenAI / gpt-5.1`, Fallback: `Ollama / llama3.2` or `AntigravityCLI`).
3. If the primary provider hits quota limits, context exhaustion, or repeated errors, OmniIDB immediately routes subsequent prompts to the fallback provider.
4. Failover events are recorded in real-time logs and annotated in the final analysis report.

---

## Workbench UI & Navigation

OmniIDB provides a unified slate-navy interface split into clean operational zones:

1. **Target Sample / Directory**:
   - Browse for an individual executable or an entire directory of samples.
   - Toggle recursive subfolder scanning.
   - Configure architecture options for raw shellcode.
2. **Analysis Operations**:
   - Toggles for renaming, workspace packaging, and agentic investigation.
   - Output path selection.
3. **AI Engine Configuration**:
   - Provider selection, API URL, secure masked key entry, and model selection.
   - Fallback provider setup.
   - Real-time connection test button and status pill.
4. **IDA Pro Configuration**:
   - Auto-detected or custom IDA executable path.
5. **Multi-Tab Execution Console**:
   - **`📋 Sample Queue`**: Displays all queued binaries with status chips (`All`, `Pending`, `Running`, `Done`, `Failed`), current stage, and elapsed time.
   - **`📜 Activity Log`**: Color-coded diagnostic log.
   - **`📝 ida.log`**: Live stream of IDA Pro kernel messages.
   - **`🔲 Split View`**: Side-by-side queue and activity console (auto-activated upon starting a run).

---

## Input Filtering & Shellcode Support

### Automated Binary Verification
OmniIDB validates binaries by reading structural magic headers before queueing them:
- **Accepted**: Windows PE (`MZ`/`PE`), Linux ELF (`\x7fELF`), macOS Mach-O (`\xfe\xed\xfa\xce`, `\xcf\xfa\xed\xfe`), and existing IDA databases (`.idb`, `.i64`).
- **Rejected**: Non-executable formats such as images (JPEG, PNG, GIF), documents (PDF, DOCX), archives (ZIP, 7z), text files, or corrupted headers. Rejection reasons are logged.

### Raw Shellcode Support
For raw shellcode files (`.bin`, `.raw`, `.sc`, `.shellcode`):
1. Check **Accept raw shellcode**.
2. Select the target architecture (**x64**, **x86**, **arm**, or **arm64**).
3. OmniIDB instructs IDA to invoke the binary loader, creates an entry function at offset `0x0`, and executes the analysis pipeline.

---

## Output Directory Structure

Each sample is organized in its own isolated subfolder named `<sample_name>-<sha256_prefix>`:

```text
C:\Output\Downloader.exe-a1b2c3d4\
├── IDB Files\
│   ├── original.i64            # Pristine database captured immediately after initial auto-analysis
│   └── analyzed.i64            # Enriched database with renamed functions, variables, and comments
├── AI Workspace\               # (Generated when "Export AI workspace" is enabled)
│   ├── AGENTS.md               # Context documentation for agent navigation
│   ├── manifest.json           # Binary metadata and properties
│   ├── strings.tsv             # Extracted strings and IOCs
│   ├── imports.tsv             # Imported API listings
│   ├── decompiled\             # Exported C decompilations
│   │   ├── sub_401000.c
│   │   └── sub_401520.c
│   └── malware_analysis_report.md  # Structured report generated by CLI agents
├── report\                     # (Generated when Autonomous Investigation is enabled)
│   ├── report_model.json       # Machine-readable triage findings and MITRE tactics
│   ├── report.md               # Technical markdown report
│   ├── report.html             # Standalone dark-mode HTML report
│   └── report.pdf              # Publication-grade vector PDF report
├── logs\
│   ├── ida.log                 # Full streaming kernel log from IDA Pro
│   └── failure.txt             # Diagnostic details (if execution encountered an error)
└── result.json                 # Execution summary, elapsed time, and rename counts
```

---

## Testing & Verification

OmniIDB includes a comprehensive regression test suite covering classification, job serialization, stage mapping, and provider discovery:

```powershell
python -m unittest discover -s tests
```

To compile and verify syntax across all source files:

```powershell
python -m py_compile omni_idb\app.py omni_idb\config.py omni_idb\runner.py scripts\batch_ida_runner.py scripts\auth_cli.py
```

---

## Troubleshooting & FAQ

#### 1. "Could not find platform dependent libraries <exec_prefix>"
- This warning may appear in IDA Pro's console when running embedded Python. It is benign and does not affect analysis or script execution.

#### 2. "IDA executable not found"
- OmniIDB automatically scans default installation directories for IDA Pro (`C:\Program Files\IDA Professional 9.x` or `8.x`). If IDA is installed elsewhere, use the **Browse...** button in the IDA Pro Configuration card to locate `ida.exe` or `idat.exe`.

#### 3. "ChatGPT Account error: Not signed in"
- Select **ChatGPTAccount** as the provider and click the **↗ Continue with ChatGPT in Browser** button. Complete authentication in your browser window to store credentials under `~/.genesect/chatgpt`.

#### 4. "CLI Agent Workspace Analysis is disabled"
- Direct API providers (OpenAI, Anthropic, DeepSeek, etc.) do not have local file system access and would consume excessive tokens. To enable **Proceed analysis of the Exported AI workspace**, select a local CLI agent provider (**AntigravityCLI**, **ClaudeCode**, or **OpenCode**).

---

## License

OmniIDB is licensed under the [MIT License](LICENSE).
