<p align="center">
  <img src="omni-IDB-logo.png" alt="OmniIDB Logo" width="140">
</p>

# OmniIDB

Batch reverse engineering and IDA database enrichment using AI.

[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-8.3%20|%209.x-green.svg)](https://hex-rays.com/ida-pro/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

**OmniIDB** is a desktop GUI and headless batch runner for **Hex-Rays IDA Pro**. Instead of opening IDA files one by one, you point OmniIDB at a binary or a folder of samples. It runs IDA in headless mode, uses LLMs to rename `sub_*` functions and local variables, exports decompiled C workspaces, and saves the updated `.i64` databases.

> **Note on Genesect**: This project is based on [Genesect](https://github.com/fareedfauzi/Genesect) by Fareed Fauzi. Where Genesect focuses on an interactive IDA Pro plugin for working inside IDA on a single sample, OmniIDB focuses on bulk batch jobs: feeding in multiple samples, running them unattended, and saving `original.i64` and `analyzed.i64` databases to disk.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Operations Available](#operations-available)
- [Supported AI Providers](#supported-ai-providers)
- [Input Formats](#input-formats)
- [Output Folder Layout](#output-folder-layout)
- [Relationship to Genesect](#relationship-to-genesect)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## What It Does

- **Batch processing**: Queue up a single binary or entire directories of malware samples.
- **Saves two IDBs**: Keeps `original.i64` (captured right after IDA finishes initial auto-analysis) and `analyzed.i64` (after functions and variables are renamed).
- **Function & variable renaming**: Uses bottom-up call graph analysis so leaf functions get renamed first, giving better context when naming parent functions.
- **Offline AI workspace export**: Dumps decompiled C functions (`decompiled/*.c`), strings, imports, and an `AGENTS.md` file you can feed to external coding agents.
- **AI workspace report (CLI agents)**: Lets agents like Antigravity CLI, Claude Code, or OpenCode review the exported workspace and write a technical malware report.
- **Autonomous multi-turn investigation**: An interactive loop where the LLM queries IDA, checks cross-references, and generates Markdown, HTML, and PDF reports.
- **Provider fallback**: Auto-switches to a secondary provider (e.g. local Ollama) if your primary API runs out of tokens or hits rate limits.
- **No pip dependencies needed**: The GUI and runner use standard Python libraries (`tkinter`, `urllib`, `subprocess`, `sqlite3`).

---

## Requirements

1. **Windows 10/11** (or Linux/macOS with Tkinter).
2. **IDA Pro 8.3+ or 9.x** with Hex-Rays decompiler (`idat.exe` or `ida.exe`).
3. **Python 3.9+**.
4. An AI provider:
   - **Cloud API**: OpenAI, Anthropic, or DeepSeek API key.
   - **Local LLM**: Ollama or LMStudio.
   - **Signed-in CLI**: Antigravity CLI (`agy`), Claude Code (`claude`), OpenCode, or ChatGPT account.

---

## Quick Start

### 1. (Optional) Extra Packages

OmniIDB runs out of the box on standard Python. If you want high-res icon rendering, ReportLab PDFs, or the OpenAI SDK:

```powershell
pip install -r requirements.txt
```

### 2. Run the App

From PowerShell or CMD:

```powershell
# Run with Python
python -m omni_idb

# Or use the launcher batch file
.\omni-idb.bat

# You can also pass a file or folder directly
python -m omni_idb C:\Samples\malware.exe
```

The GUI launches maximized by default.

### 3. Build Standalone `.exe`

To compile everything into a single portable Windows executable:

```powershell
.\build_exe.bat
```

This generates `OmniIDB.exe` directly in the project root with the embedded custom icon, and cleans up all intermediate build files automatically.

---

## Operations Available

In the UI, you can pick and choose which tasks to run:

| Option | What it does |
| :--- | :--- |
| **Rename sub_* functions** | Analyzes control flow, strings, and APIs to give `sub_*` routines descriptive names. |
| **Rename variables & parameters** | Uses Hex-Rays to replace `v1`, `a1` with meaningful variable names. |
| **Export AI workspace** | Dumps decompiled C code, imports, strings, and `AGENTS.md` into an offline folder. |
| **↳ Proceed analysis of workspace** | Available for CLI agents (`agy`, `claude`, `opencode`). The agent reads the exported files and writes a technical report. |
| **Autonomous Investigation** | Multi-turn agent loop (3–30 turns) that inspects IDA memory and outputs HTML, PDF, and MD reports. |

---

## Supported AI Providers

OmniIDB supports 10 backends:

| Provider | Setup | Model Discovery |
| :--- | :--- | :--- |
| **OpenAI** | API Key (`sk-...`) | Auto-fetches via `/v1/models` |
| **Anthropic** | API Key (`sk-ant-...`) | Auto-fetches via `/v1/models` |
| **DeepSeek** | API Key (`sk-...`) | Auto-fetches via `/v1/models` |
| **OpenAICompatible** | URL + optional key | Auto-fetches via `/v1/models` |
| **Ollama** | Local (default `localhost:11434`) | Auto-fetches tags |
| **LMStudio** | Local (default `localhost:1234`) | Auto-fetches models |
| **ChatGPTAccount** | Browser login (OAuth) | Auto-detects models |
| **AntigravityCLI** | Local `agy` CLI | Auto-fetches `agy models` |
| **ClaudeCode** | Local `claude` CLI | Claude 3.5 / 3.7 models |
| **OpenCode** | Local `opencode` CLI | Reads configured providers |

### Testing Connections & Model Discovery
Click **⚡ Test Connection** (or **⚡ Test Main** / **⚡ Test Fallback** if fallback is enabled). OmniIDB checks authentication in-process and automatically populates the model dropdown with available models.

### Fallback Provider
If your primary API provider hits rate limits or token limits, check **Enable Fallback Provider** and pick a backup (like a local Ollama model). OmniIDB will auto-route queries to the fallback if the primary fails.

---

## Input Formats

- **Supported binaries**: Windows PE (`.exe`, `.dll`, `.sys`, `.exe_`), Linux ELF, macOS Mach-O, and existing IDA databases (`.idb`, `.i64`).
- **Raw shellcode**: Check **Accept raw shellcode** and pick the architecture (`x64`, `x86`, `arm`, `arm64`). OmniIDB loads it at offset `0x0`.
- **Auto-filtering**: Non-binary files (scripts, code, text, images) are skipped automatically during directory scans so your queue stays clean.

---

## Output Folder Layout

Each sample gets a subfolder named `<name>-<sha256>`:

```text
C:\Output\sample.exe-a1b2c3d4\
├── IDB Files\
│   ├── original.i64            # Untouched IDB right after auto-analysis
│   └── analyzed.i64            # Renamed IDB with all AI edits
├── AI Workspace\               # (If "Export AI workspace" is checked)
│   ├── AGENTS.md               # Folder map and instructions for AI agents
│   ├── manifest.json           # Metadata (hashes, entrypoint, compiler)
│   ├── strings.tsv             # Extracted strings
│   ├── imports.tsv             # API imports
│   ├── decompiled\             # C decompilations (sub_*.c)
│   └── malware_analysis_report.md
├── report\                     # (If "Autonomous Investigation" is checked)
│   ├── report.md               # Markdown report with MITRE tags
│   ├── report.html             # Dark-mode HTML report
│   ├── report.pdf              # PDF report
│   └── report_model.json
├── logs\
│   ├── ida.log                 # Raw IDA console output
│   └── failure.txt             # Error log (if failed)
└── result.json                 # Run stats (runtime, rename counts)
```

---

## Relationship to Genesect

OmniIDB is based on [Genesect](https://github.com/fareedfauzi/Genesect) by **Fareed Fauzi**.

- **Genesect** is an **in-IDA plugin**: you open IDA, click functions, and chat with the AI helper interactively while analyzing a single binary.
- **OmniIDB** is a **batch queue tool**: you give it a list of files or a sample folder, it runs IDA in the background, updates the databases, exports workspaces, and writes reports without you having to click through IDA manually.

| Feature | Genesect | OmniIDB |
| :--- | :--- | :--- |
| **Primary focus** | Interactive analysis inside IDA | Headless bulk batch analysis |
| **Typical use** | One sample at a time with analyst in the loop | Dozens or hundreds of samples unattended |
| **Interface** | Dockable panel inside IDA Pro | Standalone GUI or `.exe` launcher |
| **Output** | Modifies current open IDB | Saves `original.i64` and `analyzed.i64` pairs |

---

## Troubleshooting

- **`Could not find platform dependent libraries <exec_prefix>`**: Normal warning from IDA's embedded Python. Safe to ignore.
- **`IDA executable not found`**: If IDA is in a custom path, click **Browse...** next to IDA Executable and select `ida.exe` or `idat.exe`.
- **`ChatGPT Account error: Not signed in`**: Select **ChatGPTAccount** and click **Continue with ChatGPT in Browser** to log in once.
- **`Workspace Analysis option disabled`**: The "Proceed analysis of exported workspace" checkbox is only for local CLI agents (`agy`, `claude`, `opencode`) because sending entire workspaces to cloud APIs consumes too many tokens.

---

## License

MIT
