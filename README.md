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

> **Note on Genesect**: This project is based on [Genesect](https://github.com/fareedfauzi/Genesect). Where Genesect focuses on an interactive IDA Pro plugin for working inside IDA on a single sample, OmniIDB focuses on bulk batch jobs: feeding in multiple samples, running them unattended, and saving `original.i64` and `analyzed.i64` databases to disk.

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
   - **Cloud API**: OpenAI, Anthropic, DeepSeek, Google Gemini, OpenRouter, Groq, or Mistral API key.
   - **Local LLM**: Ollama or LMStudio.
   - **Signed-in CLI**: GitHub Copilot CLI (`copilot` / `gh copilot`), Antigravity CLI (`agy`), Claude Code (`claude`), OpenCode, or ChatGPT account.

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
| **Rename sub_ functions** | Analyzes control flow, strings, and APIs to give `sub_*` routines descriptive names. |
| **Rename variables & parameters** | Uses Hex-Rays to replace `v1`, `a1` with meaningful variable names. |
| **Export AI workspace** | Dumps decompiled C code, imports, strings, and `AGENTS.md` into an offline folder. |
| **Exported Workspace AI Analysis** | CLI agents inspect exported files directly. ChatGPT Account and API providers receive a bounded source/catalog evidence bundle. All modes write a Markdown report and honor primary-first fallback. |
| **Autonomous Investigation** | Multi-turn agent loop (3–30 turns) that inspects IDA memory and outputs HTML, PDF, and MD reports. |

---

## Supported AI Providers

OmniIDB supports 15 backends:

| Provider | Setup | Model Discovery |
| :--- | :--- | :--- |
| **OpenAI** | API Key (`sk-...`) | Auto-fetches via `/v1/models` |
| **Anthropic** | API Key (`sk-ant-...`) | Auto-fetches via `/v1/models` |
| **DeepSeek** | API Key (`sk-...`) | Auto-fetches via `/v1/models` |
| **GoogleGemini** | API Key (`AIza...`) | Auto-fetches Gemini 2.5/2.0/1.5 via Google AI Studio |
| **OpenRouter** | API Key (`sk-or-...`) | Auto-fetches all aggregator models via OpenRouter |
| **Groq** | API Key (`gsk_...`) | Auto-fetches high-speed Llama & Mixtral models |
| **Mistral** | API Key (`...`) | Auto-fetches Mistral & Codestral models |
| **OpenAICompatible** | URL + optional key | Auto-fetches via `/v1/models` |
| **Ollama** | Local (default `localhost:11434`) | Auto-fetches tags |
| **LMStudio** | Local (default `localhost:1234`) | Auto-fetches models |
| **ChatGPTAccount** | Browser login (OAuth) | Auto-detects models |
| **CopilotCLI** | Local `copilot` or `gh copilot` | Auto-detects Copilot models |
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
- **Managed .NET assemblies**: The .NET mode exports a compilable ILSpy C# project, full CIL, metadata, strings, resources, and optional workspace analysis without launching IDA. ILSpyCmd is provisioned from the official NuGet package on first use when it is not already installed.

---

## Output Folder Layout

Each sample gets a subfolder named `<name>-<sha256[:12]>`:

```text
C:\Output\sample.exe-a1b2c3d4e5f6\
├── IDB Files\
│   ├── original.i64            # Untouched IDB right after initial auto-analysis
│   └── analyzed.i64            # Renamed IDB with all AI function & variable names
├── AI Workspace\               # (If "Export AI workspace" is checked)
│   ├── AGENTS.md               # Quick-start orientation guide for coding agents
│   ├── README.md               # Sample overview, module counts, and suspicious functions
│   ├── CLAUDE.md               # Pointer to AGENTS.md
│   ├── headers\
│   │   ├── omni_types.h        # IDA local types + Hex-Rays compatibility shims
│   │   └── signatures.h        # Recovered function declarations and prototypes
│   ├── modules\                # Functions grouped by behavioral category
│   │   ├── 00_entry_runtime\   # Entry points, DllMain, TLS, CRT start-up
│   │   ├── 01_network_c2\      # Sockets, WinINet/WinHTTP, URLs, C2 beaconing
│   │   ├── 02_crypto_encoding\ # Ciphers, hashes, Base64/XOR routines
│   │   ├── 03_evasion_injection\# Dynamic API resolve, injection, anti-debug
│   │   ├── 04_system_files\    # Registry, file system, processes
│   │   ├── 05_stealer_credentials\# DPAPI, browser vaults, keyloggers, clipboard
│   │   ├── 06_persistence_autorun\# Services, scheduled tasks, Run keys, startup
│   │   ├── 07_discovery_recon\ # Host profiling, network/share enumeration, user recon
│   │   ├── 08_lateral_movement\# Named pipes, remote RPC, PsExec patterns
│   │   ├── 09_compression_archive\# Zlib, LZMA, CAB, ZIP extraction & packing
│   │   ├── 10_driver_kernel_ipc\# DeviceIoControl, driver loading, raw disk access
│   │   ├── 11_gui_interface\   # Windows message loops, dialogs, UI controls
│   │   ├── 98_library_thunks\  # FLIRT matches and import stubs
│   │   └── 99_utilities\       # Generic helper functions
│   │       └── <func>.c        # Decompiled C code with types header include
│   │       └── <func>.asm      # Full IDA disassembly
│   │       └── <func>.brief.md # Per-function summary: callers, callees, APIs, triage score
│   └── catalog\                # Machine-readable JSON indexes
│       ├── functions.json      # All functions with prototype, callers, callees, triage
│       ├── triage_indicators.json # Suspicious signals (crypto, injection, stack buffers)
│       ├── strings.json        # Classified strings (URLs, IPs, registry keys, commands)
│       ├── imports.json        # Imports categorized by capability with caller list
│       ├── exports.json        # Exported functions and ordinals
│       ├── sections.json       # PE/ELF segments with entropy calculation
│       ├── callgraph.json      # Adjacency list of call edges
│       ├── callgraph.tsv       # Tab-separated caller-callee pairs
│       └── sample.json         # Architecture, hashes, bitness, and image base
├── report\                     # (If "Autonomous Investigation" is checked)
│   ├── report.md               # Markdown report with MITRE ATT&CK mappings
│   ├── report.html             # Standalone dark-mode HTML report
│   ├── report.pdf              # PDF report deliverable
│   └── report_model.json       # Evidence-gated JSON report model
├── logs\
│   ├── ida.log                 # Raw IDA console output
│   └── failure.txt             # Error log with traceback (if a run failed)
└── result.json                 # Execution stats, rename counts, cache hits, token usage
```

Managed .NET samples intentionally omit `IDB Files` and instead use:

```text
AI Workspace/
├── src/                        # Decompiled C# project, one source file per type
├── cil/                        # Full CIL method-body disassembly
├── modules/                    # Metadata overviews
├── catalog/                    # Assembly, type, import, string, and triage JSON
└── malware_analysis_report.md  # When workspace analysis is selected
```

---

## Workspace Exporter Design

The workspace exporter redesign organizes binary decompilations into an offline structure that coding agents (like Claude Code, Antigravity CLI, or Cursor) and human analysts can read without running IDA:

- **Behavioral modules**: Functions are classified into `00_entry_runtime` through `99_utilities` based on the APIs they call, strings referenced, crypto constants (AES S-box, MD5/SHA state, RC4 loops), stack buffer sizes, and call-graph neighbor propagation.
- **Three files per function**: Each routine has `<stem>.c` (Hex-Rays decompilation with `#include "headers/omni_types.h"`), `<stem>.asm` (IDA disassembly), and `<stem>.brief.md` (quick facts, callers/callees, triage indicators).
- **Consolidated headers**: Local types recovered from IDA's Type Info Library are exported to `headers/omni_types.h` alongside editor-friendly shims for Hex-Rays annotations (`__usercall`, `__int64`, etc.).
- **Triage catalog**: `catalog/triage_indicators.json` ranks suspicious routines by weighted heuristics (dynamic API resolution, process injection, crypto constants, command lines) to prioritize where to start reading.

---

## Rename Cache & Cross-Sample Consensus

Analyzing dozens of samples across malware campaigns often encounters repeated code (standard helper routines, crypto algorithms, decompression stubs). OmniIDB includes a persistent SQLite rename cache (`%LOCALAPPDATA%\OmniIDB\rename_cache.sqlite3`):

- **Normalized fingerprinting**: Generates exact and structural fingerprints by masking local variable names (`V0`, `V1`, ...), call addresses, and numeric literals so identical logic matches across different base addresses and compilers.
- **Consensus matching**: Reuses function names only when structural matches achieve at least 60% agreement across stored samples.
- **Variable cache**: Maps canonical variable order back to renamed variables, skipping repetitive LLM requests.
- **Management in GUI**: Enable/disable the cache with a single checkbox or click **Clear Cache** in the *IDA Pro & Environment Configuration* card to reset the database.

---

## Token & Cost Tracking with Budget Cap

To keep API usage transparent and prevent unexpected bills:

- **Token estimates & live cost tracking**: Monitors character counts (~3.5 chars/token) and estimates costs in real time using public price tables for OpenAI, Anthropic, DeepSeek, Google Gemini, OpenRouter, Groq, and Mistral.
- **Free provider exemptions**: Local models (Ollama, LMStudio), private API endpoints, and signed-in CLI subscriptions (Copilot CLI, Antigravity CLI, Claude Code) are automatically treated as zero-cost.
- **Batch token budget cap**: Set a maximum token cap under *Token Budget* (e.g. `200000`). If the cap is reached, OmniIDB either fails over to a free fallback provider or gracefully stops further LLM queries for the batch while safely saving all databases and exported workspaces.

---

## Unit Testing

OmniIDB includes a test suite covering module classification, import capabilities, layout generation, fingerprint stability, rename cache roundtrips, and token budgeting:

```powershell
python -m unittest discover -s tests -v
```

---

## Relationship to Genesect

OmniIDB is based on [Genesect](https://github.com/fareedfauzi/Genesect).

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
