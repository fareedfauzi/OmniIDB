"""OmniIDB native .NET Assembly Decompilation & AI Workspace Exporter.

Extracts .NET CLR metadata, TypeDefs, MethodDefs, P/Invoke imports,
user strings, and CIL/C# sources into an agent-ready AI workspace.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


ILSPYCMD_VERSION = "9.1.0.7988"


def is_ilspycmd_available() -> Optional[str]:
    """Check if ilspycmd is available on PATH."""
    direct = shutil.which("ilspycmd") or shutil.which("ilspycmd.exe")
    if direct:
        return direct
    user_tool = Path.home() / ".dotnet" / "tools" / ("ilspycmd.exe" if os.name == "nt" else "ilspycmd")
    return str(user_tool) if user_tool.is_file() else None


def _tool_cache_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "OmniIDB" / "tools" / "ilspycmd" / ILSPYCMD_VERSION


def resolve_ilspycmd(log: Callable[[str], None]) -> List[str]:
    """Resolve ILSpyCmd, downloading the pinned official NuGet tool when needed."""
    direct = is_ilspycmd_available()
    if direct:
        return [direct]
    dotnet = shutil.which("dotnet") or shutil.which("dotnet.exe")
    if not dotnet:
        raise RuntimeError("C# decompilation requires the .NET 8 runtime and ilspycmd. Install .NET 8, then retry.")
    cache = _tool_cache_dir()
    dll = cache / "tools" / "net8.0" / "any" / "ilspycmd.dll"
    if dll.is_file():
        return [dotnet, str(dll)]

    log(f"ilspycmd was not found; downloading official ILSpyCmd {ILSPYCMD_VERSION} from NuGet...")
    cache.mkdir(parents=True, exist_ok=True)
    package = cache / f"ilspycmd.{ILSPYCMD_VERSION}.nupkg"
    url = f"https://api.nuget.org/v3-flatcontainer/ilspycmd/{ILSPYCMD_VERSION}/ilspycmd.{ILSPYCMD_VERSION}.nupkg"
    try:
        urllib.request.urlretrieve(url, package)
        root = cache.resolve()
        with zipfile.ZipFile(package) as archive:
            for member in archive.infolist():
                target = (cache / member.filename).resolve()
                if root != target and root not in target.parents:
                    raise RuntimeError(f"Unsafe path in ILSpyCmd package: {member.filename}")
            archive.extractall(cache)
    except Exception as exc:
        raise RuntimeError(
            "Could not provision ilspycmd for C# decompilation. Install it with "
            f"`dotnet tool install --global ilspycmd --version {ILSPYCMD_VERSION}`. Error: {exc}"
        ) from exc
    finally:
        try:
            package.unlink()
        except OSError:
            pass
    if not dll.is_file():
        candidates = list(cache.rglob("ilspycmd.dll"))
        if not candidates:
            raise RuntimeError("The downloaded ILSpyCmd package did not contain ilspycmd.dll.")
        dll = candidates[0]
    return [dotnet, str(dll)]


def _decode_user_string(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-16-le", errors="replace").rstrip("\x00")
    return str(value or "")


def _format_flags(f: Any) -> str:
    """Format dnfile flag objects or integers safely to readable string."""
    if f is None:
        return "None"
    if isinstance(f, int):
        return hex(f)
    # Check if enum or custom flags object with active attributes
    active = [k for k in dir(f) if not k.startswith("_") and getattr(f, k, None) is True]
    if active:
        return " | ".join(active)
    # Fallback to string or numeric value if available
    val = getattr(f, "value", None)
    if isinstance(val, int):
        return hex(val)
    return str(f).strip() or "0x0"


def _json_default(obj: Any) -> Any:
    """Fallback JSON serializer for dnfile wrapper types (HeapItemString, Enum, etc.)."""
    if hasattr(obj, "value"):
        return obj.value
    return str(obj)


def export_dotnet_workspace(
    sample_path: Path | str,
    output_dir: Path | str,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Export a comprehensive .NET AI Workspace for a .NET executable or library."""
    log = log_fn or (lambda _m: None)
    sample_path = Path(sample_path).resolve()
    out = Path(output_dir).resolve()
    ws_dir = out / "AI Workspace"
    cat_dir = ws_dir / "catalog"
    mod_dir = ws_dir / "modules"
    src_dir = ws_dir / "src"

    for generated_dir in (cat_dir, mod_dir, src_dir, ws_dir / "cil"):
        if generated_dir.is_dir():
            shutil.rmtree(generated_dir)

    cat_dir.mkdir(parents=True, exist_ok=True)
    mod_dir.mkdir(parents=True, exist_ok=True)

    log(f"Extracting .NET metadata for: {sample_path.name}")

    import dnfile

    try:
        dn = dnfile.dnPE(str(sample_path))
    except Exception as exc:
        raise RuntimeError(f"Failed to parse .NET binary with dnfile: {exc}") from exc

    md = getattr(dn, "net", None)
    if not md:
        raise RuntimeError("File does not contain valid .NET CLR metadata headers.")

    tables = getattr(md, "mdtables", None)

    # 1. Assembly Info
    assembly_info: Dict[str, Any] = {
        "sample_name": sample_path.name,
        "sample_size": sample_path.stat().st_size,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "clr_version": getattr(getattr(md, "metadata", None), "version", "Unknown"),
    }

    if tables and hasattr(tables, "Assembly") and tables.Assembly and tables.Assembly.rows:
        row = tables.Assembly.rows[0]
        hash_alg = getattr(row, "HashAlgId", 0)
        assembly_info.update(
            {
                "assembly_name": str(getattr(row, "Name", "") or ""),
                "version": f"{getattr(row, 'MajorVersion', 0)}.{getattr(row, 'MinorVersion', 0)}.{getattr(row, 'BuildNumber', 0)}.{getattr(row, 'RevisionNumber', 0)}",
                "culture": str(getattr(row, "Culture", "") or "neutral"),
                "hash_algorithm": getattr(hash_alg, "value", hash_alg) if not isinstance(hash_alg, (int, str)) else hash_alg,
            }
        )

    # 2. P/Invoke Native Imports
    pinvokes: List[Dict[str, Any]] = []
    if tables and hasattr(tables, "ImplMap") and tables.ImplMap:
        for row in tables.ImplMap.rows:
            scope = getattr(row, "ImportScope", None)
            mod_name = str(scope.row.Name) if scope and getattr(scope, "row", None) and hasattr(scope.row, "Name") else "Unknown"
            pinvokes.append(
                {
                    "function": str(getattr(row, "ImportName", "") or ""),
                    "module": mod_name,
                    "flags": _format_flags(getattr(row, "MappingFlags", 0)),
                }
            )

    # 3. Referenced Assemblies
    references: List[Dict[str, Any]] = []
    if tables and hasattr(tables, "AssemblyRef") and tables.AssemblyRef:
        for row in tables.AssemblyRef.rows:
            references.append(
                {
                    "name": str(getattr(row, "Name", "") or ""),
                    "version": f"{getattr(row, 'MajorVersion', 0)}.{getattr(row, 'MinorVersion', 0)}.{getattr(row, 'BuildNumber', 0)}.{getattr(row, 'RevisionNumber', 0)}",
                    "culture": str(getattr(row, "Culture", "") or "neutral"),
                }
            )

    # 4. TypeDefs and Methods
    types_list: List[Dict[str, Any]] = []
    classes_summary: List[str] = []

    if tables and hasattr(tables, "TypeDef") and tables.TypeDef:
        for t in tables.TypeDef.rows:
            raw_ns = getattr(t, "TypeNamespace", "")
            ns = str(raw_ns).strip() if raw_ns else "Global"
            raw_name = getattr(t, "TypeName", "")
            tname = str(raw_name).strip() if raw_name else ""
            if not tname:
                continue

            base = getattr(t, "Extends", None)
            base_name = ""
            if base and getattr(base, "row", None):
                base_name = str(getattr(base.row, "TypeName", "") or "")

            type_entry: Dict[str, Any] = {
                "namespace": ns,
                "name": tname,
                "extends": base_name,
                "flags": _format_flags(getattr(t, "Flags", 0)),
                "fields": [],
                "methods": [],
            }

            # Methods belonging to this type
            method_list = getattr(t, "MethodList", [])
            for m in method_list:
                mrow = getattr(m, "row", None)
                if not mrow:
                    continue
                m_name = str(getattr(mrow, "Name", "") or "")
                m_rva = getattr(mrow, "Rva", 0)
                m_flags = getattr(mrow, "Flags", 0)
                m_impl = getattr(mrow, "ImplFlags", 0)
                type_entry["methods"].append(
                    {
                        "name": m_name,
                        "rva": hex(m_rva) if isinstance(m_rva, int) and m_rva else "None",
                        "flags": _format_flags(m_flags),
                        "impl_flags": _format_flags(m_impl),
                    }
                )

            # Fields belonging to this type
            field_list = getattr(t, "FieldList", [])
            for f in field_list:
                frow = getattr(f, "row", None)
                if not frow:
                    continue
                type_entry["fields"].append(
                    {
                        "name": str(getattr(frow, "Name", "") or ""),
                        "flags": _format_flags(getattr(frow, "Flags", 0)),
                    }
                )

            types_list.append(type_entry)
            classes_summary.append(f"{ns}.{tname} ({len(type_entry['methods'])} methods)")

    # 5. User Strings (#US Stream)
    user_strings: List[str] = []
    heap = getattr(md, "user_strings", None)
    if heap:
        try:
            sz = heap.sizeof() if callable(heap.sizeof) else heap.sizeof
            off = 1
            while off < sz:
                try:
                    data, item_sz = heap.get_with_size(off)
                    s_val = _decode_user_string(data).strip()
                    if s_val and len(s_val) >= 2:
                        user_strings.append(s_val)
                    off += max(1, item_sz)
                except Exception:
                    off += 1
        except Exception:
            pass

    # Clean & Deduplicate user strings
    clean_strings = sorted(list({s for s in user_strings if s and not s.startswith("b'")}))

    # 6. Triage Indicators
    suspicious_tags = []
    text_corpus = " ".join([m["function"] for m in pinvokes] + clean_strings).lower()
    if any(k in text_corpus for k in ("virtualalloc", "writeprocessmemory", "createremotethread", "queueuserapc")):
        suspicious_tags.append("Process Injection / Memory Allocation")
    if any(k in text_corpus for k in ("http", "socket", "webclient", "downloadfile", "downloadstring", "upload")):
        suspicious_tags.append("Network / HTTP Communication")
    if any(k in text_corpus for k in ("currentversion\\run", "schtasks", "createservice", "startup")):
        suspicious_tags.append("Persistence Mechanism")
    if any(k in text_corpus for k in ("isdebuggerpresent", "checkremotedebuggerpresent", "sleep", "antivm")):
        suspicious_tags.append("Anti-Analysis / Evasion")
    if any(k in text_corpus for k in ("rijndael", "aes", "cryptunprotectdata", "des", "password")):
        suspicious_tags.append("Cryptography / Stealer Logic")

    triage_info = {
        "sample": sample_path.name,
        "is_dotnet": True,
        "runtime": assembly_info.get("clr_version", ""),
        "total_types": len(types_list),
        "total_pinvokes": len(pinvokes),
        "total_user_strings": len(clean_strings),
        "triage_indicators": suspicious_tags,
    }

    # Write Catalog
    (cat_dir / "assembly.json").write_text(json.dumps(assembly_info, indent=2, ensure_ascii=False, default=_json_default), encoding="utf-8")
    (cat_dir / "types.json").write_text(json.dumps(types_list, indent=2, ensure_ascii=False, default=_json_default), encoding="utf-8")
    (cat_dir / "imports.json").write_text(json.dumps({"pinvoke_imports": pinvokes, "referenced_assemblies": references}, indent=2, ensure_ascii=False, default=_json_default), encoding="utf-8")
    (cat_dir / "strings.json").write_text(json.dumps(clean_strings, indent=2, ensure_ascii=False, default=_json_default), encoding="utf-8")
    (cat_dir / "triage_indicators.json").write_text(json.dumps(triage_info, indent=2, ensure_ascii=False, default=_json_default), encoding="utf-8")

    # 7. Generate metadata overviews. Actual CIL is exported by ILSpyCmd below.
    for t in types_list:
        ns = t["namespace"].replace("<", "_").replace(">", "_").replace(":", "_")
        cname = t["name"].replace("<", "_").replace(">", "_").replace(":", "_").replace("`", "_")
        il_file = mod_dir / f"{ns}_{cname}.metadata.txt"
        lines = [
            f"// Type: {t['namespace']}.{t['name']}",
            f"// Base: {t['extends']}",
            f"// Flags: {t['flags']}",
            "",
            f".class {t['name']} {{",
        ]
        for f in t["fields"]:
            lines.append(f"    .field {f['name']} (flags: {f['flags']})")
        if t["fields"]:
            lines.append("")
        for m in t["methods"]:
            lines.append(f"    .method {m['name']}() cil managed {{")
            lines.append(f"        // RVA: {m['rva']}, Flags: {m['flags']}")
            lines.append("    }")
        lines.append("}")
        il_file.write_text("\n".join(lines), encoding="utf-8")

    # 8. Decompile a complete C# project and real CIL with ILSpyCmd.
    decompiled_cs_count = 0
    cil_count = 0
    ilspy_command = resolve_ilspycmd(log)
    log("Decompiling complete C# project and CIL with ILSpyCmd...")
    src_dir.mkdir(parents=True, exist_ok=True)
    cil_dir = ws_dir / "cil"
    cil_dir.mkdir(parents=True, exist_ok=True)
    try:
        cs_result = subprocess.run(
            [*ilspy_command, "--disable-updatecheck", "--nested-directories", "-p", "-o", str(src_dir), str(sample_path)],
            check=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
        )
        decompiled_cs_count = len(list(src_dir.rglob("*.cs")))
        if decompiled_cs_count == 0:
            raise RuntimeError(cs_result.stderr.strip() or "ILSpyCmd produced no C# files")
        il_result = subprocess.run(
            [*ilspy_command, "--disable-updatecheck", "-il", "-o", str(cil_dir), str(sample_path)],
            check=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
        )
        cil_count = len(list(cil_dir.rglob("*.il")))
        if cil_count == 0 and il_result.stdout.strip():
            (cil_dir / "assembly.il").write_text(il_result.stdout, encoding="utf-8")
            cil_count = 1
        log(f"Decompiled {decompiled_cs_count} C# source files and {cil_count} CIL files")
    except Exception as exc:
        raise RuntimeError(f"ILSpyCmd could not decompile the assembly: {exc}") from exc

    # 9. Write AGENTS.md and CLAUDE.md for AI Investigation
    agents_md = [
        f"# OmniIDB AI Workspace — .NET Assembly Analysis: {sample_path.name}",
        "",
        "## Overview",
        f"- **Sample**: `{sample_path.name}`",
        f"- **CLR Runtime**: `{assembly_info.get('clr_version', 'Unknown')}`",
        f"- **Total Types**: {len(types_list)}",
        f"- **Native P/Invoke Imports**: {len(pinvokes)}",
        f"- **Extracted User Strings**: {len(clean_strings)}",
        "",
        "## Structure",
        "- `catalog/assembly.json`: Assembly headers, target runtime, and module entry point.",
        "- `catalog/types.json`: Complete type hierarchy, fields, and method prototypes.",
        "- `catalog/imports.json`: Native Win32 P/Invoke API imports and referenced .NET packages.",
        "- `catalog/strings.json`: String literals extracted from the `#US` (User String) stream.",
        "- `catalog/triage_indicators.json`: High-priority suspicious behavior indicators.",
        "- `modules/*.metadata.txt`: Type, field, and method metadata overviews.",
        f"- `cil/*.il`: Full CIL method-body disassembly ({cil_count} files).",
    ]
    if decompiled_cs_count > 0:
        agents_md.append(f"- `src/**/*.cs`: High-level decompiled C# source code ({decompiled_cs_count} files).")

    agents_md.extend([
        "",
        "## Triage Findings",
    ])
    if suspicious_tags:
        agents_md.extend([f"- ⚠ {tag}" for tag in suspicious_tags])
    else:
        agents_md.append("- No automated high-risk triage flags triggered.")

    agents_md.extend([
        "",
        "## Agent Investigation Guidelines",
        "1. Inspect `catalog/imports.json` for external native capabilities and P/Invoke calls.",
        "2. Examine `catalog/strings.json` for command and control endpoints, file paths, or registry keys.",
        "3. Review `src/**/*.cs` and `cil/*.il` for the main execution logic and control flow.",
    ])

    agents_content = "\n".join(agents_md)
    (ws_dir / "AGENTS.md").write_text(agents_content, encoding="utf-8")
    (ws_dir / "CLAUDE.md").write_text(agents_content, encoding="utf-8")
    (ws_dir / "README.md").write_text(agents_content, encoding="utf-8")

    log(f"[OK] .NET AI Workspace exported successfully ({len(types_list)} types, {len(pinvokes)} P/Invokes, {len(clean_strings)} strings)")

    return {
        "workspace_dir": str(ws_dir),
        "types_count": len(types_list),
        "pinvokes_count": len(pinvokes),
        "strings_count": len(clean_strings),
        "cs_count": decompiled_cs_count,
        "cil_count": cil_count,
    }
