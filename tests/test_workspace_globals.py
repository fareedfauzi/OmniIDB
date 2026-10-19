import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from omni_idb.workspace_export import collect_globals, write_globals
from omni_idb.workspace_analysis import build_workspace_context


class WorkspaceGlobalTests(unittest.TestCase):
    def test_collects_named_and_referenced_globals_with_usage(self):
        data_segment = types.SimpleNamespace(type=0)
        code_function = types.SimpleNamespace(start_ea=0x401000)

        def get_func(ea):
            return code_function if 0x401000 <= int(ea) < 0x401100 else None

        def xrefs_to(ea, _flags):
            if int(ea) != 0x402000:
                return []
            return [
                types.SimpleNamespace(frm=0x401010, type=3),
                types.SimpleNamespace(frm=0x401020, type=2),
            ]

        modules = {
            "idaapi": types.SimpleNamespace(BADADDR=-1),
            "ida_bytes": types.SimpleNamespace(
                get_item_head=lambda ea: ea,
                get_flags=lambda _ea: 1,
                get_item_size=lambda _ea: 4,
                has_value=lambda _flags: True,
                is_strlit=lambda _flags: False,
                is_float=lambda _flags: False,
                is_off0=lambda _flags: False,
                get_bytes=lambda _ea, _size: b"\x78\x56\x34\x12",
            ),
            "ida_funcs": types.SimpleNamespace(
                get_func=get_func,
                get_func_name=lambda ea: "main" if int(ea) == 0x401000 else "",
            ),
            "ida_ida": types.SimpleNamespace(inf_is_be=lambda: False),
            "ida_segment": types.SimpleNamespace(
                SEG_CODE=2,
                getseg=lambda _ea: data_segment,
                get_segm_name=lambda _segment: ".data",
            ),
            "ida_xref": types.SimpleNamespace(dr_W=2, dr_R=3),
            "idautils": types.SimpleNamespace(
                Names=lambda: [(0x402000, "g_config"), (0x403000, "CreateFileW")],
                Functions=lambda: [0x401000],
                FuncItems=lambda _ea: [0x401010, 0x401020],
                DataRefsFrom=lambda ea: [0x402000, 0x403000] if int(ea) == 0x401010 else [],
                XrefsTo=xrefs_to,
            ),
            "idc": types.SimpleNamespace(
                INF_SHORT_DN=0,
                get_type=lambda ea: "config_t" if int(ea) == 0x402000 else "",
                get_name=lambda ea: "g_config" if int(ea) == 0x402000 else "",
                get_strlit_contents=lambda *_args: None,
                get_str_type=lambda _ea: 0,
                get_inf_attr=lambda _attr: 0,
                demangle_name=lambda *_args: None,
            ),
        }

        with patch.dict(sys.modules, modules):
            records = collect_globals(import_eas={0x403000})

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["address"], "0x402000")
        self.assertEqual(record["name"], "g_config")
        self.assertEqual(record["type"], "config_t")
        self.assertEqual(record["initial_value"], "0x12345678 (305419896)")
        self.assertEqual(record["reads"][0]["address"], "0x401010")
        self.assertEqual(record["writes"][0]["address"], "0x401020")
        self.assertEqual(record["referencing_functions"], ["main (0x401000)"])

    def test_writes_json_and_tsv_catalogs(self):
        records = [{
            "address": "0x402000",
            "name": "g_config",
            "segment": ".data",
            "type": "uint32_t",
            "size": 4,
            "initial_value": "0x1 (1)",
            "aliases": [],
            "reads": [{"address": "0x401010", "function": "main (0x401000)"}],
            "writes": [],
            "references": [],
            "referencing_functions": ["main (0x401000)"],
        }]

        with tempfile.TemporaryDirectory(prefix="omni_globals_") as temp_dir:
            write_globals(temp_dir, records)
            tsv = Path(temp_dir, "globals.tsv")
            catalog = Path(temp_dir, "catalog", "globals.json")

            self.assertTrue(tsv.is_file())
            self.assertTrue(catalog.is_file())
            self.assertIn("g_config", tsv.read_text(encoding="utf-8-sig"))
            self.assertEqual(json.loads(catalog.read_text(encoding="utf-8"))["globals"], records)

    def test_globals_are_included_in_workspace_analysis_context(self):
        with tempfile.TemporaryDirectory(prefix="omni_globals_context_") as temp_dir:
            workspace = Path(temp_dir)
            Path(workspace, "catalog").mkdir()
            Path(workspace, "AGENTS.md").write_text("# Workspace", encoding="utf-8")
            Path(workspace, "catalog", "globals.json").write_text(
                '{"total": 1, "globals": [{"address": "0x402000", "name": "g_config"}]}',
                encoding="utf-8",
            )

            context = build_workspace_context(workspace, maximum_chars=10000)

            self.assertIn("catalog/globals.json", context)
            self.assertIn("g_config", context)


if __name__ == "__main__":
    unittest.main()
