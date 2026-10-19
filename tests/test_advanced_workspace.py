import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from omni_idb.workspace_export import _export_advanced_catalogs


class AdvancedWorkspaceTests(unittest.TestCase):
    def test_bundle_writes_every_advanced_catalog(self):
        class Progress:
            def __init__(self):
                self.steps = []

            def step(self, label, amount=1):
                self.steps.append((label, amount))

        values = {
            "collect_local_types": ("struct config_t;\n", [{"name": "config_t"}]),
            "collect_applied_types": [{"address": "0x402000", "kind": "global", "type": "config_t"}],
            "collect_xrefs": [{"source": "0x401000", "target": "0x402000", "access": "read"}],
            "collect_cfg": [{"function": "0x401000", "name": "main", "blocks": [], "edges": []}],
            "collect_entrypoints": [{"address": "0x401000", "name": "main"}],
            "collect_function_variables": [{"function": "0x401000", "name": "main", "variables": [], "decompilation_error": None}],
            "collect_data_objects": [({"address": "0x402000", "name": "g_data", "file": "data/0000000000402000.bin"}, b"abc")],
            "collect_fixups": [],
            "collect_switches": [],
            "collect_pointer_tables": [],
            "collect_analysis_gaps": {"decompilation_failures": [], "undefined_ranges": []},
            "collect_source_map": {"source_lines": [], "symbols": []},
        }
        with tempfile.TemporaryDirectory(prefix="omni_advanced_") as temp_dir:
            with ExitStack() as stack:
                for name, value in values.items():
                    stack.enter_context(patch("omni_idb.advanced_workspace_export.%s" % name, return_value=value))
                counts = {}
                progress = Progress()
                _export_advanced_catalogs(
                    temp_dir, [{"ea": 0x401000, "name": "main"}],
                    [{"address": "0x402000", "size": 3}], {}, counts, progress,
                )

            for relative in (
                "headers/local_types.h", "catalog/types.json", "xrefs.tsv", "catalog/xrefs.json",
                "catalog/cfg.json", "catalog/entrypoints.json", "catalog/function_variables.json",
                "catalog/data_objects.json", "catalog/fixups.json", "catalog/switches.json",
                "catalog/pointer_tables.json", "catalog/analysis_gaps.json", "catalog/source_map.json",
                "data/0000000000402000.bin",
            ):
                self.assertTrue(Path(temp_dir, *relative.split("/")).is_file(), relative)
            self.assertEqual(counts["types"], 1)
            self.assertEqual(counts["xrefs"], 1)
            self.assertEqual(counts["data_object_bytes"], 3)
            self.assertEqual(len(progress.steps), 11)


if __name__ == "__main__":
    unittest.main()
