"""Unit tests for Remora's Qt-free parsing and MITRE-mapping logic.

These tests deliberately avoid a real PyQt6/volatility3 install: a minimal stub
for the PyQt6 modules is registered in ``sys.modules`` *before* importing
``remora`` so the pure, GUI-independent functions can be exercised anywhere
(developer laptop or CI) with only the standard library.

Run with either::

    python3 -m unittest discover -s tests
    python3 -m pytest tests/          # if pytest is available
"""

import json
import os
import sys
import types
import unittest
from pathlib import Path

# --------------------------------------------------------------------------- #
# Install a permissive PyQt6 stub so ``import remora`` succeeds without Qt.
# --------------------------------------------------------------------------- #


class _Dummy:
    """Stands in for any Qt class/callable: subclassable and permissive."""

    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        return _Dummy()

    def __getattr__(self, name):
        return _Dummy()


class _StubModule(types.ModuleType):
    def __getattr__(self, name):
        return _Dummy


for _mod in ("PyQt6", "PyQt6.QtCore", "PyQt6.QtGui", "PyQt6.QtWidgets"):
    _stub = _StubModule(_mod)
    # An (empty) __path__ makes PyQt6 a package, so importing an *unregistered*
    # submodule (e.g. QtPrintSupport) fails cleanly with ModuleNotFoundError,
    # which remora catches to set HAS_PRINT = False.
    _stub.__path__ = []
    sys.modules.setdefault(_mod, _stub)

# Make the repository root importable, then import the module under test.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

import remora  # noqa: E402


class ParseVolOutputTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(remora.parse_vol_output(""), ([], []))
        self.assertEqual(remora.parse_vol_output("   \n  "), ([], []))
        self.assertEqual(remora.parse_vol_output(None), ([], []))

    def test_single_json_array_of_dicts(self):
        raw = json.dumps([
            {"PID": 4, "Name": "System"},
            {"PID": 88, "Name": "smss.exe"},
        ])
        cols, rows = remora.parse_vol_output(raw)
        self.assertEqual(cols, ["PID", "Name"])
        self.assertEqual(rows, [["4", "System"], ["88", "smss.exe"]])

    def test_jsonl_records(self):
        raw = "\n".join([
            json.dumps({"PID": 4, "Name": "System"}),
            json.dumps({"PID": 88, "Name": "smss.exe"}),
        ])
        cols, rows = remora.parse_vol_output(raw)
        self.assertEqual(cols, ["PID", "Name"])
        self.assertEqual(rows, [["4", "System"], ["88", "smss.exe"]])

    def test_plain_text_fallback(self):
        raw = "just some\nplain text lines"
        cols, rows = remora.parse_vol_output(raw)
        self.assertEqual(cols, ["Output"])
        self.assertEqual(rows, [["just some"], ["plain text lines"]])

    def test_nested_children_are_flattened_and_indented(self):
        raw = json.dumps([
            {"PID": 4, "Name": "System", "__children": [
                {"PID": 88, "Name": "smss.exe", "__children": [
                    {"PID": 120, "Name": "csrss.exe", "__children": []},
                ]},
            ]},
        ])
        cols, rows = remora.parse_vol_output(raw)
        self.assertEqual(cols, ["PID", "Name"])
        # First column of nested rows is indented by two spaces per depth level,
        # preserving the process tree visually after flattening.
        self.assertEqual(rows, [
            ["4", "System"],
            ["  88", "smss.exe"],
            ["    120", "csrss.exe"],
        ])
        # The __children key must never leak into the column set.
        self.assertNotIn("__children", cols)


class JsonToTableTests(unittest.TestCase):
    def test_list_of_lists(self):
        data = [["A", "B"], [1, 2], [3, 4]]
        cols, rows = remora.json_to_table(data)
        self.assertEqual(cols, ["A", "B"])
        self.assertEqual(rows, [["1", "2"], ["3", "4"]])

    def test_columns_rows_dict(self):
        data = {"columns": ["X", "Y"], "rows": [[1, 2]]}
        cols, rows = remora.json_to_table(data)
        self.assertEqual(cols, ["X", "Y"])
        self.assertEqual(rows, [["1", "2"]])

    def test_scalar_fallback(self):
        cols, rows = remora.json_to_table("hello")
        self.assertEqual(cols, ["Result"])
        self.assertEqual(rows, [["hello"]])


class FlattenRecordsTests(unittest.TestCase):
    def test_indentation_depth(self):
        rows: list = []
        remora.flatten_records(
            [{"c": "root", "__children": [{"c": "child", "__children": []}]}],
            ["c"], rows)
        self.assertEqual(rows, [["root"], ["  child"]])

    def test_none_values_become_empty_string(self):
        rows: list = []
        remora.flatten_records([{"c": None}], ["c"], rows)
        self.assertEqual(rows, [[""]])


class MitreLookupTests(unittest.TestCase):
    def test_known_plugin_maps_to_techniques(self):
        techs = remora._get_plugin_techniques("windows.malfind")
        self.assertIn("T1055", techs)

    def test_multi_segment_plugin_name(self):
        techs = remora._get_plugin_techniques("windows.registry.hashdump")
        self.assertIn("T1003.002", techs)

    def test_unknown_plugin_returns_empty(self):
        self.assertEqual(remora._get_plugin_techniques("windows.totallyfake"), [])

    def test_confidence_defaults_to_medium(self):
        self.assertEqual(remora._get_confidence("malfind", "T1055"), "H")
        self.assertEqual(remora._get_confidence("nope", "T9999"), "M")


class TriageProfileMatchTests(unittest.TestCase):
    def test_matches_full_name_with_class_segment(self):
        # Volatility reports names like "windows.pslist.PsList"
        self.assertTrue(
            remora.plugin_in_profile("windows.pslist.PsList", ["windows.pslist"]))

    def test_matches_exact_name(self):
        self.assertTrue(
            remora.plugin_in_profile("windows.pslist", ["windows.pslist"]))

    def test_matches_multi_segment_entry(self):
        self.assertTrue(remora.plugin_in_profile(
            "windows.registry.hashdump.Hashdump", ["windows.registry.hashdump"]))

    def test_prefix_guard_rejects_partial_segment(self):
        # "windows.pslist" must NOT match "windows.pslister"
        self.assertFalse(
            remora.plugin_in_profile("windows.pslister.PsLister", ["windows.pslist"]))

    def test_no_match_for_other_os(self):
        self.assertFalse(
            remora.plugin_in_profile("linux.pslist.PsList", ["windows.pslist"]))

    def test_builtin_profiles_resolve_against_class_named_plugins(self):
        # Simulate discovered Windows plugins (with class suffix) and ensure the
        # Quick Triage profile checks a sensible number of them.
        discovered = [
            "windows.pslist.PsList", "windows.pstree.PsTree",
            "windows.psscan.PsScan", "windows.cmdline.CmdLine",
            "windows.netscan.NetScan", "windows.malfind.Malfind",
            "windows.registry.hashdump.Hashdump", "windows.info.Info",
        ]
        entries = remora.TRIAGE_PROFILES["Windows · Quick Triage"]
        hits = [p for p in discovered if remora.plugin_in_profile(p, entries)]
        # Everything but windows.info should match
        self.assertIn("windows.pslist.PsList", hits)
        self.assertIn("windows.registry.hashdump.Hashdump", hits)
        self.assertNotIn("windows.info.Info", hits)


class MitreOverrideTests(unittest.TestCase):
    def test_override_file_merges(self):
        import tempfile

        original_dir = remora.SCRIPT_DIR
        original_name = remora.MITRE_TECHNIQUES.get("T9999")
        with tempfile.TemporaryDirectory() as d:
            payload = {
                "techniques": {"T9999": "Test Technique"},
                "plugin_map": {"faketool": ["T9999"]},
            }
            with open(os.path.join(d, "remora_mitre.json"), "w") as fh:
                json.dump(payload, fh)
            remora.SCRIPT_DIR = Path(d)
            try:
                status = remora._load_mitre_overrides()
                self.assertIsNotNone(status)
                self.assertEqual(remora.MITRE_TECHNIQUES.get("T9999"),
                                 "Test Technique")
                self.assertIn("T9999",
                              remora._get_plugin_techniques("faketool"))
            finally:
                remora.SCRIPT_DIR = original_dir
                # Roll back the mutation so test order can't matter.
                if original_name is None:
                    remora.MITRE_TECHNIQUES.pop("T9999", None)
                    remora.PLUGIN_MITRE_MAP.pop("faketool", None)

    def test_missing_file_returns_none(self):
        import tempfile
        original_dir = remora.SCRIPT_DIR
        with tempfile.TemporaryDirectory() as d:
            remora.SCRIPT_DIR = Path(d)
            try:
                self.assertIsNone(remora._load_mitre_overrides())
            finally:
                remora.SCRIPT_DIR = original_dir


if __name__ == "__main__":
    unittest.main()
