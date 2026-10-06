# -*- coding: utf-8 -*-
"""Тесты локального счётчика полки: только временные файлы, без сети/запусков."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from io import StringIO

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_shelf", ROOT / "bin" / "check_shelf.py")
check_shelf = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(check_shelf)


class TestShelfMeasure(unittest.TestCase):
    def test_counts_regular_files_and_deduplicates_overlapping_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.bin").write_bytes(b"abc")
            child = root / "nested"
            child.mkdir()
            (child / "b.bin").write_bytes(b"12345")

            measured = check_shelf.measure_roots([("all", root), ("nested", child)])

        self.assertEqual(measured["total_bytes"], 8)
        self.assertEqual(measured["file_count"], 2)
        self.assertEqual(measured["roots"][1]["bytes"], 0)

    def test_file_path_root_is_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "one.dat"
            file_path.write_bytes(b"1234")
            measured = check_shelf.measure_roots([("file", file_path)])
        self.assertEqual(measured["total_bytes"], 4)
        self.assertEqual(measured["file_count"], 1)

    def test_hardlink_is_counted_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a, b = root / "a", root / "b"
            a.write_bytes(b"shared")
            try:
                os.link(a, b)
            except (OSError, NotImplementedError):
                self.skipTest("hardlink unavailable on this filesystem")
            measured = check_shelf.measure_roots([("root", root)])
        self.assertEqual(measured["total_bytes"], 6)
        self.assertEqual(measured["file_count"], 1)

    def test_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_bytes(b"safe")
            link = root / "link"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink unavailable on this filesystem")
            measured = check_shelf.measure_roots([("root", root)])
        self.assertEqual(measured["total_bytes"], 4)
        self.assertEqual(measured["file_count"], 1)

    def test_missing_path_is_reported_not_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "absent"
            measured = check_shelf.measure_roots([("missing", missing)])
        self.assertEqual(measured["total_bytes"], 0)
        self.assertFalse(measured["roots"][0]["exists"])


class TestShelfPolicy(unittest.TestCase):
    def test_manifest_sets_225_decimal_gb_and_excludes_weakpass(self):
        data = check_shelf.load_manifest()
        self.assertEqual(data["capacity"]["limit_bytes"], 225_000_000_000)
        self.assertTrue(data["capacity"]["exclude_weakpass_2a"])
        excluded = {item["id"] for item in data["explicit_exclusions"]}
        self.assertIn("weakpass_2a", excluded)

    def test_projectdiscovery_catalog_has_full_scope_not_just_current_seven(self):
        data = check_shelf.load_manifest()
        group = next(g for g in data["groups"] if g["id"] == "projectdiscovery_catalog")
        self.assertEqual(group["unique_cli_projects_in_catalog_union"], 23)
        additional_cli = [item for item in group["additional_shelf_items"]
                          if item.get("kind") != "data"]
        self.assertEqual(len(group["already_in_asm_core"]) + len(additional_cli), 23)
        self.assertIn("vulnx", {item["id"] for item in group["additional_shelf_items"]})
        self.assertFalse(group["agent_connected"])

    def test_candidate_inventory_keeps_netexec_single_copy_and_gates_candidates(self):
        data = check_shelf.load_manifest()
        internal = next(g for g in data["groups"] if g["id"] == "internal_ad_linux_arsenal")
        research = next(g for g in data["groups"] if g["id"] == "research_candidates")
        internal_ids = {item["id"] for item in internal["items"]}
        candidate_ids = {item["id"] for item in research["items"]}
        self.assertIn("NetExec", internal_ids)
        self.assertIn("NetExec", candidate_ids)
        self.assertFalse(research["agent_connected"])
        self.assertTrue({"AD-Miner", "ADACLScanner", "Certipy", "AzureHound",
                         "Entra App Exposure", "Maester", "Prowler",
                         "ZAP Client Side Integration", "Greenbone CE",
                         "Monkey365", "Steampipe", "Powerpipe", "Cartography",
                         "ScubaGear", "CloudSplaining", "CloudFox", "BBOT",
                         "Checkov"}.issubset(candidate_ids))

    def test_over_budget_returns_nonzero_without_running_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.json"
            manifest.write_text(json.dumps({"capacity": {"limit_bytes": 1},
                                            "storage_roots": []}), encoding="utf-8")
            original = check_shelf.MANIFEST
            check_shelf.MANIFEST = manifest
            try:
                with redirect_stdout(StringIO()):
                    result = check_shelf.main([])
            finally:
                check_shelf.MANIFEST = original
        self.assertEqual(result, 2)


if __name__ == "__main__":
    unittest.main()
