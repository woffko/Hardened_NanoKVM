#!/usr/bin/env python3
"""Synthetic source inventory negatives; no device/process/service operations."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

# Loading the checker must not leave generated files in the source tree.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("writer_inventory", ROOT / "scripts/validate-state-writer-inventory.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / "server-rust/src/update/restore_policy.rs").read_text()
        self.policy = CHECK.policy_members(self.source)
        self.inventory = json.loads((ROOT / "docs/security-state-writers.json").read_text())

    def reject(self, change):
        value = copy.deepcopy(self.inventory)
        change(value)
        with self.assertRaises((ValueError, TypeError, KeyError)):
            CHECK.validate(value, self.policy, ROOT)

    def test_current_closed_schema_is_fully_classified(self):
        self.assertEqual(CHECK.validate(self.inventory, self.policy, ROOT),
                         sum(map(len, self.policy.values())))

    def test_missing_assignment_rejects(self):
        self.reject(lambda value: value["groups"][0]["members"]["REQUIRED"].pop())

    def test_new_schema_path_requires_assignment(self):
        self.policy["FIXED"].add("etc/kvm/new-reviewed-setting")
        with self.assertRaises(ValueError):
            CHECK.validate(self.inventory, self.policy, ROOT)

    def test_duplicate_assignment_rejects(self):
        self.reject(lambda value: value["groups"].append(copy.deepcopy(value["groups"][0])))
        def duplicate_with_distinct_id(value):
            row = copy.deepcopy(value["groups"][0])
            row["id"] = "duplicate-path-fixture"
            value["groups"].append(row)
        self.reject(duplicate_with_distinct_id)

    def test_wrong_kind_or_unknown_path_rejects(self):
        self.reject(lambda value: value["groups"][0]["members"]["REQUIRED"].append("etc/gshadow"))
        self.reject(lambda value: value["groups"][0]["members"]["REQUIRED"].append("etc/kvm/unknown"))

    def test_empty_writer_and_missing_evidence_reject(self):
        self.reject(lambda value: value["groups"][0].update(writers=[]))
        self.reject(lambda value: value["groups"][0].update(evidence=["missing-source-fixture"]))
        self.reject(lambda value: value["groups"][0].update(evidence=["../outside-source-fixture"]))

    def test_static_inventory_is_never_runtime_authority(self):
        self.reject(lambda value: value.update(runtime_authority=True))
        self.reject(lambda value: value["groups"][0].update(status="quiesced"))

    def test_missing_unknown_empty_or_unparsed_policy_fails_closed(self):
        empty = re.sub(r"(pub\(super\) const REQUIRED: &\[&str\] = &\[).*?(\];)",
                       r"\1\2", self.source, count=1, flags=re.S)
        for source in ["", empty, self.source.replace("REQUIRED", "UNKNOWN"),
                       self.source.replace('"etc/passwd"', '"../etc/passwd"'),
                       self.source.replace('    "etc/passwd",', '    include!("fixture"),'),
                       self.source.replace('    "etc/passwd",', '    "etc/passwd", "extra",')]:
            with self.assertRaises(ValueError):
                CHECK.policy_members(source)

    def test_duplicate_json_keys_and_schema_extensions_reject(self):
        with self.assertRaises(ValueError):
            json.loads('{"schema":1,"schema":1}', object_pairs_hook=CHECK.unique_object)
        self.reject(lambda value: value.update(acceptance=True))

    def test_cli_is_bounded_and_does_not_print_a_missing_root_path(self):
        with tempfile.TemporaryDirectory() as empty:
            result = subprocess.run([sys.executable, str(ROOT / "scripts/validate-state-writer-inventory.py"),
                                     "--root", empty], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(empty, result.stderr)
            self.assertIn("FAIL", result.stderr)


if __name__ == "__main__":
    unittest.main()
