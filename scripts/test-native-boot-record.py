#!/usr/bin/env python3
"""Offline image seed tests; never touches runtime /etc or a device."""
import hashlib
import importlib.util
from pathlib import Path
import os
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("boot_seed", Path(__file__).with_name("native-boot-record.py"))
seed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seed)


class FactorySeedTests(unittest.TestCase):
    def test_exact_record_and_idempotent_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "native-runtime-boot/state"
            seed.seed(output)
            expected = b"NKBOOT01" + bytes(36) + b"\x01" + bytes(3)
            self.assertEqual(output.read_bytes(), expected + hashlib.sha256(expected).digest())
            self.assertEqual(output.stat().st_mode & 0o7777, 0o600)
            self.assertEqual(output.parent.stat().st_mode & 0o7777, 0o700)
            inode = output.stat().st_ino
            seed.seed(output)
            self.assertEqual(output.stat().st_ino, inode)
            self.assertEqual(list(output.parent.iterdir()), [output])

    def test_runtime_or_corrupt_state_is_not_reset(self):
        for fault in ["armed", "ready", "corrupt", "truncated", "trailing", "mode", "hardlink", "symlink", "parent-mode"]:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "native-runtime-boot/state"
                seed.seed(output)
                if fault == "mode": output.chmod(0o644)
                elif fault == "parent-mode": output.parent.chmod(0o755)
                elif fault == "hardlink": os.link(output, output.with_name("alias"))
                elif fault == "symlink": output.unlink(); output.symlink_to("outside")
                else:
                    data = bytearray(output.read_bytes())
                    if fault in ["armed", "ready"]:
                        data[8:44] = b"12345678-1234-1234-1234-123456789abc"
                        data[44] = 2 if fault == "armed" else 3
                        data[48:] = hashlib.sha256(data[:48]).digest()
                    elif fault == "corrupt": data[-1] ^= 1
                    elif fault == "truncated": data.pop()
                    elif fault == "trailing": data.append(0)
                    output.write_bytes(data)
                before = output.lstat()
                with self.assertRaises(ValueError): seed.seed(output)
                self.assertEqual(output.lstat().st_ino, before.st_ino)

    def test_runtime_seed_is_not_part_of_app_tree_or_archive_recipe(self):
        root = Path(__file__).resolve().parent.parent
        self.assertEqual(list((root / "kvmapp").rglob("native-runtime-boot")), [])
        self.assertNotIn("native-boot-record.py", (root / "scripts/package-rust-kvmapp.sh").read_text())
        self.assertIn('"$TARGET_DIR/etc/kvm/native-runtime-boot/state"',
                      (root / "buildroot-external/hardened-sg2002/board/sg2002/post-build.sh").read_text())


if __name__ == "__main__":
    unittest.main()
