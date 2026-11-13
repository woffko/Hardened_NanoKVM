#!/usr/bin/env python3
"""Disposable offline factory seed fixtures, no device or runtime mutation."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("pico_seed", Path(__file__).with_name("picoclaw-enrollment-record.py"))
seed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seed)


class PicoFactorySeedTests(unittest.TestCase):
    def test_deterministic_factory_input_and_idempotent_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "etc/kvm/picoclaw-enrollment"
            seed.seed(output)
            prefix = b"NKPENR01" + bytes([1]) + bytes(55)
            self.assertEqual(output.read_bytes(), prefix + hashlib.sha256(b"NanoKVM Pico enrollment v1\0" + prefix).digest())
            before = output.stat()
            self.assertEqual(before.st_mode & 0o7777, 0o600)
            seed.seed(output)
            self.assertEqual(output.stat().st_ino, before.st_ino)
            self.assertEqual(list(output.parent.iterdir()), [output])

    def test_enrolled_or_unsafe_seed_is_not_reset(self):
        for fault in ["pending", "ready", "reserved", "corrupt", "truncated", "trailing", "mode", "hardlink", "symlink", "fifo", "parent"]:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "picoclaw-enrollment"
                seed.seed(output)
                if fault == "mode": output.chmod(0o644)
                elif fault == "parent": output.parent.chmod(0o777)
                elif fault == "hardlink": os.link(output, output.with_name("alias"))
                elif fault == "symlink": output.unlink(); output.symlink_to("absent")
                elif fault == "fifo": output.unlink(); os.mkfifo(output, 0o600)
                else:
                    data = bytearray(output.read_bytes())
                    if fault in ["pending", "ready"]:
                        data[8] = 2 if fault == "pending" else 3
                        data[16:32] = bytes([7]) * 16
                        data[64:] = hashlib.sha256(b"NanoKVM Pico enrollment v1\0" + data[:64]).digest()
                    elif fault == "reserved": data[32] = 1
                    elif fault == "corrupt": data[-1] ^= 1
                    elif fault == "truncated": data.pop()
                    elif fault == "trailing": data.append(0)
                    output.write_bytes(data)
                before = output.lstat()
                with self.assertRaises(ValueError): seed.seed(output)
                self.assertEqual(output.lstat().st_ino, before.st_ino)

    def test_no_factory_seed_beside_existing_store(self):
        for existing_seed in [False, True]:
            with self.subTest(existing_seed=existing_seed), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "picoclaw-enrollment"
                if existing_seed: seed.seed(output)
                (output.parent / "picoclaw-operations").mkdir()
                with self.assertRaises(ValueError): seed.seed(output)
                self.assertEqual(output.exists(), existing_seed)

    def test_seed_is_full_image_input_not_app_archive_data(self):
        root = Path(__file__).resolve().parent.parent
        self.assertEqual(list((root / "kvmapp").rglob("picoclaw-enrollment")), [])
        self.assertNotIn("picoclaw-enrollment-record.py", (root / "scripts/package-rust-kvmapp.sh").read_text())
        self.assertIn('"$TARGET_DIR/etc/kvm/picoclaw-enrollment"', (root / "buildroot-external/hardened-sg2002/board/sg2002/post-build.sh").read_text())
        self.assertIn("picoclaw-enrollment", (root / "scripts/build-rust-sd-image.sh").read_text())


if __name__ == "__main__":
    unittest.main()
