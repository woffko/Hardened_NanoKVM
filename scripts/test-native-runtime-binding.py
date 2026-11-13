#!/usr/bin/env python3
"""Host framing and CLI tests, never native target execution or provenance."""

import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "ssh_tests", Path(__file__).with_name("test-ssh-runtime-binding.py"))
ssh_tests = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ssh_tests)
binding = ssh_tests.binding
TOOL = Path(__file__).with_name("native-runtime-binding.py")


class NativeBindingTests(unittest.TestCase):
    def test_all_six_domains_are_disjoint(self):
        for role, magic in binding.NATIVE_MAGICS.items():
            elf = ssh_tests.image() + role.encode()
            data = binding.envelope(elf, magic)
            self.assertEqual(binding.locate(data, magic)[0], elf)
            for other in binding.DOMAINS:
                if other != magic:
                    with self.subTest(role=role, other=other), self.assertRaises(ValueError):
                        binding.locate(data, other)

    def test_every_native_role_rejects_missing_corrupt_truncated_and_duplicate_frames(self):
        for role, magic in binding.NATIVE_MAGICS.items():
            data = binding.envelope(ssh_tests.image(), magic)
            for bad in [b"none", data[:47], data[:-1], data[:16] + bytes(32) + data[48:],
                        data + data, magic * 65 + data]:
                with self.subTest(role=role, length=len(bad)), self.assertRaises(ValueError):
                    binding.locate(bad, magic)

    def test_native_budget_does_not_change_historical_domains(self):
        for size in [binding.MAX_NATIVE_HELPER, binding.MAX_NATIVE_HELPER + 1]:
            elf = ssh_tests.image() + bytes(size - 120)
            binding.envelope(elf)
            binding.envelope(elf, binding.APP_RECOVERY_MAGIC)
            for magic in binding.NATIVE_MAGICS.values():
                if size == binding.MAX_NATIVE_HELPER:
                    self.assertEqual(binding.locate(binding.envelope(elf, magic), magic)[0], elf)
                else:
                    with self.assertRaises(ValueError):
                        binding.envelope(elf, magic)
                    unchecked = magic + struct.pack("<Q", size) + hashlib.sha256(elf).digest() + elf
                    with self.assertRaises(ValueError):
                        binding.locate(unchecked, magic)

    def test_rehashed_dynamic_and_foreign_images_are_not_authorized(self):
        for magic in binding.NATIVE_MAGICS.values():
            for offset, value in [(4, 1), (18, 62), (64, 2), (64, 3)]:
                elf = bytearray(ssh_tests.image())
                elf[offset] = value
                data = magic + struct.pack("<Q", len(elf)) + hashlib.sha256(elf).digest() + elf
                with self.subTest(magic=magic, offset=offset), self.assertRaises(ValueError):
                    binding.locate(data, magic)

    def test_cli_prepare_extract_verify_and_fixed_role(self):
        with tempfile.TemporaryDirectory(prefix="nanokvm-native-binding-") as temporary:
            work = Path(temporary)
            def run(*args, success=True):
                result = subprocess.run([sys.executable, "-B", str(TOOL), *map(str, args)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                return result.stdout.strip()
            for bad in [[], ["/tmp/owner"], ["arbitrary"], ["--magic", "NKNOWNR1"]]:
                run(*bad, success=False)
            frames = []
            images = {}
            for role, magic in binding.NATIVE_MAGICS.items():
                images[role] = ssh_tests.image() + role.encode()
                helper = work / (role + ".elf")
                helper.write_bytes(images[role])
                args = (role, "prepare", "--helper", helper, "--directory", work / "frames")
                path = Path(run(*args))
                self.assertEqual(run(*args), str(path))
                self.assertTrue(path.name.startswith("native-" + role + "-"))
                self.assertEqual(path.read_bytes(), binding.envelope(images[role], magic))
                self.assertEqual(path.stat().st_mode & 0o733, 0o400)
                frames.append(path.read_bytes())
            backend = work / "backend"
            backend.write_bytes(b"synthetic backend" + b"".join(frames))
            for role in binding.NATIVE_MAGICS:
                expected = images[role]
                digest = hashlib.sha256(expected).hexdigest()
                self.assertEqual(run(role, "inspect", "--backend", backend), f"{digest} {len(expected)}")
                destination = work / (role + ".extracted")
                run(role, "extract", "--backend", backend, "--destination", destination)
                self.assertEqual(destination.read_bytes(), expected)
                run(role, "verify", "--backend", backend, "--helper", destination)
                run(role, "extract", "--backend", backend, "--destination", destination, success=False)
                wrong = work / "wrong"
                wrong.write_bytes(expected + b"wrong")
                run(role, "verify", "--backend", backend, "--helper", wrong, success=False)

    def test_cli_inputs_are_bounded_regular_nonsymlinks(self):
        with tempfile.TemporaryDirectory(prefix="nanokvm-native-input-") as temporary:
            work = Path(temporary)
            valid = work / "valid"
            valid.write_bytes(ssh_tests.image())
            link = work / "symlink"
            link.symlink_to(valid)
            fifo = work / "fifo"
            os.mkfifo(fifo)
            oversized = work / "oversized"
            with oversized.open("wb") as output:
                output.truncate(binding.MAX_NATIVE_HELPER + 1)
            for role in binding.NATIVE_MAGICS:
                for source in [work, link, fifo, oversized, work / "missing"]:
                    result = subprocess.run([sys.executable, "-B", str(TOOL), role, "prepare",
                                             "--helper", str(source), "--directory", str(work / "frames")],
                                            capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0, (role, source))


if __name__ == "__main__":
    unittest.main()
