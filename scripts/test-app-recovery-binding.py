#!/usr/bin/env python3
"""Synthetic cross-domain framing/CLI checks, not target execution evidence."""

import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).with_name("app-recovery-binding.py")
SPEC = importlib.util.spec_from_file_location("app_binding", TOOL)
app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app)
binding = app.binding


def image(extra=0):
    elf = bytearray(120 + extra)
    elf[:7] = b"\x7fELF\x02\x01\x01"
    for offset, value in [(16, 2), (18, 243), (52, 64), (54, 56), (56, 1)]:
        struct.pack_into("<H", elf, offset, value)
    struct.pack_into("<I", elf, 20, 1)
    struct.pack_into("<Q", elf, 32, 64)
    struct.pack_into("<I", elf, 64, 1)
    return bytes(elf)


class AppBindingTests(unittest.TestCase):
    def run_tool(self, tool, *args, success=True):
        result = subprocess.run([sys.executable, str(tool), *map(str, args)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result.stdout.strip()

    def test_domains_coexist_without_substitution(self):
        ssh, recovery = image(), image(8)
        ssh_envelope = binding.envelope(ssh)
        app_envelope = binding.envelope(recovery, app.MAGIC)
        backend = b"prefix" + ssh_envelope + b"middle" + app_envelope + b"tail"
        self.assertEqual(binding.locate(backend)[0], ssh)
        self.assertEqual(binding.locate(backend, app.MAGIC)[0], recovery)
        for data, magic in [(ssh_envelope, app.MAGIC), (app_envelope, binding.MAGIC)]:
            with self.assertRaises(ValueError):
                binding.locate(data, magic)
        for invalid in [b"", b"other", b"XXXXXXXX"]:
            with self.assertRaises(ValueError):
                binding.envelope(ssh, invalid)
            with self.assertRaises(ValueError):
                binding.locate(backend, invalid)

    def test_app_corruption_duplicate_and_rehashed_dynamic_are_rejected(self):
        valid = binding.envelope(image(), app.MAGIC)
        dynamic = bytearray(image())
        struct.pack_into("<I", dynamic, 64, 3)
        forged = app.MAGIC + struct.pack("<Q", len(dynamic)) + hashlib.sha256(dynamic).digest() + dynamic
        for bad in [b"none", valid[:47], valid[:-1], valid[:16] + bytes(32) + valid[48:],
                    valid + valid, app.MAGIC * 65 + valid, forged]:
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                binding.locate(bad, app.MAGIC)

    def test_cli_exact_extract_no_overwrite_and_cross_domain_rejection(self):
        with tempfile.TemporaryDirectory(prefix="nanokvm-app-binding-") as work:
            work = Path(work)
            backend = work / "backend"
            recovery = image(8)
            backend.write_bytes(binding.envelope(image()) + binding.envelope(recovery, app.MAGIC))
            self.assertEqual(self.run_tool(TOOL, "inspect", "--backend", backend),
                             f"{hashlib.sha256(recovery).hexdigest()} {len(recovery)}")
            output = work / "extracted"
            self.run_tool(TOOL, "extract", "--backend", backend, "--destination", output)
            self.assertEqual(output.read_bytes(), recovery)
            self.run_tool(TOOL, "verify", "--backend", backend, "--helper", output)
            self.run_tool(TOOL, "extract", "--backend", backend, "--destination", output, success=False)
            self.assertEqual(output.read_bytes(), recovery)
            wrong = work / "wrong"
            wrong.write_bytes(image())
            self.run_tool(TOOL, "verify", "--backend", backend, "--helper", wrong, success=False)
            backend.write_bytes(binding.envelope(image()))
            self.run_tool(TOOL, "inspect", "--backend", backend, success=False)
            backend.write_bytes(binding.envelope(recovery, app.MAGIC))
            self.run_tool(TOOL.with_name("ssh-runtime-binding.py"), "inspect", "--backend", backend, success=False)

    def test_shared_cache_separates_domains_and_preserves_conflicting_file(self):
        with tempfile.TemporaryDirectory(prefix="nanokvm-app-cache-") as work:
            work = Path(work)
            helper = work / "helper"
            helper.write_bytes(image())
            args = ("prepare", "--helper", helper, "--directory", work / "bindings")
            ssh = Path(self.run_tool(TOOL.with_name("ssh-runtime-binding.py"), *args))
            recovery = Path(self.run_tool(TOOL, *args))
            self.assertNotEqual(ssh, recovery)
            self.assertEqual(recovery.read_bytes(), binding.envelope(image(), app.MAGIC))
            recovery.chmod(0o644)
            recovery.write_bytes(b"conflicting app binding")
            self.run_tool(TOOL, *args, success=False)
            self.assertEqual(recovery.read_bytes(), b"conflicting app binding")
            self.assertEqual(ssh.read_bytes(), binding.envelope(image()))

    def test_app_cli_rejects_symlink_fifo_and_directory_without_blocking(self):
        with tempfile.TemporaryDirectory(prefix="nanokvm-app-types-") as work:
            work = Path(work)
            source = work / "source"
            source.write_bytes(binding.envelope(image(), app.MAGIC))
            link, fifo = work / "link", work / "fifo"
            link.symlink_to(source)
            os.mkfifo(fifo)
            for path in [link, fifo, work]:
                self.run_tool(TOOL, "inspect", "--backend", path, success=False)


if __name__ == "__main__":
    unittest.main()
