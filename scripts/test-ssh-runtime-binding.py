#!/usr/bin/env python3
"""Host synthetic framing/packaging tests, not RV64 execution acceptance."""

import hashlib
import importlib.util
import mmap
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).with_name("ssh-runtime-binding.py")
SPEC = importlib.util.spec_from_file_location("binding", TOOL)
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)


def image():
    elf = bytearray(120)
    elf[:7] = b"\x7fELF\x02\x01\x01"
    for offset, value in [(16, 2), (18, 243), (52, 64), (54, 56), (56, 1)]:
        struct.pack_into("<H", elf, offset, value)
    struct.pack_into("<I", elf, 20, 1)
    struct.pack_into("<Q", elf, 32, 64)
    struct.pack_into("<I", elf, 64, 1)
    return bytes(elf)


def unchecked_envelope(elf):
    return binding.MAGIC + struct.pack("<Q", len(elf)) + hashlib.sha256(elf).digest() + elf


class BindingTests(unittest.TestCase):
    def test_exact_envelope_and_unrelated_marker(self):
        elf = image()
        data = binding.envelope(elf)
        self.assertEqual(binding.locate(b"prefix NKSSHRT1 ignored\0" + data + b"tail"),
                         (elf, hashlib.sha256(elf).digest()))

    def test_missing_truncated_corrupt_ambiguous(self):
        data = binding.envelope(image())
        for bad in [b"none", data[:47], data[:-1], data[:16] + bytes(32) + data[48:],
                    data + data, binding.MAGIC * 65 + data]:
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                binding.locate(bad)

    def test_bounded_size(self):
        data = bytearray(binding.envelope(image()))
        for size in [0, 63, binding.MAX_HELPER + 1, 2**64 - 1]:
            struct.pack_into("<Q", data, 8, size)
            with self.subTest(size=size), self.assertRaises(ValueError):
                binding.locate(data)

    def test_rehashed_dynamic_foreign_and_bad_table_rejected(self):
        for offset, value in [(4, 1), (5, 2), (16, 3), (18, 62), (52, 63), (54, 55), (56, 0), (64, 2), (64, 3), (64, 0)]:
            elf = bytearray(image())
            elf[offset] = value
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                binding.locate(unchecked_envelope(elf))
        elf = bytearray(image())
        struct.pack_into("<Q", elf, 32, 2**64 - 1)
        with self.assertRaises(ValueError):
            binding.envelope(elf)

    def test_prepare_inspect_extract_and_no_overwrite(self):
        with tempfile.TemporaryDirectory(prefix="nanokvm-binding-") as work:
            work = Path(work)
            helper = work / "helper"
            helper.write_bytes(image())
            def run(*args, success=True):
                result = subprocess.run([sys.executable, str(TOOL), *map(str, args)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                return result.stdout.strip()
            args = ("prepare", "--helper", helper, "--directory", work / "bindings")
            path = Path(run(*args))
            self.assertEqual(run(*args), str(path))
            self.assertEqual(path.read_bytes(), binding.envelope(image()))
            # Respect the runner's stricter umask (Longrun uses 0077): require
            # owner-read and no write/execute bits, not world readability.
            self.assertEqual(path.stat().st_mode & 0o733, 0o400)
            backend = work / "backend"
            backend.write_bytes(b"synthetic prefix" + path.read_bytes() + b"tail")
            self.assertEqual(run("inspect", "--backend", backend),
                             f"{hashlib.sha256(image()).hexdigest()} 120")
            self.assertEqual(run("inspect", "--backend", backend, "--quiet"), "")
            output = work / "extracted"
            run("extract", "--backend", backend, "--destination", output)
            self.assertEqual(output.read_bytes(), image())
            run("extract", "--backend", backend, "--destination", output, success=False)
            self.assertEqual(output.read_bytes(), image())
            path.chmod(0o644)
            path.write_bytes(b"corrupt existing binding")
            run(*args, success=False)
            self.assertEqual(path.read_bytes(), b"corrupt existing binding")

    def test_load_ranges_and_alignment(self):
        for changes in [[(72, 2**64 - 1)], [(96, 121)], [(96, 1)], [(112, 3)],
                        [(80, 1), (112, 4096)], [(80, 2**64 - 1), (104, 1)]]:
            elf = bytearray(image())
            for offset, value in changes:
                struct.pack_into("<Q", elf, offset, value)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                binding.locate(unchecked_envelope(elf))

    def test_nonregular_symlink_and_oversized_inputs(self):
        with tempfile.TemporaryDirectory(prefix="nanokvm-binding-input-") as work:
            work = Path(work)
            source = work / "source"
            source.write_bytes(image())
            link = work / "link"
            link.symlink_to(source)
            fifo = work / "fifo"
            os.mkfifo(fifo)
            for path in [link, fifo, work]:
                with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                    binding.regular(path, binding.MAX_HELPER)
            with source.open("wb") as output:
                output.truncate(binding.MAX_HELPER + 1)
            with self.assertRaises(ValueError):
                binding.regular(source, binding.MAX_HELPER)

    def test_mmap_host_scanner(self):
        with tempfile.TemporaryFile() as source:
            source.write(binding.envelope(image()))
            source.flush()
            with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as view:
                self.assertEqual(binding.locate(view)[0], image())

    def test_post_build_gate_checks_final_copied_backend(self):
        script = TOOL.parent.parent / "buildroot-external/hardened-sg2002/board/sg2002/post-build.sh"
        for fault in [None, "missing-binding", "backup-differs", "unsafe-runpath",
                      "missing-app-binding", "app-helper-mismatch", "app-helper-missing",
                      *(role + "-" + failure for role in binding.NATIVE_MAGICS
                        for failure in ["missing-binding", "helper-mismatch", "helper-missing"])]:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="nanokvm-post-build-") as directory:
                work = Path(directory)
                source, target, host = work / "source", work / "target", work / "host"
                for base in [source, target / "kvmapp"]:
                    for child in ["server", "backends", "hwmon", "system/bin"]:
                        (base / child).mkdir(parents=True)
                (host / "bin").mkdir(parents=True)
                (host / "bin/python3").symlink_to(sys.executable)
                patchelf = host / "bin/patchelf"
                runpath = "/tmp/unsafe" if fault == "unsafe-runpath" else "/kvmapp/server/dl_lib"
                patchelf.write_text(f"#!/bin/sh\nprintf '%s\\n' '{runpath}'\n")
                patchelf.chmod(0o755)
                # Stub patchelf controls only this shell-gate fixture; no ABI,
                # provenance, Buildroot pipeline or target execution claim.
                backend = b"synthetic backend" + (b"" if fault == "missing-binding" else binding.envelope(image()))
                if fault != "missing-app-binding":
                    backend += binding.envelope(image(), binding.APP_RECOVERY_MAGIC)
                native_images = {role: image() + role.encode() for role in binding.NATIVE_MAGICS}
                for role, magic in binding.NATIVE_MAGICS.items():
                    if fault != role + "-missing-binding":
                        backend += binding.envelope(native_images[role], magic)
                    if fault != role + "-helper-missing":
                        (source / ("system/bin/nanokvm-native-" + role)).write_bytes(
                            native_images[role] + (b"differs" if fault == role + "-helper-mismatch" else b""))
                (source / "server/NanoKVM-Server").write_bytes(backend)
                (source / "backends/NanoKVM-Server.rust").write_bytes(
                    backend + (b"differs" if fault == "backup-differs" else b""))
                (source / "hwmon/nanokvm-hwmon").write_bytes(b"synthetic hwmon")
                if fault != "app-helper-missing":
                    (source / "system/bin/nanokvm-app-recovery").write_bytes(
                        image() + (b"differs" if fault == "app-helper-mismatch" else b""))
                env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOST_DIR": str(host),
                       "NANOKVM_KVMAPP_SOURCE_DIR": str(source)}
                result = subprocess.run([str(script), str(target)], env=env, capture_output=True,
                                        text=True, timeout=10)
                self.assertEqual(result.returncode == 0, fault is None, result.stderr)
                if fault is None:
                    self.assertEqual((target / "kvmapp/server/NanoKVM-Server").read_bytes(), backend)
                    self.assertEqual((target / "kvmapp/backends/NanoKVM-Server.rust").read_bytes(), backend)
                    self.assertEqual((target / "kvmapp/system/bin/nanokvm-app-recovery").read_bytes(), image())
                    self.assertEqual((target / "usr/libexec/nanokvm-app-recovery").read_bytes(), image())
                    for role, expected in native_images.items():
                        for parent in ["kvmapp/system/bin", "usr/libexec"]:
                            helper = target / parent / ("nanokvm-native-" + role)
                            self.assertEqual(helper.read_bytes(), expected)
                            self.assertEqual(helper.stat().st_mode & 0o7777, 0o755)


if __name__ == "__main__":
    unittest.main()
