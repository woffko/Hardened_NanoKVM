#!/usr/bin/env python3
"""Disposable real ext4 fixtures; no mounts, loops, devices or target execution."""

import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).with_name("verify-app-recovery-rootfs.py")


def static_image():
    image = bytearray(120)
    image[:7] = b"\x7fELF\x02\x01\x01"
    for offset, value in [(16, 2), (18, 243), (52, 64), (54, 56), (56, 1)]:
        struct.pack_into("<H", image, offset, value)
    struct.pack_into("<I", image, 20, 1)
    struct.pack_into("<Q", image, 32, 64)
    struct.pack_into("<I", image, 64, 1)
    return bytes(image)


class RootfsRecoveryTests(unittest.TestCase):
    @staticmethod
    def fixture(directory, fault, helper=None, actual_backend=None):
        root = directory / "tree"
        independent = root / "usr/libexec/nanokvm-app-recovery"
        bundled = root / "kvmapp/system/bin/nanokvm-app-recovery"
        backend = root / "kvmapp/server/NanoKVM-Server"
        for path in [independent, bundled, backend]:
            path.parent.mkdir(parents=True, exist_ok=True)
        if helper is None:
            helper = static_image()
        frame = b"NKAPPBT1" + struct.pack("<Q", len(helper)) + hashlib.sha256(helper).digest() + helper
        backend.write_bytes(actual_backend if actual_backend is not None else
                            b"synthetic backend" + (b"" if fault == "missing-binding" else frame))
        independent.write_bytes(helper)
        independent.chmod(0o755)
        bundled.write_bytes(helper)
        if fault == "missing-independent":
            independent.unlink()
        elif fault in ["independent-bytes", "bundled-bytes"]:
            corrupt = bytearray(helper)
            corrupt[-1] ^= 1
            (independent if fault == "independent-bytes" else bundled).write_bytes(corrupt)
        elif fault == "independent-symlink":
            independent.unlink()
            independent.symlink_to("../../kvmapp/system/bin/nanokvm-app-recovery")
        elif fault == "independent-hardlink":
            os.link(independent, independent.with_name("alias"))
        elif fault == "independent-mode":
            independent.chmod(0o777)
        elif fault == "parent-mode":
            independent.parent.chmod(0o777)
        image = directory / "rootfs.ext4"
        with image.open("wb") as output:
            payload_bytes = backend.stat().st_size + 2 * len(helper)
            output.truncate(max(16 * 1024 * 1024, 2 * payload_bytes + 8 * 1024 * 1024))
        subprocess.run(["mkfs.ext4", "-F", "-q", "-d", str(root), str(image)],
                       check=True, capture_output=True, timeout=30)
        for path in ["/", "/usr", "/usr/libexec", "/usr/libexec/nanokvm-app-recovery"]:
            for field in ["uid", "gid"]:
                subprocess.run(["debugfs", "-w", "-R", f"sif {path} {field} 0", str(image)],
                               check=True, capture_output=True, timeout=10)
        if fault == "independent-owner":
            subprocess.run(["debugfs", "-w", "-R", "sif /usr/libexec/nanokvm-app-recovery uid 1", str(image)],
                           check=True, capture_output=True, timeout=10)
        elif fault == "oversized-independent":
            subprocess.run(["debugfs", "-w", "-R", "sif /usr/libexec/nanokvm-app-recovery size 33554433", str(image)],
                           check=True, capture_output=True, timeout=10)
        return image

    def test_actual_ext4_accepts_only_exact_protected_independent_payload(self):
        faults = [None, "missing-independent", "independent-bytes", "bundled-bytes",
                  "missing-binding", "independent-symlink", "independent-hardlink",
                  "independent-mode", "independent-owner", "parent-mode", "oversized-independent"]
        for fault in faults:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="nanokvm-app-ext4-") as temporary:
                image = self.fixture(Path(temporary), fault)
                result = subprocess.run([sys.executable, "-B", str(TOOL), str(image)],
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode == 0, fault is None, result.stderr)
                if fault is None:
                    self.assertIn("not boot/runtime acceptance", result.stdout)

    def test_missing_and_invalid_images_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="nanokvm-app-invalid-ext4-") as temporary:
            missing = Path(temporary) / "missing"
            invalid = Path(temporary) / "invalid"
            invalid.write_bytes(b"not an ext4 filesystem")
            for path in [missing, invalid]:
                result = subprocess.run([sys.executable, "-B", str(TOOL), str(path)],
                                        capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--actual":
        def bounded(path, maximum):
            with Path(path).open("rb") as source:
                data = source.read(maximum + 1)
            if not 0 < len(data) <= maximum:
                raise ValueError("unbounded actual fixture input")
            return data

        backend = bounded(sys.argv[2], 128 * 1024 * 1024)
        helper = bounded(sys.argv[3], 32 * 1024 * 1024)
        with tempfile.TemporaryDirectory(prefix="nanokvm-app-actual-ext4-") as temporary:
            image = RootfsRecoveryTests.fixture(Path(temporary), None, helper, backend)
            result = subprocess.run([sys.executable, "-B", str(TOOL), str(image)],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise ValueError(result.stderr)
            print(result.stdout.strip())
            print("actual backend SHA256=" + hashlib.sha256(backend).hexdigest())
            print("actual helper SHA256=" + hashlib.sha256(helper).hexdigest())
    else:
        unittest.main()
