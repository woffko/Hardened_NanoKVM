#!/usr/bin/env python3
"""Synthetic boot-delivery consistency and disposable legacy-copier fixtures.

No target process, device, network, full init script or live rootfs is used.
"""

import hashlib
import importlib.util
import io
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("boot_delivery", ROOT / "scripts/app-boot-delivery.py")
delivery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(delivery)
COMPAT = ROOT / "support/update-compat/rc12/S95nanokvm"


class BootDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="nanokvm-boot-delivery-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        self.bytes = []
        for name in delivery.SCRIPTS:
            data = ("#!/bin/sh\n# synthetic canonical " + name + "\nexit 0\n").encode()
            (self.scripts / name).write_bytes(data)
            self.bytes.append(data)
        self.backend = self.root / "backend"
        self.backend.write_bytes(b"synthetic backend, not an ELF" + b"\x00".join(self.bytes))
        self.compat = self.root / "compat"
        self.compat.write_bytes(COMPAT.read_bytes())
        self.version = self.root / "version"
        self.version.write_text("0.0.0\n")

    def inputs(self):
        delivery.verify_inputs(self.backend, self.scripts, self.compat, self.version)

    def test_nonrelease_or_invalid_semver_is_rejected_before_packaging(self):
        for version in ["2.0.43-dev", "2.0.43+metadata", "02.0.43", "1.2", "1.2.3.4",
                        "18446744073709551616.0.0", "1.2.3\nextra", ""]:
            with self.subTest(version=version):
                self.version.write_text(version)
                with self.assertRaises((OSError, ValueError)):
                    self.inputs()

    def archive(self, members):
        path = self.root / "archive.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, data, kind in members:
                info = tarfile.TarInfo(name)
                info.type = kind
                if kind == tarfile.REGTYPE:
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
                else:
                    info.linkname = delivery.S95_PATH
                    archive.addfile(info)
        return path

    def legacy(self):
        return (delivery.S95_PATH, self.compat.read_bytes(), tarfile.REGTYPE)

    def test_pinned_script_matches_the_documented_rc12_digest(self):
        self.assertEqual(hashlib.sha256(COMPAT.read_bytes()).hexdigest(), delivery.COMPAT_SHA256)

    def test_compile_bound_inputs_accept_exact_bytes(self):
        self.inputs()

    def test_framed_payloads_keep_exact_once_source_verification(self):
        # Framing is opaque to this build consistency check; its consumer still
        # needs the separate Rust catalog validation and protected provenance.
        magics = (b"NKBSA001", b"NKBSE001", b"NKBSW001", b"NKBSK001")
        frames = [magic + len(data).to_bytes(8, "little")
                  + hashlib.sha256(data).digest() + data
                  for magic, data in zip(magics, self.bytes)]
        backend = b"synthetic framed backend, not an ELF" + b"".join(frames)
        self.backend.write_bytes(backend)
        self.inputs()
        for duplicate in frames:
            with self.subTest(duplicate_magic=duplicate[:8]):
                self.backend.write_bytes(backend + duplicate)
                with self.assertRaises(ValueError):
                    self.inputs()

    def test_old_missing_duplicate_or_changed_backend_payload_is_rejected(self):
        original = self.backend.read_bytes()
        for payload in [b"old backend", original + self.bytes[0], original[:-1]]:
            with self.subTest(length=len(payload)):
                self.backend.write_bytes(payload)
                with self.assertRaises(ValueError):
                    self.inputs()

    def test_foreign_compat_and_missing_canonical_script_are_rejected(self):
        self.compat.write_bytes(b"foreign old script")
        with self.assertRaises(ValueError):
            self.inputs()
        self.compat.write_bytes(COMPAT.read_bytes())
        (self.scripts / delivery.SCRIPTS[0]).unlink()
        with self.assertRaises(OSError):
            self.inputs()

    def test_nonregular_or_symlink_build_inputs_are_not_read(self):
        self.backend.unlink()
        self.backend.symlink_to(self.compat)
        with self.assertRaises(OSError):
            self.inputs()
        self.backend.unlink()
        self.backend.mkdir()
        with self.assertRaises(ValueError):
            self.inputs()

    def test_archive_accepts_only_the_legacy_boot_profile(self):
        delivery.verify_archive(self.archive([self.legacy()]))
        for name in delivery.SCRIPTS[:-1]:
            with self.subTest(name=name):
                path = "kvmapp/system/init.d/" + name
                for member in [(path, b"new gate", tarfile.REGTYPE),
                               (path + "/", b"", tarfile.DIRTYPE),
                               (path + "/child", b"new gate", tarfile.REGTYPE)]:
                    with self.assertRaises(ValueError):
                        delivery.verify_archive(self.archive([self.legacy(), member]))

    def test_missing_duplicate_foreign_and_nonregular_s95_are_rejected(self):
        for members in [[], [self.legacy(), self.legacy()],
                        [(delivery.S95_PATH, b"new gated script", tarfile.REGTYPE)],
                        [(delivery.S95_PATH, b"", tarfile.SYMTYPE)],
                        [(delivery.S95_PATH, b"", tarfile.LNKTYPE)],
                        [(delivery.S95_PATH, b"", tarfile.DIRTYPE)],
                        [self.legacy(), (delivery.S95_PATH + "/child", b"bad tree", tarfile.REGTYPE)],
                        [(delivery.S95_PATH, bytes(delivery.MAX_SCRIPT + 1), tarfile.REGTYPE)]]:
            with self.subTest(members=len(members)):
                with self.assertRaises(ValueError):
                    delivery.verify_archive(self.archive(members))

    def test_archive_aliases_and_special_objects_are_rejected(self):
        for name in ["./kvmapp/system/init.d/S02apprecover", "kvmapp//system/init.d/S02apprecover",
                     "/kvmapp/system/init.d/S02apprecover", "kvmapp/system/../init.d/S02apprecover"]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    delivery.verify_archive(self.archive([self.legacy(), (name, b"gate", tarfile.REGTYPE)]))
        with self.assertRaises(ValueError):
            delivery.verify_archive(self.archive([self.legacy(), ("fifo", b"", tarfile.FIFOTYPE)]))

    def test_archive_member_and_expansion_limits_are_enforced(self):
        path = self.archive([self.legacy(), ("other", b"data", tarfile.REGTYPE)])
        with mock.patch.object(delivery, "MAX_MEMBERS", 1), self.assertRaises(ValueError):
            delivery.verify_archive(path)
        with mock.patch.object(delivery, "MAX_EXPANDED", 1), self.assertRaises(ValueError):
            delivery.verify_archive(path)

    def test_corrupt_compressed_archive_is_rejected(self):
        path = self.root / "invalid.tar.gz"
        path.write_bytes(b"not gzip or tar")
        with self.assertRaises((OSError, ValueError, tarfile.TarError)):
            delivery.verify_archive(path)

    def test_exact_legacy_copier_does_not_publish_gates_or_overwrite_itself(self):
        text = COMPAT.read_text()
        match = re.search(r"^install_boot_script\(\) \{\n.*?^\}", text, re.M | re.S)
        self.assertIsNotNone(match)
        body = match[0]
        self.assertIn('[ -f "$src" ] || return', body)
        self.assertIn('if ! cmp -s "$src" "$dst";', body)
        candidate = self.root / "candidate"
        installed = self.root / "installed"
        candidate.mkdir()
        installed.mkdir()
        (candidate / "S95nanokvm").write_bytes(self.compat.read_bytes())
        for name in delivery.SCRIPTS:
            (installed / name).write_bytes(self.compat.read_bytes() if name == "S95nanokvm" else b"old trusted gate\n")
        body = body.replace('src="/kvmapp/system/init.d/$name"',
                            'src=' + shlex.quote(str(candidate)) + '/"$name"')
        body = body.replace('dst="/etc/init.d/$name"',
                            'dst=' + shlex.quote(str(installed)) + '/"$name"')
        self.assertNotIn('/kvmapp/', body)
        self.assertNotIn('/etc/', body)
        log = self.root / "writes"
        prefix = 'cp() { echo attempted >> ' + shlex.quote(str(log)) + '; return 75; }\n'
        prefix += 'chmod() { return 75; }\n'
        calls = '\n'.join('install_boot_script ' + name + ' || true' for name in delivery.SCRIPTS)
        result = subprocess.run(["/bin/sh", "-c", prefix + body + '\n' + calls],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(log.exists())
        # The pre-fix canonical bundle WOULD enter the old copy path.
        (candidate / "S95nanokvm").write_bytes(b"new gated S95\n")
        result = subprocess.run(["/bin/sh", "-c", prefix + body + '\n' + calls],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.read_text(), "attempted\n")


if __name__ == "__main__":
    unittest.main()
