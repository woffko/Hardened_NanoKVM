#!/usr/bin/env python3
"""Disposable ext4 fixtures, no mounts/loops/device or target execution."""

import hashlib
import importlib.util
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "native_tests", Path(__file__).with_name("test-native-runtime-binding.py"))
native_tests = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native_tests)
binding = native_tests.binding
TOOL = Path(__file__).with_name("verify-native-runtime-rootfs.py")


class NativeRootfsTests(unittest.TestCase):
    @staticmethod
    def fixture(directory, fault=None, role="owner", actual_backend=None, helpers=None):
        root = directory / "tree"
        parents = ["/", "/usr", "/usr/libexec", "/kvmapp", "/kvmapp/system",
                   "/kvmapp/system/bin", "/kvmapp/server", "/etc", "/etc/kvm", "/etc/kvm/native-runtime-boot"]
        for parent in parents:
            (root / parent.lstrip("/")).mkdir(parents=True, exist_ok=True)
        state = root / "etc/kvm/native-runtime-boot/state"
        state.parent.chmod(0o700)
        prefix = b"NKBOOT02" + bytes(36) + b"\x01" + bytes(35)
        state.write_bytes(prefix + hashlib.sha256(prefix).digest())
        state.chmod(0o600)
        if fault and fault.startswith("boot-"):
            if fault == "boot-missing": state.unlink()
            elif fault == "boot-mode": state.chmod(0o644)
            elif fault == "boot-parent-mode": state.parent.chmod(0o755)
            elif fault == "boot-symlink": state.unlink(); state.symlink_to("/outside")
            elif fault == "boot-hardlink": os.link(state, state.with_name("alias"))
            elif fault not in ["boot-owner", "boot-parent-owner"]:
                data = bytearray(state.read_bytes())
                if fault == "boot-size": data.append(0)
                elif fault == "boot-magic": data[0] ^= 1
                elif fault == "boot-epoch": data[8] = 1
                elif fault == "boot-phase": data[44] = 3
                elif fault == "boot-reserved": data[45] = 1
                elif fault == "boot-profile": data[48] = 1
                elif fault == "boot-hash": data[111] ^= 1
                elif fault == "boot-old-format":
                    prefix = b"NKBOOT01" + bytes(36) + b"\x01" + bytes(3)
                    data = prefix + hashlib.sha256(prefix).digest()
                else: raise ValueError(fault)
                if fault not in ["boot-size", "boot-hash", "boot-old-format"]:
                    data[80:112] = hashlib.sha256(data[:80]).digest()
                state.write_bytes(data)
        if helpers is None:
            helpers = {name: native_tests.ssh_tests.image() + name.encode() for name in binding.NATIVE_MAGICS}
        frames = []
        payloads = []
        for name, magic in binding.NATIVE_MAGICS.items():
            frame = binding.envelope(helpers[name], magic)
            if name == role:
                if fault == "missing-binding":
                    frame = b""
                elif fault == "duplicate-binding":
                    frame += frame
                elif fault == "wrong-domain":
                    frame = binding.envelope(helpers[name], binding.MAGIC)
            frames.append(frame)
            for parent in ["/usr/libexec", "/kvmapp/system/bin"]:
                payload = parent + "/nanokvm-native-" + name
                path = root / payload.lstrip("/")
                path.write_bytes(helpers[name])
                path.chmod(0o755)
                payloads.append(payload)
        backend = root / "kvmapp/server/NanoKVM-Server"
        backend.write_bytes(actual_backend if actual_backend is not None else b"synthetic backend" + b"".join(frames))
        backend.chmod(0o755)
        independent = root / ("usr/libexec/nanokvm-native-" + role)
        bundled = root / ("kvmapp/system/bin/nanokvm-native-" + role)
        if fault == "missing-independent":
            independent.unlink()
        elif fault in ["independent-bytes", "bundled-bytes"]:
            path = independent if fault == "independent-bytes" else bundled
            corrupt = bytearray(path.read_bytes())
            corrupt[-1] ^= 1
            path.write_bytes(corrupt)
        elif fault in ["independent-symlink", "bundled-symlink"]:
            path = independent if fault == "independent-symlink" else bundled
            path.unlink()
            path.symlink_to("/outside")
        elif fault in ["independent-hardlink", "bundled-hardlink"]:
            path = independent if fault == "independent-hardlink" else bundled
            os.link(path, path.with_name("alias"))
        elif fault in ["independent-mode", "bundled-mode"]:
            (independent if fault == "independent-mode" else bundled).chmod(0o777)
        image = directory / "rootfs.ext4"
        payload_size = backend.stat().st_size + 2 * sum(map(len, helpers.values()))
        with image.open("wb") as output:
            output.truncate(max(16 * 1024 * 1024, payload_size * 2 + 8 * 1024 * 1024))
        subprocess.run(["mkfs.ext4", "-F", "-q", "-d", str(root), str(image)],
                       check=True, capture_output=True, timeout=30)
        commands = []
        for path in parents + payloads + ["/kvmapp/server/NanoKVM-Server", "/etc/kvm/native-runtime-boot/state"]:
            for field in ["uid", "gid"]:
                commands.append(f"sif {path} {field} 0")
        if fault in ["independent-owner", "bundled-owner"]:
            parent = "/usr/libexec" if fault == "independent-owner" else "/kvmapp/system/bin"
            commands.append(f"sif {parent}/nanokvm-native-{role} uid 1")
        elif fault == "oversized-independent":
            commands.append(f"sif /usr/libexec/nanokvm-native-{role} size {binding.MAX_NATIVE_HELPER + 1}")
        elif fault == "parent-mode":
            commands.append("sif /usr/libexec mode 040777")
        elif fault == "bundled-parent-owner":
            commands.append("sif /kvmapp/system uid 1")
        elif fault == "backend-owner":
            commands.append("sif /kvmapp/server/NanoKVM-Server uid 1")
        elif fault == "boot-owner":
            commands.append("sif /etc/kvm/native-runtime-boot/state uid 1")
        elif fault == "boot-parent-owner":
            commands.append("sif /etc/kvm/native-runtime-boot uid 1")
        subprocess.run(["debugfs", "-w", "-f", "-", str(image)], input="\n".join(commands) + "\n",
                       text=True, check=True, capture_output=True, timeout=30)
        return image

    def test_all_four_roles_require_exact_protected_independent_and_bundled_bytes(self):
        faults = [None, "missing-independent", "independent-bytes", "bundled-bytes",
                  "missing-binding", "duplicate-binding", "wrong-domain", "independent-symlink",
                  "bundled-symlink", "independent-hardlink", "bundled-hardlink", "independent-mode",
                  "bundled-mode", "independent-owner", "bundled-owner", "oversized-independent"]
        for role in binding.NATIVE_MAGICS:
            for fault in faults:
                with self.subTest(role=role, fault=fault), tempfile.TemporaryDirectory(prefix="nanokvm-native-ext4-") as temporary:
                    image = self.fixture(Path(temporary), fault, role)
                    result = subprocess.run([sys.executable, "-B", str(TOOL), str(image)],
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode == 0, fault is None, result.stderr)
                    if fault is None:
                        self.assertIn("not boot/runtime acceptance", result.stdout)

    def test_parent_and_backend_protection_and_invalid_filesystems(self):
        for fault in ["parent-mode", "bundled-parent-owner", "backend-owner"]:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="nanokvm-native-parent-") as temporary:
                image = self.fixture(Path(temporary), fault)
                result = subprocess.run([sys.executable, "-B", str(TOOL), str(image)],
                                        capture_output=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)

    def test_only_exact_protected_factory_seed_is_accepted_in_full_image(self):
        for fault in ["boot-missing", "boot-size", "boot-magic", "boot-epoch", "boot-phase",
                      "boot-reserved", "boot-profile", "boot-old-format", "boot-hash", "boot-mode", "boot-parent-mode",
                      "boot-symlink", "boot-hardlink", "boot-owner", "boot-parent-owner"]:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="nanokvm-native-boot-ext4-") as temporary:
                image = self.fixture(Path(temporary), fault)
                result = subprocess.run([sys.executable, "-B", str(TOOL), str(image)],
                                        capture_output=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
        with tempfile.TemporaryDirectory(prefix="nanokvm-native-invalid-ext4-") as temporary:
            invalid = Path(temporary) / "invalid"
            invalid.write_bytes(b"not ext4")
            for image in [invalid, Path(temporary) / "missing"]:
                result = subprocess.run([sys.executable, "-B", str(TOOL), str(image)],
                                        capture_output=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--actual":
        with binding.regular(Path(sys.argv[2]), binding.MAX_BACKEND) as source:
            backend = source.read(binding.MAX_BACKEND + 1)
        helpers = {}
        for role in binding.NATIVE_MAGICS:
            with binding.regular(Path(sys.argv[3]) / ("nanokvm-native-" + role), binding.MAX_NATIVE_HELPER) as source:
                helpers[role] = source.read(binding.MAX_NATIVE_HELPER + 1)
        with tempfile.TemporaryDirectory(prefix="nanokvm-native-actual-ext4-") as temporary:
            image = NativeRootfsTests.fixture(Path(temporary), actual_backend=backend, helpers=helpers)
            result = subprocess.run([sys.executable, "-B", str(TOOL), str(image)],
                                    check=True, capture_output=True, text=True, timeout=30)
            print(result.stdout.strip())
            print("actual backend SHA256=" + hashlib.sha256(backend).hexdigest())
            for role, data in helpers.items():
                print("actual " + role + " SHA256=" + hashlib.sha256(data).hexdigest())
    else:
        unittest.main()
