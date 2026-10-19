#!/usr/bin/env python3
"""Verify four independent native programs in an ext image without mounting.

Build consistency only, not signature provenance, native startup or boot health.
Historical images without these bindings require their historical verifier.
"""

import argparse
import importlib.util
import mmap
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "app_rootfs", Path(__file__).with_name("verify-app-recovery-rootfs.py"))
rootfs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rootfs)
binding = rootfs.binding


def verify(image):
    for parent in ["/", "/usr", "/usr/libexec", "/kvmapp", "/kvmapp/system",
                   "/kvmapp/system/bin", "/kvmapp/server"]:
        rootfs.metadata(image, parent, "directory")
    backend = "/kvmapp/server/NanoKVM-Server"
    if rootfs.metadata(image, backend, "regular", binding.MAX_BACKEND) != (0o755, 0, 0, 1):
        raise ValueError("unsafe native authority backend metadata")
    with tempfile.TemporaryDirectory(prefix="nanokvm-native-rootfs-", dir="/tmp") as temporary:
        backend_dump = Path(temporary) / "backend"
        rootfs.debugfs(image, f"dump {backend} {backend_dump}")
        with binding.regular(backend_dump, binding.MAX_BACKEND) as source:
            with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as view:
                for role, magic in binding.NATIVE_MAGICS.items():
                    expected, _ = binding.locate(view, magic)
                    name = "nanokvm-native-" + role
                    for index, parent in enumerate(["/usr/libexec", "/kvmapp/system/bin"]):
                        payload = parent + "/" + name
                        if rootfs.metadata(image, payload, "regular", binding.MAX_NATIVE_HELPER) != (0o755, 0, 0, 1):
                            raise ValueError("unsafe native helper metadata: " + payload)
                        destination = Path(temporary) / (role + "-" + str(index))
                        rootfs.debugfs(image, f"dump {payload} {destination}")
                        with binding.regular(destination, binding.MAX_NATIVE_HELPER) as helper:
                            if helper.read(binding.MAX_NATIVE_HELPER + 1) != expected:
                                raise ValueError("native helper differs from exact backend binding: " + payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    if not args.image.is_file():
        raise ValueError("missing ext rootfs image")
    verify(args.image)
    print("independent native runtime rootfs bindings: PASS (not boot/runtime acceptance)")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("Native runtime rootfs rejected: " + str(error), file=sys.stderr)
        sys.exit(1)
