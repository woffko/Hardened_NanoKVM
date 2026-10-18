#!/usr/bin/env python3
"""Check independent recovery bytes/metadata in an ext image, without mounting.

Build consistency only: not an RSA signature, boot execution or health gate.
Historical images without this protocol need their historical verifier.
"""

import argparse
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "nanokvm_runtime_binding", Path(__file__).with_name("ssh-runtime-binding.py"))
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)


def debugfs(image, command):
    result = subprocess.run(["debugfs", "-R", command, str(image)],
                            env={**os.environ, "LC_ALL": "C"},
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError("debugfs failed")
    return result.stdout


def metadata(image, path, kind, limit=None):
    text = debugfs(image, "stat " + path)
    header = re.search(r"Inode:\s+(\d+)\s+Type:\s+(\w+)\s+Mode:\s+([0-7]+)", text)
    owner = re.search(r"User:\s+(\d+)\s+Group:\s+(\d+)", text)
    size = re.search(r"\bSize:\s+(\d+)", text)
    links = re.search(r"\bLinks:\s+(\d+)", text)
    if not all((header, owner, size, links)) or not int(header[1]) or header[2] != kind:
        raise ValueError("missing or unsafe rootfs object: " + path)
    mode = int(header[3], 8)
    if kind == "directory":
        if int(owner[1]) != 0 or mode & 0o7022:
            raise ValueError("unprotected independent recovery parent: " + path)
    elif limit is not None and not 0 < int(size[1]) <= limit:
        raise ValueError("unbounded rootfs payload: " + path)
    return mode, int(owner[1]), int(owner[2]), int(links[1])


def verify(image):
    for parent in ["/", "/usr", "/usr/libexec"]:
        metadata(image, parent, "directory")
    independent = "/usr/libexec/nanokvm-app-recovery"
    bundled = "/kvmapp/system/bin/nanokvm-app-recovery"
    backend = "/kvmapp/server/NanoKVM-Server"
    if metadata(image, independent, "regular", binding.MAX_HELPER) != (0o755, 0, 0, 1):
        raise ValueError("unsafe independent recovery metadata")
    metadata(image, bundled, "regular", binding.MAX_HELPER)
    metadata(image, backend, "regular", binding.MAX_BACKEND)
    with tempfile.TemporaryDirectory(prefix="nanokvm-app-rootfs-", dir="/tmp") as temporary:
        paths = []
        for index, source in enumerate([backend, independent, bundled]):
            destination = Path(temporary) / str(index)
            debugfs(image, f"dump {source} {destination}")
            paths.append(destination)
        with binding.regular(paths[0], binding.MAX_BACKEND) as source:
            expected, _ = binding.locate(source.read(binding.MAX_BACKEND + 1), binding.APP_RECOVERY_MAGIC)
        for path in paths[1:]:
            with binding.regular(path, binding.MAX_HELPER) as source:
                if source.read(binding.MAX_HELPER + 1) != expected:
                    raise ValueError("rootfs recovery differs from exact backend binding")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    if not args.image.is_file():
        raise ValueError("missing ext rootfs image")
    verify(args.image)
    print("independent app recovery rootfs binding: PASS (not boot/runtime acceptance)")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"App recovery rootfs rejected: {error}", file=sys.stderr)
        sys.exit(1)
