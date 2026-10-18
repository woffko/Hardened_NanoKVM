#!/usr/bin/env python3
"""Bounded build consistency for RC12 app-only boot-script delivery.

This is neither a signature/provenance API nor permission to execute legacy
scripts. Full-image staging keeps canonical scripts; app archives defer their
publication to the backend after independent helper bootstrap.
"""

import argparse
import hashlib
import importlib.util
import mmap
from pathlib import Path
import re
import sys
import tarfile

SPEC = importlib.util.spec_from_file_location(
    "nanokvm_runtime_binding", Path(__file__).with_name("ssh-runtime-binding.py"))
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)

SCRIPTS = ("S02apprecover", "S30eth", "S30wifi", "S95nanokvm")
MAX_SCRIPT = 64 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_MEMBERS = 8192
COMPAT_SHA256 = "8030d0f81581a417eca91e3db7e0c3d96cba197b519022d7c73c3c5caca05365"
PROFILE = "rc12-compat-bootstrap-v1"
S95_PATH = "kvmapp/system/init.d/S95nanokvm"


def script_bytes(path):
    with binding.regular(path, MAX_SCRIPT) as source:
        data = source.read(MAX_SCRIPT + 1)
    if not 0 < len(data) <= MAX_SCRIPT:
        raise ValueError("boot script exceeds its bound")
    return data


def verify_inputs(backend_path, scripts, compat, version_path):
    with binding.regular(version_path, 64) as source:
        version = source.read(65).decode("utf-8").strip()
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("app version must be strict semver x.y.z")
    if any(int(part) > 2**64 - 1 for part in version.split(".")):
        raise ValueError("app version component exceeds semver range")
    if hashlib.sha256(script_bytes(compat)).hexdigest() != COMPAT_SHA256:
        raise ValueError("legacy compatibility script differs from pinned RC12/app42 bytes")
    with binding.regular(backend_path, binding.MAX_BACKEND) as source:
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as backend:
            for name in SCRIPTS:
                data = script_bytes(scripts / name)
                first = backend.find(data)
                if first < 0 or backend.find(data, first + 1) >= 0:
                    raise ValueError("missing or ambiguous compile-bound boot script: " + name)


def verify_archive(path):
    forbidden = {"kvmapp/system/init.d/" + name for name in SCRIPTS[:-1]}
    found = False
    total = 0
    with binding.regular(path, MAX_ARCHIVE) as source:
        with tarfile.open(fileobj=source, mode="r|gz") as archive:
            for count, member in enumerate(archive, 1):
                if count > MAX_MEMBERS or member.size < 0:
                    raise ValueError("archive member bound exceeded")
                total += member.size
                if total > MAX_EXPANDED:
                    raise ValueError("archive expansion bound exceeded")
                # Only the canonical packager's path spelling is supported.
                # Aliases, links and special objects cannot bypass this check.
                name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
                parts = name.split("/")
                if name.startswith("/") or any(p in ("", ".", "..") for p in parts):
                    raise ValueError("noncanonical archive path")
                if not (member.isfile() or member.isdir()):
                    raise ValueError("unsupported archive entry type")
                if any(name == path or name.startswith(path + "/") for path in forbidden):
                    raise ValueError("app archive would publish a gate before helper bootstrap")
                if name.startswith(S95_PATH + "/"):
                    raise ValueError("legacy S95 must not be an implicit directory")
                if name == S95_PATH:
                    if found or not member.isfile() or not 0 < member.size <= MAX_SCRIPT:
                        raise ValueError("missing/duplicate/invalid legacy S95")
                    content = archive.extractfile(member)
                    if content is None:
                        raise ValueError("unreadable legacy S95")
                    with content:
                        data = content.read(MAX_SCRIPT + 1)
                    if len(data) != member.size or hashlib.sha256(data).hexdigest() != COMPAT_SHA256:
                        raise ValueError("archive compatibility script differs from pinned bytes")
                    found = True
    if not found:
        raise ValueError("app archive lacks mandatory legacy-compatible S95")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inputs = commands.add_parser("verify-inputs")
    inputs.add_argument("--backend", type=Path, required=True)
    inputs.add_argument("--scripts", type=Path, required=True)
    inputs.add_argument("--compat", type=Path, required=True)
    inputs.add_argument("--version-file", type=Path, required=True)
    archive = commands.add_parser("verify-archive")
    archive.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "verify-inputs":
        verify_inputs(args.backend, args.scripts, args.compat, args.version_file)
        print(PROFILE, COMPAT_SHA256)
    else:
        verify_archive(args.archive)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, tarfile.TarError) as error:
        print("App boot delivery rejected: " + str(error), file=sys.stderr)
        sys.exit(1)
