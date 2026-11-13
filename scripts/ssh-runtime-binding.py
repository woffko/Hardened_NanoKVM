#!/usr/bin/env python3
"""Bounded build/package binding of the static helper; not a signature API.

The backend embeds this envelope, then captures its own bytes at runtime. No
runtime p3 helper/manifest is trusted. Host inspection is only a consistency
gate, not evidence that arbitrary supplied backend bytes are authentic.
"""

import argparse
import hashlib
import mmap
import os
from pathlib import Path
import stat
import struct
import sys

MAGIC = b"NKSSHRT1"
APP_RECOVERY_MAGIC = b"NKAPPBT1"
NATIVE_MAGICS = {
    "owner": b"NKNOWNR1",
    "broker": b"NKNBRKR1",
    "ctl": b"NKNCTL01",
    "recovery": b"NKNREC01",
}
DOMAINS = (MAGIC, APP_RECOVERY_MAGIC, *NATIVE_MAGICS.values())
HEADER = 48
MAX_HELPER = 32 * 1024 * 1024
MAX_NATIVE_HELPER = 8 * 1024 * 1024
MAX_BACKEND = 128 * 1024 * 1024


def regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum:
            raise ValueError("input must be a bounded nonempty regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def check_elf(image):
    if not 64 <= len(image) <= MAX_HELPER or image[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("helper is not static ELF64 little-endian RV64")
    u16 = lambda offset: struct.unpack_from("<H", image, offset)[0]
    phoff = struct.unpack_from("<Q", image, 32)[0]
    count = u16(56)
    if (u16(16) != 2 or u16(18) != 243 or struct.unpack_from("<I", image, 20)[0] != 1
            or u16(52) != 64 or u16(54) != 56 or not 1 <= count <= 128
            or phoff < 64 or phoff + count * 56 > len(image)):
        raise ValueError("helper ELF header/program table is invalid")
    load = False
    for n in range(count):
        start = phoff + n * 56
        kind = struct.unpack_from("<I", image, start)[0]
        if kind in (2, 3):
            raise ValueError("helper ELF has dynamic/interpreter segments")
        if kind == 1:
            offset, address, _, filesz, memsz, align = struct.unpack_from("<6Q", image, start + 8)
            if (offset + filesz > len(image) or memsz < filesz or address + memsz > 2**64 - 1
                    or (align > 1 and (align & (align - 1) or address % align != offset % align))):
                raise ValueError("helper LOAD range/alignment is invalid")
            load = True
    if not load:
        raise ValueError("helper ELF has no LOAD")


def envelope(image, magic=MAGIC):
    if magic not in DOMAINS:
        raise ValueError("unsupported runtime binding domain")
    if magic in NATIVE_MAGICS.values() and len(image) > MAX_NATIVE_HELPER:
        raise ValueError("native helper exceeds its byte budget")
    check_elf(image)
    return magic + struct.pack("<Q", len(image)) + hashlib.sha256(image).digest() + image


def locate(backend, magic=MAGIC):
    if magic not in DOMAINS:
        raise ValueError("unsupported runtime binding domain")
    found = None
    offset = 0
    candidates = 0
    while True:
        offset = backend.find(magic, offset)
        if offset < 0:
            break
        candidates += 1
        if candidates > 64:
            raise ValueError("backend has too many helper binding markers")
        start = offset
        offset += len(magic)
        if start + HEADER > len(backend):
            continue
        size = struct.unpack_from("<Q", backend, start + 8)[0]
        end = start + HEADER + size
        if not 64 <= size <= MAX_HELPER or end > len(backend):
            continue
        if magic in NATIVE_MAGICS.values() and size > MAX_NATIVE_HELPER:
            continue
        image = backend[start + HEADER:end]
        digest = backend[start + 16:start + HEADER]
        if hashlib.sha256(image).digest() != digest:
            continue
        try:
            check_elf(image)
        except ValueError:
            continue
        if found is not None:
            raise ValueError("backend has ambiguous duplicate helper bindings")
        found = (image, digest)
    if found is None:
        raise ValueError("backend has no valid embedded static helper binding")
    return found


def create_exclusive(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def main(magic=MAGIC, description=__doc__):
    if magic not in DOMAINS:
        raise ValueError("unsupported runtime binding domain")
    maximum = MAX_NATIVE_HELPER if magic in NATIVE_MAGICS.values() else MAX_HELPER
    parser = argparse.ArgumentParser(description=description)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--helper", required=True, type=Path)
    prepare.add_argument("--directory", required=True, type=Path)
    for name in ("inspect", "extract", "verify"):
        command = sub.add_parser(name)
        command.add_argument("--backend", required=True, type=Path)
        if name == "extract":
            command.add_argument("--destination", required=True, type=Path)
        elif name == "verify":
            command.add_argument("--helper", required=True, type=Path)
        else:
            command.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    if args.command == "prepare":
        with regular(args.helper, maximum) as source:
            image = source.read(maximum + 1)
        data = envelope(image, magic)
        args.directory.mkdir(parents=True, exist_ok=True)
        prefix = "" if magic == MAGIC else "app-"
        for role, domain in NATIVE_MAGICS.items():
            if magic == domain:
                prefix = "native-" + role + "-"
        destination = args.directory.resolve() / (prefix + hashlib.sha256(image).hexdigest() + ".binding")
        try:
            create_exclusive(destination, data, 0o444)
        except FileExistsError:
            with regular(destination, maximum + HEADER) as source:
                if source.read(maximum + HEADER + 1) != data:
                    raise ValueError("existing content-addressed binding differs") from None
        print(destination)
        return
    with regular(args.backend, MAX_BACKEND) as source:
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as backend:
            image, digest = locate(backend, magic)
    if args.command == "extract":
        create_exclusive(args.destination, image, 0o500)
    elif args.command == "verify":
        with regular(args.helper, maximum) as source:
            if source.read(maximum + 1) != image:
                raise ValueError("helper differs from exact embedded runtime")
    elif not args.quiet:
        print(digest.hex(), len(image))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"SSH runtime binding rejected: {error}", file=sys.stderr)
        sys.exit(1)
