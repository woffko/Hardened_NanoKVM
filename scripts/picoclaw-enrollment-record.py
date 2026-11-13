#!/usr/bin/env python3
"""Offline full-image-only Pico enrollment seed; never include in app archives."""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import tempfile


def factory_record():
    prefix = b"NKPENR01\x01" + bytes(55)
    return prefix + hashlib.sha256(b"NanoKVM Pico enrollment v1\0" + prefix).digest()


def seed(output):
    output = Path(output)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = output.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o7022:
        raise ValueError("unsafe Pico factory seed parent")
    if (output.parent / "picoclaw-operations").exists() or (output.parent / "picoclaw-operations").is_symlink():
        raise ValueError("refusing factory seed beside an existing Pico store")
    expected = factory_record()
    if output.exists() or output.is_symlink():
        info = output.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or output.read_bytes() != expected):
            raise ValueError("refusing to reset non-factory Pico enrollment")
        return
    fd, temporary = tempfile.mkstemp(prefix=".pico-factory-", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(expected)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output)
        os.unlink(temporary)
        temporary = None
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            os.unlink(temporary)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    seed(parser.parse_args().output)
