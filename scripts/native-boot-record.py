#!/usr/bin/env python3
"""Image-producer-only native boot seed. Never install from an app archive."""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import tempfile


def factory_record():
    prefix = b"NKBOOT02" + bytes(36) + b"\x01" + bytes(35)
    return prefix + hashlib.sha256(prefix).digest()


def seed(output):
    expected = factory_record()
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = output.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError("unsafe native boot seed directory")
    if output.exists() or output.is_symlink():
        info = output.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or output.read_bytes() != expected):
            raise ValueError("refusing to reset an existing non-factory boot record")
        return
    fd, temporary = tempfile.mkstemp(prefix=".factory-", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(expected)
            stream.flush()
            os.fsync(stream.fileno())
        # Producer operates on an offline tree, never a mounted device runtime.
        os.link(temporary, output)
        os.unlink(temporary)
        temporary = None
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
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
