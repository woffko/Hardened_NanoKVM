#!/usr/bin/env python3
"""Check the pinned service accounts in the final filesystem image."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

USERS = {
    "avahi": (100, 101, "/"),
    "sshd": (101, 102, "/var/empty"),
}
GROUPS = {"avahi": 101, "sshd": 102, "input": 103, "kvm": 104, "sgx": 105}


def validate(passwd, group):
    users = [line.split(":") for line in passwd.splitlines()]
    groups = [line.split(":") for line in group.splitlines()]
    for rows, width in ((users, 7), (groups, 4)):
        if any(len(row) != width for row in rows):
            raise ValueError("malformed account table")
        if len({row[0] for row in rows}) != len(rows):
            raise ValueError("duplicate account name")
        if len({int(row[2]) for row in rows}) != len(rows):
            raise ValueError("duplicate numeric account ID")
    by_user = {row[0]: row for row in users}
    by_group = {row[0]: row for row in groups}
    for name, (uid, gid, home) in USERS.items():
        row = by_user.get(name)
        if row is None or (int(row[2]), int(row[3]), row[5], row[6]) != (uid, gid, home, "/bin/false"):
            raise ValueError(f"service account mismatch: {name}")
    for name, gid in GROUPS.items():
        row = by_group.get(name)
        if row is None or int(row[2]) != gid:
            raise ValueError(f"service group mismatch: {name}")


def main():
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        raise SystemExit("usage: validate-sg2002-account-ids.py <rootfs-image>")
    with tempfile.TemporaryDirectory(prefix="nanokvm-account-ids-") as directory:
        contents = []
        for name in ("passwd", "group"):
            target = Path(directory) / name
            subprocess.run(["debugfs", "-R", f"dump /etc/{name} {target}", sys.argv[1]],
                           check=True, capture_output=True, env=dict(os.environ, LC_ALL="C"))
            contents.append(target.read_text())
        validate(*contents)
    print("PASS: final rootfs carries the pinned service account/group IDs")


if __name__ == "__main__":
    main()
