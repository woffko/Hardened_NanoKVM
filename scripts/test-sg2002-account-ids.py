#!/usr/bin/env python3
"""Exercise actual Buildroot explicit-ID precedence over package allocation."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("accounts", root / "scripts/validate-sg2002-account-ids.py")
accounts = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
spec.loader.exec_module(accounts)
buildroot = Path(sys.argv[1]).resolve()
pins = (root / "buildroot-external/hardened-sg2002/board/sg2002/users.txt").read_text()
# The compact numbers are also what mkusers allocates today, so a package added
# later, listed first, is what shows that the pins hold them in place.
packages = "future -1 future -1 * - - - A package added later\n"
packages += "avahi -1 avahi -1 * - - -\nsshd -1 sshd -1 * /var/empty - - SSH drop priv user\n"
packages += "- -1 input -1 - - - -\n- -1 kvm -1 - - - -\n- -1 sgx -1 - - - -\n"
with tempfile.TemporaryDirectory(prefix="nanokvm-account-test-") as temporary:
    work = Path(temporary)
    config = work / "config"
    config.write_text('BR2_TARGET_GENERIC_PASSWD_METHOD="sha-512"\n')
    for label, entries, valid in (("package-first", packages + pins, True),
                                  ("pins-first", pins + packages, True),
                                  ("unpinned", packages, False)):
        target = work / label
        (target / "etc").mkdir(parents=True)
        for name in ("passwd", "group", "shadow"):
            shutil.copyfile(buildroot / "system/skeleton/etc" / name, target / "etc" / name)
        table = work / (label + ".txt")
        table.write_text(entries)
        result = subprocess.run(["bash", str(buildroot / "support/scripts/mkusers"), str(table), str(target)],
                                env=dict(os.environ, BR2_CONFIG=str(config)), check=True,
                                capture_output=True, text=True)
        passwd = (target / "etc/passwd").read_text()
        group = (target / "etc/group").read_text()
        try:
            accounts.validate(passwd, group)
        except ValueError:
            if valid:
                raise
        else:
            assert valid, "unpinned image incorrectly accepted"
        if valid:
            assert f"chown -h -R 101:102 '{target}/var/empty'" in result.stdout.replace("//", "/")
            shadow = {line.split(":")[0]: line.split(":")[1]
                      for line in (target / "etc/shadow").read_text().splitlines()}
            assert all(shadow[name].startswith(("*", "!")) for name in accounts.USERS)
            for name, (uid, _, _) in accounts.USERS.items():
                changed = "\n".join(":".join([row[0], row[1], str(uid + 200)] + row[3:])
                                    if row[0] == name else ":".join(row)
                                    for row in (line.split(":") for line in passwd.splitlines()))
                try:
                    accounts.validate(changed, group)
                except ValueError:
                    pass
                else:
                    raise AssertionError(f"changed user accepted: {name}")
            for name, gid in accounts.GROUPS.items():
                changed = "\n".join(":".join([row[0], row[1], str(gid + 200), row[3]])
                                    if row[0] == name else ":".join(row)
                                    for row in (line.split(":") for line in group.splitlines()))
                try:
                    accounts.validate(passwd, changed)
                except ValueError:
                    pass
                else:
                    raise AssertionError(f"changed group accepted: {name}")
        print("PASS", label)
print("PASS: mkusers order independence, locked reservations, ownership commands, collision regression")
