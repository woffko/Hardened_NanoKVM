#!/usr/bin/env python3
"""Execute boot-policy fixtures only in disposable trees with inert commands.

--baseline-ref loads the named historical source for a fail-before comparison.
No actual device, mount, partition, account, hostname or service is changed.
"""

import argparse
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def source(path, baseline):
    if baseline:
        return subprocess.run(["git", "show", baseline + ":" + path], cwd=ROOT,
                              check=True, capture_output=True, text=True, timeout=10).stdout
    return (ROOT / path).read_text()


def put(root, relative, data, mode=0o600):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def snapshot(root, relatives):
    result = {}
    for relative in relatives:
        path = root / relative
        paths = sorted(path.rglob("*")) if path.is_dir() else [path]
        for child in paths:
            if child.is_file():
                result[str(child.relative_to(root))] = (child.read_bytes(), child.stat().st_mode & 0o7777)
    return result


def s01_fixture(body, root, kind):
    victims = {"etc/kvm/server.yaml": b"trusted private config\n",
               "etc/kvm/pwd": b"trusted account\n", "etc/shadow": b"trusted shadow\n",
               "etc/passwd": b"trusted passwd\n", "etc/hostname": b"trusted hostname\n",
               "etc/ssh/sshd_config": b"trusted ssh config\n",
               "usr/bin/picoclaw": b"trusted optional app bytes\n",
               "etc/init.d/S96picoclaw": b"trusted optional init bytes\n",
               "root/.picoclaw/workspace/notes/keep": b"trusted user data\n"}
    for name, data in victims.items():
        put(root, name, data)
    before = snapshot(root, list(victims))
    put(root, "etc/profile", b"# fixture: retain inert PATH\n")
    put(root, "proc/mounts", b"fixture /data exfat rw 0 0\n")
    put(root, "dev/mmcblk0p3", b"inert device sentinel\n")
    if kind in ["marker-only", "forged-marker-and-state"]:
        put(root, "data/hardened-system-raw-update-pending.json", b'{"forged":true}\n')
    if kind in ["preserve-without-marker", "forged-marker-and-state"]:
        for name in victims:
            put(root, "data/.hardened-kvmcache/system-update/preserve/root/" + name,
                b"forged p3 bytes must not be imported\n")
        put(root, "data/.hardened-kvmcache/system-update/preserve/root/etc/kvm/update-keys/forged.pub.pem",
            b"inert forged public-key marker\n")
    legacy_before = snapshot(root, ["data"])
    commands = root / "commands"
    commands.mkdir()
    log = root / "commands.log"
    for name in ["parted", "resize2fs", "mkfs.exfat", "mount", "hostname", "sleep"]:
        put(commands, name, b'#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$COMMAND_LOG"\nexit 0\n', 0o755)
    # One simultaneous rewrite of absolute roots: inserted fixture prefixes are
    # never rewritten recursively. The sole computed restore destination in the
    # historical S01 is explicitly redirected too. No runtime override is added
    # to production scripts.
    pattern = r"(?<![A-Za-z0-9_./$-])/(data|boot|tmp|etc|dev|sys|proc|root|usr|var|device_key)(?=/|[\s\";]|$)"
    body = re.sub(pattern, lambda match: str(root / match[1]), body)
    body = body.replace('dest="/$rel"', 'dest="' + str(root) + '/$rel"')
    script = put(root, "fixture.sh", body.encode(), 0o700)
    result = subprocess.run(["/bin/sh", str(script), "start"], cwd=root,
                            env={"PATH": str(commands) + ":/usr/bin:/bin", "COMMAND_LOG": str(log)},
                            capture_output=True, text=True, timeout=10)
    unchanged = before == snapshot(root, list(victims))
    unchanged = unchanged and not (root / "etc/kvm/update-keys/forged.pub.pem").exists()
    # No deletion or completion marker may turn old evidence into trusted work.
    retained = legacy_before == snapshot(root, ["data"])
    return result.returncode == 0 and unchanged and retained


def s95_fixture(body, root, kind):
    match = re.search(r"^pending_update_file\(\) \{\n.*?^\}", body, re.M | re.S)
    if not match:
        raise ValueError("S95 pending-update selector not found")
    pending, legacy = root / "protected-pending", root / "legacy-p3-pending"
    if kind in ["root-only", "root-and-p3"]:
        pending.write_text("trusted root pending\n")
    if kind in ["p3-only", "root-and-p3"]:
        legacy.write_text("untrusted p3 pending\n")
    script = ("SYSTEM_PENDING_FILE=" + shlex.quote(str(pending)) + "\n"
              "SYSTEM_RAW_INSTALL_MARKER=" + shlex.quote(str(legacy)) + "\n" + match[0] +
              '\nif value=$(pending_update_file); then printf "%s\\n" "$value"; else printf "none\\n"; fi\n')
    result = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=10)
    expected = str(pending) if pending.exists() else "none"
    return result.returncode == 0 and result.stdout.strip() == expected


def rootfs_gate_fixture(root, kind, s01, s95):
    validator = (ROOT / "scripts/validate-nanokvm-rootfs.sh").read_text()
    match = re.search(r"^require_boot_state_boundary\(\) \{\n.*?^\}", validator, re.M | re.S)
    if not match:
        raise ValueError("rootfs boot boundary function not found")
    for base in ["kvmapp/system/init.d", "etc/init.d"]:
        put(root, base + "/S01fs", s01.encode())
        put(root, base + "/S95nanokvm", s95.encode())
    if kind == "installed-S01-mismatch":
        put(root, "etc/init.d/S01fs", b"stale installed S01\n")
    elif kind == "installed-S95-mismatch":
        put(root, "etc/init.d/S95nanokvm", b"stale installed S95\n")
    elif kind in ["legacy-S01", "legacy-S95"]:
        name = "S01fs" if kind == "legacy-S01" else "S95nanokvm"
        token = "restore_raw_root_config" if kind == "legacy-S01" else "SYSTEM_RAW_INSTALL_MARKER"
        for base in ["kvmapp/system/init.d", "etc/init.d"]:
            put(root, base + "/" + name, token.encode())
    prefix = "ROOT=" + shlex.quote(str(root)) + "\n"
    prefix += 'dump_file() { printf "%s%s\\n" "$ROOT" "$1"; }\ndie() { exit 1; }\n'
    if kind == "inspection-error":
        prefix += 'grep() { return 2; }\n'
    result = subprocess.run(["/bin/sh", "-c", prefix + match[0] + "\nrequire_boot_state_boundary\n"],
                            capture_output=True, timeout=10)
    return (result.returncode == 0) == (kind == "valid")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref")
    args = parser.parse_args()
    s01 = source("kvmapp/system/init.d/S01fs", args.baseline_ref)
    s95 = source("kvmapp/system/init.d/S95nanokvm", args.baseline_ref)
    failures = 0
    for name, function, body, kinds in [
        ("S01 boot restore", s01_fixture, s01,
         ["none", "marker-only", "preserve-without-marker", "forged-marker-and-state"]),
        ("S95 boot authority", s95_fixture, s95,
         ["none", "p3-only", "root-only", "root-and-p3"]),
    ]:
        for kind in kinds:
            with tempfile.TemporaryDirectory(prefix="nanokvm-p3-boot-boundary-") as temporary:
                ok = function(body, Path(temporary), kind)
                print(("PASS" if ok else "FAIL"), name, kind)
                failures += not ok
    repair = source("scripts/repair-nanokvm-backend-runtime.cjs", args.baseline_ref)
    ok = "/data/.hardened-kvmcache/system-update/preserve" not in repair
    print(("PASS" if ok else "FAIL"), "runtime repair has no legacy identity import")
    failures += not ok
    if not args.baseline_ref:
        for kind in ["valid", "installed-S01-mismatch", "installed-S95-mismatch",
                     "legacy-S01", "legacy-S95", "inspection-error"]:
            with tempfile.TemporaryDirectory(prefix="nanokvm-boot-rootfs-gate-") as temporary:
                ok = rootfs_gate_fixture(Path(temporary), kind, s01, s95)
                print(("PASS" if ok else "FAIL"), "rootfs boot boundary", kind)
                failures += not ok
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
