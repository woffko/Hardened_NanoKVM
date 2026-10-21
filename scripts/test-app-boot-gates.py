#!/usr/bin/env python3
"""Bounded app-consumer shell fixtures; no network, device or host-root access.

Known consumer functions run only after checking that the fixed gate is their
first statement. Ungated historical bodies are rejected without executing them.
This is a source regression guard, not a sandbox for arbitrary shell programs.
"""

import argparse
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
GATE = "/usr/libexec/nanokvm-app-recovery gate >/dev/null || return 1"


def source(name, baseline):
    path = "kvmapp/system/init.d/" + name
    if baseline:
        return subprocess.run(["git", "show", baseline + ":" + path], cwd=ROOT,
                              check=True, capture_output=True, text=True, timeout=10).stdout
    return (ROOT / path).read_text()


def function(body, name):
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}", body, re.M | re.S)
    if not match:
        raise ValueError("missing function " + name)
    return match[0]


def denied_consumer(body, name):
    body = function(body, name)
    statements = [line.strip() for line in body.splitlines()[1:-1]
                  if line.strip() and not line.lstrip().startswith("#")]
    if not statements or statements[0] != GATE:
        return False  # Never execute an ungated historical body on the host.
    with tempfile.TemporaryDirectory(prefix="nanokvm-app-consumer-") as temporary:
        root = Path(temporary)
        helper, log = root / "helper", root / "calls"
        helper.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$GATE_LOG"\nexit 75\n')
        helper.chmod(0o700)
        body = body.replace("/usr/libexec/nanokvm-app-recovery", str(helper))
        result = subprocess.run(["/bin/sh", "-c", body + "\n" + name],
                                env={"GATE_LOG": str(log)}, capture_output=True, timeout=5)
        return result.returncode == 1 and log.read_text() == "gate\n"


def protected_copy(body, name):
    body = function(body, "install_boot_script")
    # Verify the known guard before running this copier in a disposable tree.
    if "S02apprecover|S30eth|S30wifi|S95nanokvm) return 0 ;;" not in body:
        return False
    with tempfile.TemporaryDirectory(prefix="nanokvm-app-init-copy-") as temporary:
        root = Path(temporary)
        for base, data in [("kvmapp/system/init.d", "old bundled code\n"),
                           ("etc/init.d", "independent protected code\n")]:
            target = root / base / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(data)
        body = body.replace('src="/kvmapp/', 'src="' + str(root) + '/kvmapp/')
        body = body.replace('dst="/etc/', 'dst="' + str(root) + '/etc/')
        result = subprocess.run(["/bin/sh", "-c", body + "\ninstall_boot_script " + name],
                                capture_output=True, timeout=5)
        return result.returncode == 0 and (root / "etc/init.d" / name).read_text() == "independent protected code\n"


def denied_native_consumer(body, name, operation):
    body = function(body, name)
    statements = [line.strip() for line in body.splitlines()[1:-1]
                  if line.strip() and not line.lstrip().startswith("#")]
    if statements != [
        "/usr/libexec/nanokvm-native-ctl picoclaw-control-ready >/dev/null || return $?",
        "/usr/libexec/nanokvm-native-ctl " + operation,
    ]:
        return False  # Historical copy/launcher bodies must never execute.
    with tempfile.TemporaryDirectory(prefix="nanokvm-native-consumer-") as temporary:
        root = Path(temporary)
        helper, log = root / "helper", root / "calls"
        helper.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$GATE_LOG"\nexit 75\n')
        helper.chmod(0o700)
        body = body.replace("/usr/libexec/nanokvm-native-ctl", str(helper))
        result = subprocess.run(["/bin/sh", "-c", body + "\n" + name],
                                env={"GATE_LOG": str(log)}, capture_output=True, timeout=5)
        return result.returncode == 75 and log.read_text() == "picoclaw-control-ready\n"


def optional_hwmon_absent(body):
    body = function(body, "start_hwmon_shadow")
    lines = body.splitlines()
    if lines[1].strip() != GATE or lines[2].strip() != '[ -x "$HWMON_SOURCE" ] || return 0':
        return False
    with tempfile.TemporaryDirectory(prefix="nanokvm-optional-hwmon-") as temporary:
        root = Path(temporary)
        helper = root / "helper"
        helper.write_text('#!/bin/sh\ntest "$1" = gate\n')
        helper.chmod(0o700)
        body = body.replace("/usr/libexec/nanokvm-app-recovery", str(helper))
        prefix = "HWMON_SOURCE=" + shlex.quote(str(root / "absent")) + "\n"
        result = subprocess.run(["/bin/sh", "-c", prefix + body + "\nstart_hwmon_shadow"],
                                capture_output=True, timeout=5)
        return result.returncode == 0


def rootfs_gate(kind, sources):
    validator = (ROOT / "scripts/validate-nanokvm-rootfs.sh").read_text()
    body = function(validator, "require_app_consumer_gates")
    with tempfile.TemporaryDirectory(prefix="nanokvm-app-init-rootfs-") as temporary:
        root = Path(temporary)
        for base in ["kvmapp/system/init.d", "etc/init.d"]:
            (root / base).mkdir(parents=True)
            for name, data in sources.items():
                (root / base / name).write_text(data)
        if kind == "installed-mismatch":
            (root / "etc/init.d/S30eth").write_text("stale installed gate\n")
        elif kind == "missing-installed":
            (root / "etc/init.d/S02apprecover").unlink()
        elif kind == "missing-marker":
            for base in ["kvmapp/system/init.d", "etc/init.d"]:
                (root / base / "S30wifi").write_text("ungated script\n")
        prefix = "ROOT=" + shlex.quote(str(root)) + "\n"
        prefix += 'dump_file() { printf "%s%s\\n" "$ROOT" "$1"; }\ndie() { exit 1; }\n'
        if kind == "inspection-error":
            prefix += 'grep() { return 2; }\n'
        result = subprocess.run(["/bin/sh", "-c", prefix + body + "\nrequire_app_consumer_gates\n"],
                                capture_output=True, timeout=5)
        return (result.returncode == 0) == (kind == "valid")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref")
    args = parser.parse_args()
    sources = {name: source(name, args.baseline_ref) for name in ["S30eth", "S30wifi", "S95nanokvm", "S96picoclaw"]}
    failures = 0

    def check(label, ok):
        nonlocal failures
        print(("PASS" if ok else "FAIL"), label)
        failures += not ok

    for file, names in [
        ("S30eth", ["apply_ipv6_dhcpv6"]), ("S30wifi", ["ap_start"]),
        ("S95nanokvm", ["start_kvm_system_runtime", "start_hwmon_shadow", "start_server_runtime",
                         "restart_server_runtime", "restart_server_safe", "start_runtime"]),
    ]:
        for name in names:
            check(file + " " + name + " denial before side effects", denied_consumer(sources[file], name))
    for name, operation in [("start_service", "ensure-picoclaw"), ("stop_service", "stop-picoclaw"),
                            ("onboard_service", "onboard-picoclaw")]:
        check("S96 " + name + " native denial before side effects",
              denied_native_consumer(sources["S96picoclaw"], name, operation))
    s95 = sources["S95nanokvm"]
    check("optional absent hwmon does not fail normal startup", optional_hwmon_absent(s95))
    for mode in ["start", "restart"]:
        match = re.search(r"^  " + mode + r"\)\n([^\n]+)", s95, re.M)
        check("S95 " + mode + " entry", bool(match and match[1].strip() == GATE.replace("return 1", "exit 1")))
    check("watchdog repeated admission", "while true; do\n            if ! /usr/libexec/nanokvm-app-recovery gate" in s95)
    check("delayed hwmon admission", 'sleep "$HWMON_START_DELAY_SECS"\n        /usr/libexec/nanokvm-app-recovery gate' in s95)
    for name in ["S02apprecover", "S30eth", "S30wifi", "S95nanokvm"]:
        check("preserve independent " + name, protected_copy(s95, name))
    api_path = "server-rust/src/api/picoclaw.rs"
    if args.baseline_ref:
        api = subprocess.run(["git", "show", args.baseline_ref + ":" + api_path], cwd=ROOT,
                             check=True, capture_output=True, text=True, timeout=10).stdout
    else:
        api = (ROOT / api_path).read_text()
    onboard = api.split("async fn onboard_runtime_config()", 1)[-1].split("fn resolve_config_path()", 1)[0]
    preflight = api.split("async fn native_control_ready()", 1)[-1].split("async fn run_native_control(", 1)[0]
    stop = api.split("async fn stop_runtime_inner()", 1)[1].split("async fn run_install_runtime()", 1)[0]
    native = api.split("async fn run_native_control(", 1)[-1].split("async fn run_script(", 1)[0]
    check("picoclaw Stop is independent of app gate and script selection",
          "run_native_control(PicoControl::Stop, support)" in stop
          and "AllowedCommand::NativePicoclawControl" in native
          and "output.status == 0" in native and "run_allowed_owned(" in native
          and "AllowedCommand::AppSlotGate" not in stop and 'run_script("stop"' not in stop
          and "killall" not in api)
    check("picoclaw onboard API requires exact current support and fresh boot, no legacy script selection",
          "native_control_ready().await?" in onboard and
          "run_native_control(PicoControl::Onboard, support).await?" in onboard and
          "native_bootstrap::check_installed()" in preflight and "boot::require_ready()" in preflight and
          "async fn run_script(" not in api)
    if not args.baseline_ref:
        s02 = source("S02apprecover", None)
        with tempfile.TemporaryDirectory(prefix="nanokvm-early-app-gate-") as temporary:
            root = Path(temporary)
            helper = root / "helper"
            helper.write_text('#!/bin/sh\ntest "$1" = gate || exit 64\nexit "$GATE_RESULT"\n')
            helper.chmod(0o700)
            native = root / "native"
            native.write_text('#!/bin/sh\ntest "$1" = activate-boot || exit 64\nprintf native > "$NATIVE_LOG"\nexit "$NATIVE_RESULT"\n')
            native.chmod(0o700)
            script = root / "S02apprecover"
            script.write_text(s02.replace("/usr/libexec/nanokvm-app-recovery", str(helper))
                              .replace("/usr/libexec/nanokvm-native-ctl", str(native)))
            for code in [0, 75, 78]:
                log = root / "native-log"
                log.unlink(missing_ok=True)
                result = subprocess.run(["/bin/sh", str(script), "start"],
                                        env={"GATE_RESULT": str(code), "NATIVE_RESULT": "0", "NATIVE_LOG": str(log)}, timeout=5)
                check("S02 propagates helper exit " + str(code), result.returncode == code)
                check("S02 native enrollment only after app gate " + str(code), log.exists() == (code == 0))
            for code in [75, 78]:
                result = subprocess.run(["/bin/sh", str(script), "start"],
                                        env={"GATE_RESULT": "0", "NATIVE_RESULT": str(code), "NATIVE_LOG": str(log)}, timeout=5)
                check("S02 propagates native boot failure " + str(code), result.returncode == code)
        sources["S02apprecover"] = s02
        del sources["S96picoclaw"]  # Optional service is not auto-installed/enabled.
        for kind in ["valid", "installed-mismatch", "missing-installed", "missing-marker", "inspection-error"]:
            check("rootfs gate " + kind, rootfs_gate(kind, sources))
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
