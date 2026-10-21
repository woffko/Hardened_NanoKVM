#!/usr/bin/env python3
"""Bounded Pico shell/API routing checks; no device, root or real service calls."""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
CTL = "/usr/libexec/nanokvm-native-ctl"


def source(path, reference):
    if reference:
        return subprocess.run(
            ["git", "show", reference + ":" + path], cwd=ROOT,
            check=True, capture_output=True, text=True, timeout=10,
        ).stdout
    return (ROOT / path).read_text()


def function(body, name):
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}", body, re.M | re.S)
    return match[0] if match else ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref")
    args = parser.parse_args()
    shell = source("kvmapp/system/init.d/S96picoclaw", args.baseline_ref)
    api = source("server-rust/src/api/picoclaw.rs", args.baseline_ref)
    failures = 0
    checks = 0

    def check(label, good):
        nonlocal failures, checks
        checks += 1
        failures += not good
        print(("PASS" if good else "FAIL"), label)

    def fixed(body, name, operation):
        lines = [line.strip() for line in function(body, name).splitlines()[1:-1]
                 if line.strip() and not line.lstrip().startswith("#")]
        return lines == [CTL + " picoclaw-control-ready >/dev/null || return $?", CTL + " " + operation]

    safe = fixed(shell, "start_service", "ensure-picoclaw") and fixed(
        shell, "stop_service", "stop-picoclaw"
    ) and fixed(shell, "onboard_service", "onboard-picoclaw") and "killall" not in shell and "pidof" not in shell
    check("S96 start/stop/onboard are only fixed broker operations", safe)
    check("S96 never copies/removes a workspace or directly launches upstream",
          all(word not in shell for word in ["rm -", "cp -", "mkdir", "cd ", "BIN_PATH", "LOG_FILE", "setup_runtime_env"]))
    # Do not execute historical launcher/killall bodies on the host. Baseline
    # refusal is the negative result, not permission to try its unsafe fallback.
    if safe:
        with tempfile.TemporaryDirectory(prefix="nanokvm-pico-routing-") as temporary:
            root = Path(temporary)
            ctl, script, log, legacy = [root / name for name in ["ctl", "S96", "calls", "legacy"]]
            ctl.write_text(
                '#!/bin/sh\n[ "$#" -eq 1 ] || exit 64\n'
                'printf "%s\\n" "$1" >> "$CALLS"\n'
                '[ "$PWD" = "$EXPECTED_CWD" ] || exit 90\n'
                '[ "$PICOCLAW_HOME" = "relative custom home" ] || exit 91\n'
                'case "$1" in\n'
                ' picoclaw-control-ready) exit "$READY_RESULT" ;;\n'
                ' ensure-picoclaw) exit "$ENSURE_RESULT" ;;\n'
                ' stop-picoclaw) exit "$STOP_RESULT" ;;\n'
                ' onboard-picoclaw) exit "$ONBOARD_RESULT" ;;\n'
                ' *) exit 64 ;;\nesac\n'
            )
            ctl.chmod(0o700)
            legacy.write_text('#!/bin/sh\nprintf legacy >> "$CALLS"\nexit 92\n')
            legacy.chmod(0o700)
            script.write_text(shell.replace(CTL, str(ctl)))
            env = {
                "PATH": "/usr/bin:/bin", "CALLS": str(log),
                "EXPECTED_CWD": str(root), "PICOCLAW_HOME": "relative custom home",
                "PICOCLAW_BIN_PATH": str(legacy), "PICOCLAW_LOG_FILE": str(root / "unused-log"),
                "ENSURE_RESULT": "0", "STOP_RESULT": "0", "ONBOARD_RESULT": "0", "READY_RESULT": "0",
            }
            for action, variable, operation in [
                ("start", "ENSURE_RESULT", "ensure-picoclaw"),
                ("stop", "STOP_RESULT", "stop-picoclaw"),
                ("onboard", "ONBOARD_RESULT", "onboard-picoclaw"),
            ]:
                for code in [0, 1, 70, 71, 78, 130]:
                    log.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["/bin/sh", str(script), action], cwd=root,
                        env={**env, variable: str(code)}, capture_output=True, timeout=5,
                    )
                    check(action + " propagates broker exit " + str(code),
                          result.returncode == code and
                          log.read_text() == "picoclaw-control-ready\n" + operation + "\n")
            for stop, ensure, expected in [(0, 0, 0), (0, 71, 71), (71, 0, 71), (78, 0, 78)]:
                log.unlink(missing_ok=True)
                result = subprocess.run(
                    ["/bin/sh", str(script), "restart"], cwd=root,
                    env={**env, "STOP_RESULT": str(stop), "ENSURE_RESULT": str(ensure)},
                    capture_output=True, timeout=5,
                )
                calls = "picoclaw-control-ready\nstop-picoclaw\n" + (
                    "picoclaw-control-ready\nensure-picoclaw\n" if stop == 0 else "")
                check("restart retains stop-before-start " + str((stop, ensure)),
                      result.returncode == expected and log.read_text() == calls)
            for action in ["start", "stop", "onboard", "restart"]:
                for code in [64, 71, 78]:
                    log.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["/bin/sh", str(script), action], cwd=root,
                        env={**env, "READY_RESULT": str(code)}, capture_output=True, timeout=5,
                    )
                    check("unsupported/mismatched control refuses " + str((action, code)),
                          result.returncode == code and log.read_text() == "picoclaw-control-ready\n")
            for argv in [[], ["start", "extra"], ["stop", "extra"], ["onboard", "extra"], ["restart", "extra"], ["invalid"]]:
                log.unlink(missing_ok=True)
                result = subprocess.run(
                    ["/bin/sh", str(script), *argv], cwd=root,
                    env=env, capture_output=True, timeout=5,
                )
                check("invalid argv makes no native call " + str(argv),
                      result.returncode != 0 and not log.exists())
            script.write_text(shell.replace(CTL, str(root / "missing-helper")))
            for action in ["start", "stop", "onboard", "restart"]:
                log.unlink(missing_ok=True)
                result = subprocess.run(
                    ["/bin/sh", str(script), action], cwd=root,
                    env=env, capture_output=True, timeout=5,
                )
                check("missing helper has no legacy fallback " + action,
                      result.returncode != 0 and not log.exists())
            check("service control never creates home or opens gateway log",
                  not (root / "relative custom home").exists() and not (root / "unused-log").exists())

    start = api.split("async fn start_runtime_inner()", 1)[-1].split("async fn stop_runtime_inner()", 1)[0]
    compact_start = re.sub(r"\s+", "", start)
    stop = api.split("async fn stop_runtime_inner()", 1)[-1].split("async fn run_install_runtime()", 1)[0]
    control = api.split("async fn run_native_control(", 1)[-1].split("async fn run_script(", 1)[0]
    preflight = api.split("async fn native_control_ready()", 1)[-1].split("async fn run_native_control(", 1)[0]
    check("API start preflights current helpers/boot before changing defaults",
          "native_control_ready().await" in compact_start and
          compact_start.index("native_control_ready().await") < compact_start.index("ensure_startup_defaults()") and
          "run_native_control(PicoControl::Ensure, support)" in start and 'run_script("start"' not in start)
    check("API Stop uses owned completion without killall/sleep/script selection",
          "run_native_control(PicoControl::Stop, support)" in stop and
          'run_script("stop"' not in stop and "sleep(" not in stop and "killall" not in api)
    check("API native preflight retains exact current support and fresh boot proof",
          "ProcessLock::acquire()" in preflight and "native_bootstrap::check_installed()" in preflight and
          "boot::require_ready()" in preflight and "spawn_blocking" in preflight)
    check("API preflight admits before queuing any blocking work",
          "ProcessLock::acquire()" in preflight and "spawn_blocking" in preflight and
          preflight.index("ProcessLock::acquire()") < preflight.index("spawn_blocking") and
          "let _admission = admission;" in preflight)
    check("API fixed helper owns boot proof and checks actual exit status",
          "AllowedCommand::NativePicoclawControl" in control and "run_allowed_owned(" in control and
          "support," in control and "output.status == 0" in control)
    onboard = api.split("async fn onboard_runtime_config()", 1)[-1].split("fn resolve_config_path()", 1)[0]
    check("API onboarding uses native completion without holding Config or selecting a shell",
          "native_control_ready().await?" in onboard and
          "run_native_control(PicoControl::Onboard, support).await?" in onboard and
          "load_config_document()" in onboard and ".configuration()" not in onboard and
          "async fn run_script(" not in api)
    uninstall = api.split("pub async fn uninstall_runtime()", 1)[-1].split("pub async fn get_runtime_session()", 1)[0]
    check("uninstall does not delete after an unverified Stop",
          "if let Err(err) = stop_runtime_inner().await" in uninstall and
          uninstall.index("if let Err(err) = stop_runtime_inner().await") < uninstall.index("fs::remove_dir_all"))
    print(f"{checks} checks; {failures} failures")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
