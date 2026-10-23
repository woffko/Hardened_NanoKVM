#!/usr/bin/env python3
"""Bounded current-S95 function fixtures. No host root or actual native binary."""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = (ROOT / "kvmapp/system/init.d/S95nanokvm").read_text()


def function(name):
    found = re.search(r"^" + name + r"\(\) \{\n.*?^\}", SOURCE, re.M | re.S)
    if not found:
        raise ValueError(name)
    return found[0]


class NativeInitTests(unittest.TestCase):
    def run_function(self, name, mode):
        with tempfile.TemporaryDirectory(prefix="nanokvm-native-init-") as temporary:
            root = Path(temporary)
            calls = root / "calls"
            ctl = root / "ctl"
            ctl.write_text('''#!/bin/sh
echo "ctl:$1" >> "$CALLS"
case "$1:$MODE" in
 boot-ready:unready) exit 78 ;;
 status:absent|running:absent|ensure-kvm:denied|ensure-backend:denied|restart-backend:denied|restart-backend-safe:denied|shutdown:denied) exit 1 ;;
 running:paused) exit 1 ;;
esac
exit 0
''')
            broker = root / "broker"
            broker.write_text('#!/bin/sh\necho "broker:$1" >> "$CALLS"\n')
            app = root / "app"
            app.write_text('#!/bin/sh\necho "app:$1" >> "$CALLS"\n')
            for path in [ctl, broker, app]: path.chmod(0o700)
            prefix = '\n'.join([
                'NATIVE_CTL=' + shlex.quote(str(ctl)), 'NATIVE_BROKER=' + shlex.quote(str(broker)),
                'NATIVE_LOG=' + shlex.quote(str(root / "native.log")),
                'runtime_log() { :; }', 'sleep() { :; }', 'prepare_native_log() { :; }',
                'stop_system_update_watchdog() { echo stop-update-watchdog >> "$CALLS"; }',
                'stop_watchdog() { echo stop-watchdog >> "$CALLS"; }',
                'rm() { echo cleanup >> "$CALLS"; }',
            ])
            body = function(name).replace("/usr/libexec/nanokvm-app-recovery", str(app))
            result = subprocess.run(["/bin/sh", "-c", prefix + '\n' + body + '\n' + name
                                     + '\nresult=$?\nwait\nexit "$result"\n'],
                                    env={"PATH": os.environ["PATH"], "MODE": mode, "CALLS": str(calls)},
                                    capture_output=True, text=True, timeout=5)
            return result.returncode, calls.read_text().splitlines() if calls.exists() else []

    def test_legacy_unready_does_not_launch_or_adopt(self):
        code, calls = self.run_function("start_native_broker", "unready")
        self.assertNotEqual(code, 0)
        self.assertEqual(calls, ["ctl:boot-ready"])

    def test_existing_running_daemon_reused_but_pause_is_not_bypassed(self):
        for mode in ["running", "paused"]:
            code, calls = self.run_function("start_native_broker", mode)
            self.assertEqual(code == 0, mode == "running")
            self.assertEqual(calls, ["ctl:boot-ready", "ctl:status", "ctl:running"])

    def test_failed_launch_is_submitted_once_without_kill_or_socket_cleanup(self):
        code, calls = self.run_function("start_native_broker", "absent")
        self.assertNotEqual(code, 0)
        self.assertEqual(calls.count("broker:--serve"), 1)
        self.assertNotIn("cleanup", calls)

    def test_native_start_has_no_direct_fallback_when_ensure_denied(self):
        code, calls = self.run_function("start_kvm_system_runtime", "denied")
        self.assertNotEqual(code, 0)
        self.assertEqual(calls, ["app:gate", "ctl:ensure-kvm"])

    def test_stop_requires_boot_and_durable_closure_before_watchdog_cleanup(self):
        code, calls = self.run_function("stop_runtime", "unready")
        self.assertNotEqual(code, 0)
        self.assertEqual(calls, ["ctl:boot-ready"])
        code, calls = self.run_function("stop_runtime", "denied")
        self.assertNotEqual(code, 0)
        self.assertEqual(calls, ["ctl:boot-ready", "ctl:shutdown"])
        code, calls = self.run_function("stop_runtime", "running")
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["ctl:boot-ready", "ctl:shutdown", "stop-update-watchdog", "stop-watchdog"])

    def test_backend_start_and_restarts_have_no_denial_fallback(self):
        for name, operation in [("start_server_runtime", "ensure-backend"),
                                ("restart_server_runtime", "restart-backend"),
                                ("restart_server_safe", "restart-backend-safe")]:
            for mode in ["denied", "running"]:
                with self.subTest(name=name, mode=mode):
                    code, calls = self.run_function(name, mode)
                    self.assertEqual(code == 0, mode == "running")
                    self.assertEqual(calls, ["app:gate", "ctl:" + operation])

    def test_no_native_pid_adoption_or_direct_launch_remains(self):
        for forbidden in ["find_kvm_system_pids", "adopt_single_kvm_system_process", "KVM_SYSTEM_PID_FILE",
                          "KVM_SYSTEM_RUNTIME_DIR", "HWMON_PID_FILE", "killall nanokvm-hwmon",
                          "SERVER_PID_FILE", "SERVER_RUNTIME_DIR", "stop_server_process",
                          "killall NanoKVM-Server", "NANOKVM_XTHEAD_LOADER", "wait_process_exit"]:
            self.assertNotIn(forbidden, SOURCE)
        self.assertIn('exec "$NATIVE_CTL" ensure-hwmon', function("start_hwmon_shadow"))
        self.assertIn('"$NATIVE_CTL" ensure-kvm', function("start_kvm_system_runtime"))


if __name__ == "__main__":
    unittest.main()
