#!/usr/bin/env python3
"""Exercise the real CLI in a private PID/mount/user namespace; no host signals."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CTL = ROOT / 'server-rust/target/debug/nanokvm-native-ctl'
if sys.argv[1:] != ['--inside']:
    raise SystemExit(subprocess.call(['unshare', '--user', '--map-root-user', '--mount',
                                     '--pid', '--fork', '--mount-proc',
                                     sys.executable, __file__, '--inside']))
subprocess.run(['mount', '--make-rprivate', '/'], check=True)
with tempfile.TemporaryDirectory(prefix='watchdog-cli-') as directory:
    root = Path(directory)
    for target in ('/run', '/tmp', '/etc/init.d'):
        private = root / target[1:]
        private.mkdir(mode=0o700, parents=True)
        subprocess.run(['mount', '--bind', str(private), target], check=True)
    children = []
    def call(action, role='runtime', pid=None, expected=0):
        args = [str(CTL), '--watchdog', action, role]
        if pid is not None:
            args.append(str(pid))
        result = subprocess.run(args, capture_output=True, text=True, timeout=6)
        assert result.returncode == expected, (args, result.returncode, result.stderr)
        return result.stdout.strip()
    try:
        call('status', expected=3)
        # The child must call owned itself: its parent identity is what is checked.
        child = subprocess.Popen(['/bin/sh', '-c',
            'while ! "$1" --watchdog owned runtime >/dev/null 2>&1; do sleep 0.05; done; '
            'echo admitted > /run/admitted; exec sleep 60', 'fixture', str(CTL)])
        children.append(child)
        time.sleep(0.1)
        assert not Path('/run/admitted').exists()
        call('record', pid=child.pid)
        assert call('status') == str(child.pid)
        deadline = time.monotonic() + 3
        while not Path('/run/admitted').exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert Path('/run/admitted').exists(), 'registered child was not admitted'
        unrelated = subprocess.Popen(['sleep', '60'])
        children.append(unrelated)
        call('record', pid=unrelated.pid, expected=70)
        call('owned', expected=3)
        call('stop')
        child.wait(timeout=3)
        assert unrelated.poll() is None
        call('status', expected=3)
        assert not Path('/run/nanokvm-watchdog.pid').exists()
        call('discard', pid=unrelated.pid)
        unrelated.wait(timeout=3)
        # Historical S95 subshells retain the script argv and become children
        # of PID 1. This fixture runs as PID 1 in its private namespace.
        assert os.getpid() == 1
        legacy_script = Path('/etc/init.d/S95nanokvm')
        legacy_script.write_text('while true; do sleep 1; done\n')
        legacy = subprocess.Popen(['/bin/sh', str(legacy_script), 'start'])
        children.append(legacy)
        legacy_record = Path('/tmp/nanokvm-watchdog.pid')
        legacy_record.write_text(str(legacy.pid) + '\n')
        legacy_record.chmod(0o600)
        assert call('status') == str(legacy.pid)
        call('stop')
        legacy.wait(timeout=3)
        assert not legacy_record.exists()
        other = subprocess.Popen(['sleep', '60'])
        children.append(other)
        legacy_record.write_text(str(other.pid) + '\n')
        legacy_record.chmod(0o600)
        call('status', expected=3)
        call('stop')
        assert other.poll() is None, 'legacy text authorized an unrelated process'
        assert legacy_record.exists(), 'unrecognized legacy evidence removed'
        # A malformed record is an error, not admission to launch another watchdog.
        path = Path('/run/nanokvm-watchdog.pid')
        path.write_text('v1 1 1 invalid\n')
        path.chmod(0o600)
        call('status', expected=70)
        call('stop', expected=70)
        assert path.exists()
        print('watchdog CLI: registration, ownership, stop, discard, refusal PASS')
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait()
        for target in ('/etc/init.d', '/tmp', '/run'):
            subprocess.run(['umount', target], check=True)
