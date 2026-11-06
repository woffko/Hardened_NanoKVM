#!/usr/bin/env bash
# stop_pid_file, taken from S95nanokvm and run under the host's sh and, when
# present, BusyBox sh. Any account can create a file in /tmp, and the PID that a
# PID file names is killed. So only a regular file owned by the caller (root on
# the device) counts: not a link, and not another account's file.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
S95="$ROOT_DIR/kvmapp/system/init.d/S95nanokvm"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fail() {
    echo "S95 PID file test: $*" >&2
    exit 1
}

awk '$0 == "stop_pid_file() {" {p = 1} p {print} p && $0 == "}" {exit}' "$S95" > "$T/lib.sh"
grep -qx 'stop_pid_file() {' "$T/lib.sh" || fail "no stop_pid_file in S95nanokvm"
# A function named kill stands in for the builtin and records the calls.
printf 'kill() { echo "kill $*" >> "%s/calls"; }\n' "$T" >> "$T/lib.sh"
foreign=""
for candidate in /etc/passwd /etc/hostname /etc/hosts; do
    if [ -f "$candidate" ] && [ ! -O "$candidate" ]; then foreign="$candidate"; break; fi
done
[ -n "$foreign" ] || fail "no file of another account to test with"

shells="sh"
command -v busybox >/dev/null 2>&1 && shells="sh busybox"
for shell in $shells; do
    run() {
        : > "$T/calls"
        $([ "$shell" = busybox ] && echo busybox) sh -c ". '$T/lib.sh'; stop_pid_file '$1'"
    }
    echo 4242 > "$T/own.pid"
    run "$T/own.pid"
    [ "$(cat "$T/calls")" = "kill 4242" ] || fail "$shell: an own PID file was not used: $(cat "$T/calls")"
    [ ! -e "$T/own.pid" ] || fail "$shell: an own PID file stayed"

    echo 1 > "$T/target"
    ln -sf "$T/target" "$T/link.pid"
    run "$T/link.pid"
    [ ! -s "$T/calls" ] || fail "$shell: a linked PID file was used: $(cat "$T/calls")"

    run "$foreign"
    [ ! -s "$T/calls" ] || fail "$shell: another account's file was used: $(cat "$T/calls")"
    echo "ok $shell: only an own regular PID file is used"
done
echo "S95 PID files: PASS"
