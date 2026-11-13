#!/usr/bin/env bash
# Check the actual S95/helper boundary; identity and signal safety are tested in Rust.
set -euo pipefail
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
for name in await_watchdog_registration register_watchdog stop_watchdog stop_system_update_watchdog; do
    awk -v start="$name() {" '$0 == start {p=1} p {print} p && $0 == "}" {exit}' "$ROOT_DIR/kvmapp/system/init.d/S95nanokvm" >> "$T/lib.sh"
done
cat > "$T/check.sh" <<'CHECK'
set -eu
. "$TEST_DIR/lib.sh"
NATIVE_CTL=helper
helper() {
    printf '%s\n' "$*" >> "$TEST_DIR/calls"
    case "$2" in
        record) return "$RECORD_RESULT" ;;
        discard) return 0 ;;
        stop) return "$STOP_RESULT" ;;
        owned) return "$OWNED_RESULT" ;;
        *) return 99 ;;
    esac
}
sleep() { :; }
RECORD_RESULT=0 STOP_RESULT=0 OWNED_RESULT=0
: > "$TEST_DIR/calls"
register_watchdog runtime 999999
[ "$(cat "$TEST_DIR/calls")" = '--watchdog record runtime 999999' ]
RECORD_RESULT=70
: > "$TEST_DIR/calls"
if register_watchdog update 999999; then exit 1; fi
[ "$(cat "$TEST_DIR/calls")" = "--watchdog record update 999999
--watchdog discard update 999999" ]
stop_watchdog
stop_system_update_watchdog
STOP_RESULT=70
if stop_watchdog; then exit 1; fi
if stop_system_update_watchdog; then exit 1; fi
await_watchdog_registration runtime
OWNED_RESULT=3
: > "$TEST_DIR/calls"
if await_watchdog_registration runtime; then exit 1; fi
[ "$(wc -l < "$TEST_DIR/calls")" -eq 10 ]
OWNED_RESULT=70
if await_watchdog_registration update; then exit 1; fi
CHECK
TEST_DIR="$T" sh "$T/check.sh"
if command -v busybox >/dev/null 2>&1; then
    TEST_DIR="$T" busybox sh "$T/check.sh"
fi
if rg -n 'kill .*\$.*pid|read_pid_file|stop_pid_file|/tmp/.*watchdog.pid' "$ROOT_DIR/kvmapp/system/init.d/S95nanokvm"; then
    echo 'unsafe legacy PID operation remains' >&2
    exit 1
fi
echo 'S95 watchdog helper boundary: PASS (sh and available BusyBox)'
