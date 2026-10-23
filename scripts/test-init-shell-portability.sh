#!/usr/bin/env bash
# The init scripts run under BusyBox ash. Bash's `cmd &>file` is not POSIX: a
# shell without bash compatibility reads it as `cmd &` plus an empty redirect
# and goes on without waiting (S30eth's DHCP wait depended on that option,
# L-B10). Every init script must parse under sh and BusyBox sh and use no `&>`.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
INIT="$ROOT_DIR/kvmapp/system/init.d"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() {
    echo "init shell portability: $*" >&2
    exit 1
}

count=0
for script in "$INIT"/*; do
    [ -f "$script" ] || continue
    name="${script##*/}"
    if grep -nE '(^|[^&])&>' "$script"; then
        fail "$name uses the bash-only &> redirect"
    fi
    sh -n "$script" || fail "$name does not parse under sh"
    if command -v busybox >/dev/null 2>&1; then
        busybox sh -n "$script" || fail "$name does not parse under BusyBox sh"
    fi
    count=$((count + 1))
done
[ "$count" -gt 0 ] || fail "no init scripts found"

# What `&>` does depends on the shell build: POSIX sh (dash) runs the command
# in the background; BusyBox ash with ASH_BASH_COMPAT waits, as bash does. The
# device's BusyBox 1.38.0 has that option. Measure and report; the fix above
# removes the dependency either way.
cat > "$TEST_ROOT/slow" <<'SLOW'
#!/bin/sh
sleep 1
: > "$MARKER"
SLOW
chmod +x "$TEST_ROOT/slow"
for shell in sh "busybox sh"; do
    [ "$shell" = sh ] || command -v busybox >/dev/null 2>&1 || continue
    rm -f "$TEST_ROOT/marker"
    if MARKER="$TEST_ROOT/marker" $shell -c "'$TEST_ROOT/slow' &>/dev/null; test -e '$TEST_ROOT/marker'"; then
        echo "note: $shell waits for a &> command (bash-compatible build)"
    else
        echo "note: $shell backgrounds a &> command"
        sleep 1.2
    fi
done
echo "init shell portability ($count scripts): PASS"
