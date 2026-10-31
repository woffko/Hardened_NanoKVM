#!/usr/bin/env bash
# support/sg2002/raw/S01restore with its fixed paths moved into a temporary
# directory. Only a clean exit of the early helper may let the boot continue:
# the helper writes the block marker for the errors it returns, and the script
# has to write it when the helper was killed or could not run at all.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
SCRIPT="$ROOT/support/sg2002/raw/S01restore"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
sed -e "s#/run/nanokvm-restore-blocked#$T/blocked#g" \
    -e "s#/etc/hostname#$T/hostname#g" \
    -e "s#/usr/libexec/nanokvm-early-restore#$T/helper#g" "$SCRIPT" > "$T/S01restore"
mkdir "$T/bin"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" > "%s/named"\nexit "${HOSTNAME_EXIT:-0}"\n' "$T" > "$T/bin/hostname"
chmod 0755 "$T/bin/hostname"
export PATH="$T/bin:$PATH"

helper() {
    printf '#!/bin/sh\n%s\n' "$1" > "$T/helper"
    chmod 0755 "$T/helper"
}
run() {
    local code=0
    sh "$T/S01restore" >/dev/null 2>&1 || code=$?
    echo "$code"
}
fail() {
    echo "S01restore test: $*" >&2
    exit 1
}

helper 'exit 0'
[ "$(run)" = 0 ] || fail "a clean helper must let the boot continue"
[ ! -e "$T/blocked" ] || fail "a clean helper must not block"
[ "$(cat "$T/named")" = "-F $T/hostname" ] || fail "the restored name must reach the kernel"
rm "$T/named"
export HOSTNAME_EXIT=1
[ "$(run)" = 0 ] || fail "a name that cannot be set must not stop the boot"
unset HOSTNAME_EXIT
rm "$T/named"

helper 'exit 78'
[ "$(run)" != 0 ] || fail "a refusing helper must stop the script"
[ -e "$T/blocked" ] || fail "a refusing helper must leave the marker"
[ "$(stat -c %a "$T/blocked")" = 600 ] || fail "the marker must be private"
[ ! -e "$T/named" ] || fail "a blocked boot must not rename the system"
rm "$T/blocked"

helper 'kill -ABRT $$'
[ "$(run)" != 0 ] || fail "an aborted helper must stop the script"
[ -e "$T/blocked" ] || fail "an aborted helper must leave the marker"
rm "$T/blocked"

helper 'kill -KILL $$'
[ "$(run)" != 0 ] || fail "a killed helper must stop the script"
[ -e "$T/blocked" ] || fail "a killed helper must leave the marker"
rm "$T/blocked"

rm "$T/helper"
[ "$(run)" != 0 ] || fail "a missing helper must stop the script"
[ -e "$T/blocked" ] || fail "a missing helper must leave the marker"

helper 'touch "$0.ran"'
[ "$(run)" != 0 ] || fail "an existing marker must stop the script"
[ ! -e "$T/helper.ran" ] || fail "an existing marker must not run the helper"

echo "S01restore test: PASS"
