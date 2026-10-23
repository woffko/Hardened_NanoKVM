#!/usr/bin/env bash
# The S95 update watchdog confirms a pending system update that needs a reboot
# only in a boot after its install. The functions are taken from S95nanokvm
# itself and run under the host's sh and, when present, BusyBox sh, against
# temporary pending records and this host's real boot ID.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
S95="$ROOT_DIR/kvmapp/system/init.d/S95nanokvm"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() {
    echo "S95 boot health test: $*" >&2
    exit 1
}

# Copy the named top-level functions out of S95.
for name in json_string_value pending_update_file system_update_booted_since_install; do
    awk -v start="$name() {" '$0 == start {p = 1} p {print} p && $0 == "}" {exit}' "$S95" >> "$TEST_ROOT/lib.sh"
    grep -qx "$name() {" "$TEST_ROOT/lib.sh" || fail "no function $name in S95nanokvm"
done
awk '$0 == "system_update_boot_healthy() {" {p = 1} p {print} p && $0 == "}" {exit}' "$S95" |
    grep -qx '    system_update_booted_since_install || return 1' ||
    fail "system_update_boot_healthy does not check the boot"

current="$(cat /proc/sys/kernel/random/boot_id)"
other="0f8c6f4e-6b9b-4f0e-9a51-6c1f0d6f7a10"
[ "$current" != "$other" ] || fail "the fixed test boot ID is this boot"

shells="sh"
command -v busybox >/dev/null 2>&1 && shells="sh busybox"

# expect STATUS JSON: write the pending record (or none) and check the result.
expect() {
    for shell in $shells; do
        rm -f "$TEST_ROOT/pending.json"
        [ "$2" = none ] || printf '%s\n' "$2" > "$TEST_ROOT/pending.json"
        status=0
        if [ "$shell" = busybox ]; then
            SYSTEM_PENDING_FILE="$TEST_ROOT/pending.json" busybox sh -c ". '$TEST_ROOT/lib.sh'; system_update_booted_since_install" || status=$?
        else
            SYSTEM_PENDING_FILE="$TEST_ROOT/pending.json" sh -c ". '$TEST_ROOT/lib.sh'; system_update_booted_since_install" || status=$?
        fi
        [ "$status" = "$1" ] || fail "$shell: expected $1, got $status for $2"
    done
}

record() {
    printf '{\n  "version": "0.1.0",\n  "target": "sg2002-licheervnano-sd",\n  "backupId": "0.1.0-1",\n  "installedAt": 1,\n  "requiresReboot": %s,\n  "fileCount": 1%s\n}' "$1" "$2"
}

# Installed in this boot: not yet.
expect 1 "$(record true ",
  \"installBootId\": \"$current\"")"
# Installed in another boot: yes.
expect 0 "$(record true ",
  \"installBootId\": \"$other\"")"
# No reboot needed: the install boot is enough.
expect 0 "$(record false ",
  \"installBootId\": \"$current\"")"
# A record from an older backend has no boot ID: unchanged behavior.
expect 0 "$(record true "")"
# No pending record at all.
expect 1 none

echo "S95 boot health: PASS ($shells)"
