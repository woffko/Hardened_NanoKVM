#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail() { echo "raw-restore-policy: $*" >&2; exit 1; }
SCRIPT="$ROOT/support/sg2002/raw/S01restore"
BUNDLE="$ROOT/scripts/create-raw-system-update-bundle.sh"
RUST="$ROOT/server-rust/src/update/raw_restore.rs"

[ -x "$SCRIPT" ] || fail "S01restore is missing or not executable"
grep -Fq 'nanokvm-early-restore' "$SCRIPT" || fail "S01restore does not call the early helper"
grep -Fq 'nanokvm-restore-blocked' "$SCRIPT" || fail "S01restore does not block on failure"
grep -Fq 'NANOKVM_EARLY_RESTORE_BIN' "$BUNDLE" || fail "bundle does not require the early helper"
grep -Fq 'raw-restore-required' "$BUNDLE" || fail "bundle does not write the discriminator"
grep -Fq 'nanokvm-raw-restore-required-v1' "$BUNDLE" "$RUST" || fail "discriminator bytes are not fixed"
grep -Fq 'raw-restore-required' "$RUST" || fail "early helper does not read the discriminator"
for name in S02apprecover S03usbdev S30eth S30wifi S40firewall S49ntp S50sshd S95nanokvm; do
	path="$ROOT/kvmapp/system/init.d/$name"
	[ -f "$path" ] || fail "missing consumer script $name"
	grep -Fq '/run/nanokvm-restore-blocked' "$path" || fail "$name does not honor the restore block"
done
echo "raw restore policy: PASS"
