#!/usr/bin/env bash
# Builds nanokvm_update_edid for the host against a model of the LT6911UXC
# (tools/nanokvm_update_edid/test-fake-bus.c) and checks that the tool never
# erases a chip that does not return an EDID, saves the current EDID first,
# and writes it back when the new one does not verify. No hardware is used.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TOOL="$ROOT_DIR/tools/nanokvm_update_edid"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() {
    echo "nanokvm_update_edid test: $*" >&2
    exit 1
}

printf 'ux\n' > "$TEST_ROOT/hdmi_version"
printf 'beta\n' > "$TEST_ROOT/hw"
build() {
    cc -Wall -Wextra -Werror -DEDID_FAKE_BUS -I "$ROOT_DIR/support/sg2002/additional/kvm/include" \
        -DVERSION_PATH="\"$TEST_ROOT/hdmi_version\"" -DPRODUCT_PATH="\"$TEST_ROOT/hw\"" \
        -DEDID_BACKUP_DIR="\"$2\"" -o "$1" "$TOOL/nanokvm_update_edid.c" "$TOOL/test-fake-bus.c"
}
build "$TEST_ROOT/tool" "$TEST_ROOT/backup"
build "$TEST_ROOT/tool-no-backup" "$TEST_ROOT/missing"

# The new EDID ships with the tool; the old one differs in its product code.
NEW="$TOOL/E21_NanoKVM.bin"
OLD="$TEST_ROOT/old.bin"
python3 -I - "$NEW" "$OLD" <<'PY'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
data[10] ^= 0x01
data[127] = (-sum(data[:127])) % 256
open(sys.argv[2], "wb").write(data)
PY

# run TOOL NAME [VAR=VALUE...]: one tool run against a fresh model.
run() {
    tool="$1"
    name="$2"
    shift 2
    rm -rf "$TEST_ROOT/backup" "$TEST_ROOT/$name".*
    mkdir -p "$TEST_ROOT/backup"
    status=0
    printf 'y\n' | env "$@" FAKE_FLASH_OUT="$TEST_ROOT/$name.flash" FAKE_LOG="$TEST_ROOT/$name.log" \
        "$tool" "$NEW" > "$TEST_ROOT/$name.out" 2>&1 || status=$?
    touch "$TEST_ROOT/$name.log"
}

backups() {
    find "$TEST_ROOT/backup" -type f | wc -l
}

# 1. An update saves the current EDID, then writes and verifies the new one.
run "$TEST_ROOT/tool" update FAKE_FLASH="$OLD"
[ "$status" = 0 ] || fail "update failed: $(cat "$TEST_ROOT/update.out")"
cmp -s "$TEST_ROOT/update.flash" "$NEW" || fail "the chip does not hold the new EDID"
[ "$(backups)" = 1 ] || fail "expected one backup, found $(backups)"
cmp -s "$(find "$TEST_ROOT/backup" -type f)" "$OLD" || fail "the backup is not the previous EDID"

# 2. A chip that does not return an EDID, as a wrong chip version would, is
# never erased or programmed.
run "$TEST_ROOT/tool" garbage FAKE_FLASH="$OLD" FAKE_GARBAGE=1
[ "$status" != 0 ] || fail "a chip without an EDID was accepted"
! grep -q -e '^erase' -e '^program' "$TEST_ROOT/garbage.log" || fail "a chip without an EDID was erased"
cmp -s "$TEST_ROOT/garbage.flash" "$OLD" || fail "the chip changed"
[ "$(backups)" = 0 ] || fail "a backup was saved for a chip without an EDID"

# 3. An erased chip, as after an interrupted update, can be written again.
run "$TEST_ROOT/tool" blank
[ "$status" = 0 ] || fail "an erased chip could not be written: $(cat "$TEST_ROOT/blank.out")"
cmp -s "$TEST_ROOT/blank.flash" "$NEW" || fail "the erased chip does not hold the new EDID"

# 4. A write that fails after the erase puts the previous EDID back.
run "$TEST_ROOT/tool" interrupted FAKE_FLASH="$OLD" FAKE_FAIL_AFTER_ERASE=12
[ "$status" != 0 ] || fail "a failed write was reported as success"
grep -q '^fail' "$TEST_ROOT/interrupted.log" || fail "the injected failure did not happen"
grep -q 'The previous EDID is restored' "$TEST_ROOT/interrupted.out" ||
    fail "no restore reported: $(cat "$TEST_ROOT/interrupted.out")"
cmp -s "$TEST_ROOT/interrupted.flash" "$OLD" || fail "the previous EDID was not restored"

# 5. Without a place for the backup nothing is erased.
run "$TEST_ROOT/tool-no-backup" no-backup FAKE_FLASH="$OLD"
[ "$status" != 0 ] || fail "an update without a backup was accepted"
! grep -q -e '^erase' -e '^program' "$TEST_ROOT/no-backup.log" || fail "the chip was erased without a backup"
cmp -s "$TEST_ROOT/no-backup.flash" "$OLD" || fail "the chip changed without a backup"

# 6. A bus held by another process (libkvm polling the chip) stops the tool
# before it reads or erases anything; once the bus is free, the update runs.
flock -x "$TEST_ROOT/bus.lock" sleep 2 &
holder=$!
sleep 0.2
run "$TEST_ROOT/tool" busy FAKE_FLASH="$OLD" FAKE_LOCK="$TEST_ROOT/bus.lock"
[ "$status" != 0 ] || fail "an update on a busy bus was accepted"
[ ! -s "$TEST_ROOT/busy.log" ] || fail "the busy bus was touched: $(cat "$TEST_ROOT/busy.log")"
grep -q 'I2C bus is in use' "$TEST_ROOT/busy.out" || fail "no busy message: $(cat "$TEST_ROOT/busy.out")"
[ "$(backups)" = 0 ] || fail "a backup was saved on a busy bus"
wait "$holder"
run "$TEST_ROOT/tool" freed FAKE_FLASH="$OLD" FAKE_LOCK="$TEST_ROOT/bus.lock"
[ "$status" = 0 ] || fail "the update after the bus was freed failed: $(cat "$TEST_ROOT/freed.out")"
cmp -s "$TEST_ROOT/freed.flash" "$NEW" || fail "the chip does not hold the new EDID after the bus was freed"

echo "nanokvm_update_edid: PASS"
