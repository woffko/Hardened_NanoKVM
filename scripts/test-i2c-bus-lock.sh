#!/usr/bin/env bash
# The shared LT6911 bus lock (L-B13), support/sg2002/additional/kvm/include/
# i2c_bus_lock.h: a holder excludes a contender for as long as the contender
# is willing to wait, a more patient contender gets the lock when the holder
# goes away, and a holder that exits without releasing leaves it free. Then
# the static part: every bus-4 user takes the lock, that is libkvm's detection
# poll, the EDID tool before it reads the chip, and S15kvmhwd's probes. An
# optional argument names another include directory (negative controls).
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
INCLUDE="${1:-$ROOT/support/sg2002/additional/kvm/include}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

fail() {
    echo "i2c bus lock test: $*" >&2
    exit 1
}

cc -std=gnu11 -Wall -Wextra -Werror -I "$INCLUDE" \
    "$ROOT/support/sg2002/kvm_vision_host_test/i2c_bus_lock_test.c" -o "$T/lock"
: > "$T/bus"

"$T/lock" try "$T/bus" 0 | grep -qx held || fail "a free lock was not taken"
"$T/lock" hold "$T/bus" 1500 > "$T/holder.out" &
holder=$!
sleep 0.3
grep -qx held "$T/holder.out" || fail "the holder did not take the lock"
start=$(date +%s%N)
if "$T/lock" try "$T/bus" 300 > "$T/try.out"; then
    fail "a contender got a held lock"
fi
grep -qx busy "$T/try.out" || fail "the refused contender did not say busy"
# "busy" already shows the contender gave up before the holder let go (at
# 1500 ms); the lower bound shows it did wait. No upper bound: host load.
elapsed=$(( ($(date +%s%N) - start) / 1000000 ))
[ "$elapsed" -ge 280 ] || fail "the contender gave up after ${elapsed} ms, before its 300 ms"
"$T/lock" try "$T/bus" 3000 | grep -qx held || fail "a patient contender did not get the lock after the holder exited"
wait "$holder"
"$T/lock" try "$T/bus" 0 | grep -qx held || fail "the lock stayed held after its holder exited"
echo "ok a held lock refuses a short wait, admits a longer one and dies with its holder"

VISION="$ROOT/support/sg2002/additional/kvm/src/kvm_vision.cpp"
[ "$(grep -c 'lt6911_enable();' "$VISION")" = "$(grep -c 'I2cBusLock bus;' "$VISION")" ] ||
    fail "libkvm enables the chip in a function without the bus lock"
awk '/^static void poll_lt6911/,/^}/' "$VISION" > "$T/poll"
grep -q 'I2cBusLock' "$T/poll" && grep -q 'lt6911_enable();' "$T/poll" && grep -q 'lt6911_disable();' "$T/poll" ||
    fail "libkvm's poll does not run the chip transaction under the bus lock"
echo "ok libkvm polls the chip only under the bus lock"

EDID="$ROOT/tools/nanokvm_update_edid/nanokvm_update_edid.c"
awk '/^int lt6911_edid_config/,/^}/' "$EDID" > "$T/config"
# A missing line is a finding, not a shell error (set -e, pipefail).
lock_line="$(grep -n 'bus_lock(client)' "$T/config" | head -n 1 | cut -d: -f1 || true)"
read_line="$(grep -n 'edid_read(' "$T/config" | head -n 1 | cut -d: -f1 || true)"
[ -n "$lock_line" ] && [ -n "$read_line" ] && [ "$lock_line" -lt "$read_line" ] ||
    fail "the EDID tool reads the chip before taking the bus lock"
echo "ok the EDID tool takes the bus lock before its first read"

S15="$ROOT/kvmapp/system/init.d/S15kvmhwd"
if grep -nE 'i2cdetect -ry 4' "$S15" | grep -v 'flock /dev/i2c-4 i2cdetect -ry 4'; then
    fail "S15kvmhwd probes bus 4 without the bus lock"
fi
grep -q 'flock /dev/i2c-4 i2cdetect -ry 4' "$S15" || fail "S15kvmhwd has no locked bus-4 probe"
echo "ok S15kvmhwd probes bus 4 under the bus lock"
echo "i2c bus lock test: PASS"
