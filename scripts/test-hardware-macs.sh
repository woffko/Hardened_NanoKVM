#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
INIT_D="$ROOT_DIR/kvmapp/system/init.d"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

export S30ETH_TEST_ONLY=1
export S03USBDEV_TEST_ONLY=1
export S03USBHID_TEST_ONLY=1
export BASE_UID_FILE="$TEST_ROOT/base_uid"

# The device has sha256sum; macOS only has shasum.
command -v sha256sum >/dev/null 2>&1 || sha256sum() { shasum -a 256; }

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

expect() {
    [ "$2" = "$3" ] || fail "$1: got '$2', want '$3'"
}

reset_inputs() {
    rm -f "$BASE_UID_FILE"
}

# Chip ID and the MACs a real unit (usb0 verified on hardware) gets from it.
UID_FILE_TEXT="UID: e5ca04be_1519c372"
SEED=e5ca04be1519c372

for script in S30eth S03usbdev S03usbhid; do
    # shellcheck source=/dev/null
    . "$INIT_D/$script"

    reset_inputs
    expect "$script: no chip ID" "$(hw_mac_seed)" ""

    # Same value as /device_key on this unit, so MACs derived from it do not change.
    echo "$UID_FILE_TEXT" > "$BASE_UID_FILE"
    expect "$script: base_uid seed" "$(hw_mac_seed)" "$SEED"

    # The USB serial hides the chip ID and falls back to the old constant without one.
    if [ "$script" != S30eth ]; then
        expect "$script: usb serial" "$(make_usb_serial "$SEED")" "425AF29F923BF04D"
        expect "$script: usb serial, other chip" "$(make_usb_serial 0011223344556677)" "B7E30C87D12950CB"
        expect "$script: usb serial from base_uid" "$(usb_serial)" "425AF29F923BF04D"
        reset_inputs
        expect "$script: usb serial without a chip ID" "$(usb_serial)" "0123456789ABCDEF"
    fi

    # A bad chip ID must give no seed rather than one shared by all units.
    reset_inputs
    echo "garbage" > "$BASE_UID_FILE"
    expect "$script: base_uid without a value" "$(hw_mac_seed)" ""
    echo "UID: xyz_xyz" > "$BASE_UID_FILE"
    expect "$script: non-hex base_uid" "$(hw_mac_seed)" ""
done

# shellcheck source=/dev/null
. "$INIT_D/S30eth"
expect "eth0 mac" "$(make_eth_mac "$SEED")" "02:2d:b1:aa:9f:ec"
expect "eth0 mac, other chip" "$(make_eth_mac 0011223344556677)" "02:00:ef:11:be:bc"

# shellcheck source=/dev/null
. "$INIT_D/S03usbdev"
expect "rndis dev mac" "$(make_usb_mac 02 functions/rndis.usb0-dev "$SEED")" "02:b5:bd:b4:79:71"
expect "rndis host mac" "$(make_usb_mac 06 functions/rndis.usb0-host "$SEED")" "06:84:86:ea:56:ee"
expect "ncm dev mac" "$(make_usb_mac 02 functions/ncm.usb0-dev "$SEED")" "02:f7:5c:ad:de:03"
expect "ncm host mac" "$(make_usb_mac 06 functions/ncm.usb0-host "$SEED")" "06:12:a5:ec:95:3e"

# set_usb_function_macs writes the files only when a seed exists.
FUNC="$TEST_ROOT/functions/rndis.usb0"
mkdir -p "$FUNC"
touch "$FUNC/dev_addr" "$FUNC/host_addr"
reset_inputs
set_usb_function_macs "$FUNC" 2>/dev/null
[ ! -s "$FUNC/dev_addr" ] || fail "USB MAC written without a seed"
echo "$UID_FILE_TEXT" > "$BASE_UID_FILE"
set_usb_function_macs "$FUNC"
expect "dev_addr file" "$(cat "$FUNC/dev_addr")" "$(make_usb_mac 02 "$FUNC-dev" "$SEED")"
expect "host_addr file" "$(cat "$FUNC/host_addr")" "$(make_usb_mac 06 "$FUNC-host" "$SEED")"

# Locally administered unicast, and no two interfaces share a MAC.
macs="$(make_eth_mac "$SEED")
$(make_usb_mac 02 functions/rndis.usb0-dev "$SEED")
$(make_usb_mac 06 functions/rndis.usb0-host "$SEED")
$(make_usb_mac 02 functions/ncm.usb0-dev "$SEED")
$(make_usb_mac 06 functions/ncm.usb0-host "$SEED")"
echo "$macs" | grep -qE '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$' || fail "malformed MAC in: $macs"
[ "$(echo "$macs" | sort -u | wc -l | tr -d ' ')" = 5 ] || fail "MAC collision in: $macs"
echo "$macs" | while read -r m; do
    first=$((16#${m%%:*}))
    [ $((first & 3)) -eq 2 ] || fail "$m is not locally administered unicast"
done

echo "hardware MAC derivation tests passed"
