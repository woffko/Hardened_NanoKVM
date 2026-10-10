#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
SCRIPT="$ROOT_DIR/kvmapp/system/init.d/S03usbdev"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

export HID_ONLY_FLAG="$TEST_ROOT/usb.hidonly"
export HID_ONLY_SCRIPT="$TEST_ROOT/S03usbhid"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

expect() {
    [ "$2" = "$3" ] || fail "$1: got '$2', want '$3'"
}

printf '#!/bin/sh\necho "hid-only: $*"\n' > "$HID_ONLY_SCRIPT"
chmod +x "$HID_ONLY_SCRIPT"

# `noop` matches no action, so the normal script does nothing with it.
expect "no flag runs the normal script" "$(sh "$SCRIPT" noop)" ""

touch "$HID_ONLY_FLAG"
expect "flag hands over every argument" "$(sh "$SCRIPT" noop two)" "hid-only: noop two"

chmod -x "$HID_ONLY_SCRIPT"
expect "flag without a usable HID-only script keeps the normal one" "$(sh "$SCRIPT" noop)" ""
chmod +x "$HID_ONLY_SCRIPT"

rm "$HID_ONLY_FLAG"
expect "removing the flag goes back to the normal script" "$(sh "$SCRIPT" noop)" ""

echo "HID-only mode script tests passed"
