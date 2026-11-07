#!/bin/sh
# Host checks for the bridge's numeric/global-input validation. Invalid values
# must fail before any curl or device/API request is attempted.
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BRIDGE="$ROOT_DIR/kvmapp/picoclaw/skills/kvm-control/scripts/nanokvm-bridge.sh"

fail() {
    echo "test-nanokvm-bridge: $*" >&2
    exit 1
}

expect_fail() {
    if "$@" >/dev/null 2>&1; then
        fail "accepted invalid input: $*"
    fi
}

expect_fail env NANOKVM_BRIDGE_TIMEOUT_SECONDS=0 sh "$BRIDGE" --session-id test screenshot
expect_fail sh "$BRIDGE" --timeout-seconds 0 --session-id test click --x 1 --y 1
expect_fail sh "$BRIDGE" --timeout-seconds abc --session-id test click --x 1 --y 1
expect_fail sh "$BRIDGE" --session-id test click --x '1,"evil":1' --y 1
expect_fail sh "$BRIDGE" --session-id test move --x 1 --y bad
expect_fail sh "$BRIDGE" --session-id test screenshot --width abc
expect_fail env NANOKVM_BRIDGE_SCREENSHOT_WIDTH=abc sh "$BRIDGE" --session-id test screenshot
expect_fail sh "$BRIDGE" --session-id test double-click --x 1 --y 1 --wait-ms bad

echo "test-nanokvm-bridge: PASS"
