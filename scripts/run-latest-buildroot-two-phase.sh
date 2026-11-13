#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEPLOY="$ROOT/scripts/test-published-raw-update-playwright.cjs"
TARGET_IP=10.0.87.133

if [ ! -t 0 ]
then
	echo "this launcher requires an interactive terminal" >&2
	exit 2
fi

restore_tty() {
	stty echo 2>/dev/null || true
	unset DEVICE_PASSWORD
}
trap restore_tty EXIT HUP INT TERM

printf 'NanoKVM device password: ' >&2
stty -echo
IFS= read -r DEVICE_PASSWORD
stty echo
printf '\n' >&2

[ -n "$DEVICE_PASSWORD" ] || {
	echo "password must not be empty" >&2
	exit 2
}

printf '%s\n' "$DEVICE_PASSWORD" | "$DEPLOY" --confirm-device "$TARGET_IP"
