#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail() { echo "usb-network-policy: $*" >&2; exit 1; }
USBDEV="$ROOT/kvmapp/system/init.d/S03usbdev"
FIREWALL="$ROOT/kvmapp/system/init.d/S40firewall"

grep -Fq 'if [ -e /boot/usb.ncm ]' "$USBDEV" || fail "NCM is not opt-in"
grep -Fq 'if [ -e /boot/usb.rndis0 ]' "$USBDEV" || fail "RNDIS is not opt-in"
for port in 80 443 22; do
	if grep -Eq -- "-i[[:space:]]+usb0.*--dport[[:space:]]+$port" "$FIREWALL"; then
		fail "usb0 management port $port is accepted by default"
	fi
done
if grep -Eq -- "-i[[:space:]]+usb0.*(-j[[:space:]]+ACCEPT)" "$FIREWALL"; then
	fail "usb0 has a default ACCEPT rule"
fi
echo "usb network policy: PASS"
