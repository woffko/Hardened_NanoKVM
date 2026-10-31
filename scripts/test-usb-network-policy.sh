#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail() { echo "usb-network-policy: $*" >&2; exit 1; }
USBDEV="$ROOT/kvmapp/system/init.d/S03usbdev"
FIREWALL="$ROOT/kvmapp/system/init.d/S40firewall"

grep -Fq 'if [ -e /boot/usb.ncm ]' "$USBDEV" || fail "NCM is not opt-in"
grep -Fq 'if [ -e /boot/usb.rndis0 ]' "$USBDEV" || fail "RNDIS is not opt-in"
# What the rules do with usb0 in every mode is tested on real tables in
# test-s40firewall.sh. A new card must not bring usb0 up at all.
for image in buildroot-external/hardened-sg2002/board/sg2002/genimage.cfg \
	scripts/assemble-latest-buildroot-sg2002-sd-image.sh; do
	if grep -Fq 'usb.rndis0' "$ROOT/$image"; then
		fail "$image still ships usb.rndis0"
	fi
done
grep -Fq 'etc/kvm/usb_management' "$ROOT/server-rust/src/update/restore_policy.rs" ||
	fail "a raw update would forget the operator's opening of usb0"
echo "usb network policy: PASS"
