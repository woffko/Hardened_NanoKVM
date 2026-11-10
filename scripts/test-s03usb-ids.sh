#!/usr/bin/env bash
# usb_id, taken from S03usbdev and S03usbhid and run under the host's sh and,
# when present, BusyBox sh. /boot/usb.vid and /boot/usb.pid come from a FAT
# partition that anyone holding the card can edit. Only one 16-bit hexadecimal
# number is passed on to the gadget; anything else gives the default, so a
# damaged file cannot leave the gadget with an ID of zero.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fail() {
    echo "S03 USB ID test: $*" >&2
    exit 1
}

shells="sh"
command -v busybox >/dev/null 2>&1 && shells="sh busybox"
for script in S03usbdev S03usbhid; do
    source="$ROOT_DIR/kvmapp/system/init.d/$script"
    awk '$0 == "usb_id() {" {p = 1} p {print} p && $0 == "}" {exit}' "$source" > "$T/lib.sh"
    grep -qx 'usb_id() {' "$T/lib.sh" || fail "no usb_id in $script"
    grep -qx '    usb_id /boot/usb.vid 0x3346 > idVendor' "$source" || fail "$script does not check the vendor ID"
    grep -qx '    usb_id /boot/usb.pid 0x1009 > idProduct' "$source" || fail "$script does not check the product ID"
    grep -q 'cat /boot/usb\.[vp]id' "$source" && fail "$script still copies an ID file as it is"
    for shell in $shells; do
        id() {
            $([ "$shell" = busybox ] && echo busybox) sh -c ". '$T/lib.sh'; usb_id '$T/id' 0x3346"
        }
        expect() {
            [ "$(id)" = "$2" ] || fail "$script, $shell: $1 gave '$(id)', not '$2'"
        }
        printf '0x1d6b\n' > "$T/id";            expect "a valid ID" 0x1d6b
        printf '0xABCD' > "$T/id";              expect "a valid ID without a newline" 0xABCD
        printf '0x1d6b\r\n' > "$T/id";          expect "a DOS line ending" 0x1d6b
        printf '0x1d6b\n0x0002\n' > "$T/id";    expect "the first line of two" 0x1d6b
        : > "$T/id";                            expect "an empty file" 0x3346
        printf '1d6b\n' > "$T/id";              expect "no 0x prefix" 0x3346
        printf '0x1d6\n' > "$T/id";             expect "three digits" 0x3346
        printf '0x1d6b0\n' > "$T/id";           expect "five digits" 0x3346
        printf '0x1d6g\n' > "$T/id";            expect "a letter that is no digit" 0x3346
        printf ' 0x1d6b\n' > "$T/id";           expect "a leading space" 0x3346
        printf '0x1d6b; reboot\n' > "$T/id";    expect "text after the number" 0x3346
        printf '$(reboot)\n' > "$T/id";         expect "a command substitution" 0x3346
        rm -f "$T/id";                          expect "a missing file" 0x3346
        mkdir "$T/id";                          expect "a directory" 0x3346
        rmdir "$T/id"
    done
    echo "ok $script: only a 16-bit hexadecimal ID is used"
done
echo "S03 USB IDs: PASS"
