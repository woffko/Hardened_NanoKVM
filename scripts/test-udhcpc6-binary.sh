#!/usr/bin/env bash
# Host checks on the bundled udhcpc6 (default: kvmapp/system/bin/udhcpc6) and
# on its config fragment: a static RISC-V ELF with no interpreter and no
# dynamic section, the DHCPv6 applet name present, no shell inside, a bounded
# size; the fragment keeps the client static, v6-only and shell-free. These
# are ELF and string checks, not an execution of the client.
set -uo pipefail
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
BINARY=${1:-$ROOT_DIR/kvmapp/system/bin/udhcpc6}
FRAGMENT=$ROOT_DIR/buildroot-external/hardened-sg2002/board/sg2002/udhcpc6.fragment
MAX_BYTES=262144
failed=0
check() {
  if "$@"; then echo "PASS $name"; else echo "FAIL $name"; failed=1; fi
}
for tool in readelf strings; do
  command -v "$tool" >/dev/null || { echo "udhcpc6 test needs $tool" >&2; exit 2; }
done
header=$(readelf -h "$BINARY" 2>/dev/null)
name="an ELF64 executable for RISC-V"
check sh -c 'printf "%s" "$1" | grep -q "Class:.*ELF64" && printf "%s" "$1" | grep -q "Machine:.*RISC-V" && printf "%s" "$1" | grep -q "Type:.*EXEC"' _ "$header"
name="no program interpreter"
check sh -c '! readelf -l "$1" | grep -q INTERP' _ "$BINARY"
name="no dynamic section"
check sh -c 'readelf -d "$1" | grep -q "no dynamic section"' _ "$BINARY"
name="the udhcpc6 applet name is present"
check sh -c 'strings -n 2 "$1" | grep -qx udhcpc6' _ "$BINARY"
name="no shell applet or shell strings"
check sh -c '! strings -n 2 "$1" | grep -qx -e sh -e ash -e hush && ! strings "$1" | grep -q -e "PS1=# " -e "ash: "' _ "$BINARY"
name="no IPv4 client or server applet"
check sh -c '! strings -n 2 "$1" | grep -qx -e udhcpc -e udhcpd' _ "$BINARY"
name="no build timestamp banner"
check sh -c '! strings "$1" | grep -q "BusyBox v"' _ "$BINARY"
name="size below $MAX_BYTES bytes"
check sh -c '[ "$(stat -c %s "$1")" -le "$2" ]' _ "$BINARY" "$MAX_BYTES"
name="fragment: static, DHCPv6 with RFC 3646, no shell, no IPv4 client"
check sh -c 'f=$1; grep -qx "CONFIG_STATIC=y" "$f" && grep -qx "CONFIG_UDHCPC6=y" "$f" && grep -qx "CONFIG_FEATURE_UDHCPC6_RFC3646=y" "$f" && grep -qx "CONFIG_SH_IS_NONE=y" "$f" && grep -qx "# CONFIG_UDHCPC is not set" "$f" && grep -qx "# CONFIG_UDHCPD is not set" "$f" && ! grep -qx "CONFIG_FEATURE_SUID=y" "$f"' _ "$FRAGMENT"
name="fragment: the hook path is the default script"
check grep -qx 'CONFIG_UDHCPC6_DEFAULT_SCRIPT="/kvmapp/system/network/udhcpc6.script"' "$FRAGMENT"
exit $failed
