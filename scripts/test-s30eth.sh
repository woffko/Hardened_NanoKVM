#!/bin/sh
# Host checks for S30eth's static IPv4/IPv6 and resolv.conf parsing. The script
# is sourced with S30ETH_TEST_ONLY=1; no network or device state is touched.
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
S30ETH="$ROOT_DIR/kvmapp/system/init.d/S30eth"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

BOOT_RESOLV_FILE="$tmp/boot-resolv" \
ETC_RESOLV_FILE="$tmp/etc-resolv" \
S30ETH_TEST_ONLY=1 \
. "$S30ETH"

fail() {
    echo "test-s30eth: $*" >&2
    exit 1
}

is_ipv4_addr 192.168.1.10 || fail "rejected a valid IPv4 address"
is_ipv4_addr 0.0.0.0 || fail "rejected the all-zero IPv4 address"
if is_ipv4_addr 192.168.1.256; then fail "accepted IPv4 octet 256"; fi
if is_ipv4_addr 192.168.1.01; then fail "accepted a leading-zero octet"; fi
if is_ipv4_addr 192.168.1; then fail "accepted a three-octet address"; fi
if is_ipv4_addr 192.168.1.1.2; then fail "accepted five octets"; fi
if is_ipv4_addr '192.168.1.1/24'; then fail "accepted a CIDR as an address"; fi

is_ipv4_netid 1 || fail "rejected netmask /1"
is_ipv4_netid 32 || fail "rejected netmask /32"
if is_ipv4_netid 0; then fail "accepted netmask /0"; fi
if is_ipv4_netid 33; then fail "accepted netmask /33"; fi
if is_ipv4_netid 024; then fail "accepted a leading-zero netmask"; fi

[ "$(calc_gw 192.168.1.10 24)" = "192.168.1.1" ] || fail "wrong gateway for .10/24"
[ "$(calc_gw 192.168.1.1 24)" = "192.168.1.254" ] || fail "wrong gateway for the gateway address"
if calc_gw 192.168.1 24; then fail "computed a gateway from an invalid address"; fi
if calc_gw 192.168.1.10 33; then fail "computed a gateway from an invalid netmask"; fi

is_ipv6_addr 2001:db8::1 || fail "rejected a valid IPv6 address"
if is_ipv6_addr 2001:db8::zz; then fail "accepted an invalid IPv6 address"; fi
is_ipv6_cidr 2001:db8::/64 || fail "rejected a valid IPv6 CIDR"
if is_ipv6_cidr 2001:db8::/129; then fail "accepted IPv6 prefix /129"; fi
if is_ipv6_cidr 2001:db8::; then fail "accepted an IPv6 address without a prefix"; fi

printf '%s\n' \
    'nameserver 1.1.1.1' \
    'nameserver invalid' \
    'search example.com bad/../x' \
    'domain example.org' \
    'options ndots:5 rotate' \
    > "$BOOT_RESOLV_FILE"
render_static_dns 192.168.1.1 || fail "render_static_dns failed on a mixed file"
grep -qx 'nameserver 1.1.1.1' "$ETC_RESOLV_FILE" || fail "valid nameserver dropped"
grep -qx 'domain example.org' "$ETC_RESOLV_FILE" || fail "valid domain dropped"
grep -qx 'options ndots:5 rotate' "$ETC_RESOLV_FILE" || fail "valid options dropped"
if grep -Eq 'invalid|bad/' "$ETC_RESOLV_FILE"; then
    fail "invalid resolv.conf line survived"
fi

printf 'nameserver invalid\n' > "$BOOT_RESOLV_FILE"
render_static_dns 192.168.1.1 || fail "render_static_dns failed with no valid nameserver"
grep -qx 'nameserver 192.168.1.1' "$ETC_RESOLV_FILE" || fail "fallback nameserver missing"

printf 'nameserver 2001:db8::1\n' > "$BOOT_RESOLV_FILE"
render_static_dns 192.168.1.1 || fail "render_static_dns failed for IPv6"
grep -qx 'nameserver 2001:db8::1' "$ETC_RESOLV_FILE" || fail "IPv6 nameserver dropped"

echo "test-s30eth: PASS"
