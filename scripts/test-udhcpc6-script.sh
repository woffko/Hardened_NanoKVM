#!/usr/bin/env bash
# Runs the DHCPv6 hook with BusyBox as udhcpc6 calls it, in a private user,
# network and mount namespace that has an eth0, and checks the /128 it adds
# and removes and what reaches resolv.conf.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
HOOK="$ROOT_DIR/kvmapp/system/network/udhcpc6.script"

if [ "${1:-}" != --inside ]; then
    for tool in busybox unshare ip; do
        if ! command -v "$tool" >/dev/null; then
            echo "udhcpc6 hook test needs $tool" >&2
            exit 2
        fi
    done
    TEST_ROOT="$(mktemp -d)"
    # The overlay leaves its work directory without permissions.
    trap 'chmod -R u+rwx "$TEST_ROOT" 2>/dev/null; rm -rf "$TEST_ROOT"' EXIT
    status=0
    unshare --user --map-root-user --net --mount bash "$0" --inside "$TEST_ROOT" || status=$?
    exit "$status"
fi

TEST_ROOT="$2"
fail() {
    echo "udhcpc6 hook test: $*" >&2
    exit 1
}

mount -t tmpfs tmpfs /run
mkdir -p "$TEST_ROOT/etc-upper" "$TEST_ROOT/etc-work"
mount -t overlay overlay -o "lowerdir=/etc,upperdir=$TEST_ROOT/etc-upper,workdir=$TEST_ROOT/etc-work" /etc
ip link add eth0 type veth peer name eth0-peer
echo 0 > /proc/sys/net/ipv6/conf/eth0/dad_transmits
ip link set eth0 up
RESOLV_CONF=/etc/resolv.conf
[ -e /boot/resolv.conf ] && RESOLV_CONF=/etc/resolv.conf.dhcp6
# A host resolv.conf may be a link out of the overlay; replace it inside.
rm -f "$RESOLV_CONF"
printf 'nameserver 192.0.2.53\n' > "$RESOLV_CONF"

# BusyBox applets and iproute2's ip, as on the device.
mkdir -p "$TEST_ROOT/bin"
for applet in sh cat grep mktemp rm touch; do
    ln -s "$(command -v busybox)" "$TEST_ROOT/bin/$applet"
done
ln -s "$(command -v ip)" "$TEST_ROOT/bin/ip"

# hook ACTION [NAME=VALUE...]: the environment udhcpc6 passes.
hook() {
    action="$1"
    shift
    env -i PATH="$TEST_ROOT/bin" interface=eth0 "$@" "$TEST_ROOT/bin/sh" "$HOOK" "$action" ||
        fail "the hook failed for $action"
}

addresses() {
    ip -6 addr show dev eth0 scope global | awk '$1 == "inet6" { print $2 }'
}

expect_addresses() {
    [ "$(addresses)" = "$1" ] || fail "$2: eth0 has '$(addresses)', expected '$1'"
}

expect_resolv() {
    printf '%s\n' "$@" > "$TEST_ROOT/expected"
    diff -u "$TEST_ROOT/expected" "$RESOLV_CONF" || fail "resolv.conf differs"
}

# 1. A lease adds its /128 and the server's resolvers and search list.
hook bound ipv6=2001:db8::5 dns="2001:db8::53 2001:db8::54" search="example.net lab.example"
expect_addresses 2001:db8::5/128 "bound"
expect_resolv 'nameserver 192.0.2.53' \
    'search example.net lab.example # eth0-dhcpv6' \
    'nameserver 2001:db8::53 # eth0-dhcpv6' \
    'nameserver 2001:db8::54 # eth0-dhcpv6'

# 2. A renewal with the same address keeps it; with a new one replaces it.
hook renew ipv6=2001:db8::5 dns=2001:db8::53
expect_addresses 2001:db8::5/128 "renew, same address"
hook renew ipv6=2001:db8::6 dns=2001:db8::53 domain=example.org
expect_addresses 2001:db8::6/128 "renew, new address"
expect_resolv 'nameserver 192.0.2.53' \
    'search example.org # eth0-dhcpv6' \
    'nameserver 2001:db8::53 # eth0-dhcpv6'

# A new address that the kernel refuses leaves the current one in place.
hook renew ipv6=ff02::1 dns=2001:db8::53 domain=example.org
expect_addresses 2001:db8::6/128 "renew with an address the kernel refuses"

# 3. Values that are not an address or a domain list never reach ip or
# resolv.conf, even with a newline that would start another line.
hook renew ipv6="2001:db8::7/0" \
    dns="2001:db8::53
nameserver 203.0.113.66 bad;rm" \
    search="evil.example
nameserver 203.0.113.67"
expect_addresses 2001:db8::6/128 "renew with values that are not an address"
expect_resolv 'nameserver 192.0.2.53' \
    'nameserver 2001:db8::53 # eth0-dhcpv6'

# 4. Losing the lease removes the /128 and the server's lines, nothing else.
hook deconfig
expect_addresses "" "deconfig"
expect_resolv 'nameserver 192.0.2.53'
[ ! -e /run/udhcpc6.eth0.address ] || fail "deconfig kept the address record"

echo "udhcpc6 hook: PASS"
