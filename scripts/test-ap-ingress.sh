#!/usr/bin/env bash
# Real packet checks; all interfaces/rules live in private network namespaces.
set -euo pipefail
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export PATH="${XTABLES_BIN_DIR:-$ROOT_DIR/build/host-tools/iptables/sbin}:$PATH"
if [ "${1:-}" != --inside ]; then
    exec unshare --user --map-root-user --net --mount bash "$0" --inside
fi
mount -t tmpfs tmpfs /run
T=$(mktemp -d)
remote=
trap 'if [ -n "$remote" ]; then kill "$remote" 2>/dev/null || true; wait "$remote" 2>/dev/null || true; fi; rm -rf "$T"' EXIT
for name in install_ap_guard remove_ap_guard; do
    awk -v start="$name() {" '$0 == start {p=1} p {print} p && $0 == "}" {exit}' \
        "$ROOT_DIR/kvmapp/system/init.d/S30wifi" >> "$T/functions"
done
. "$T/functions"
AP_GUARD_CHAIN=NKVM-AP-INGRESS
unshare --net sleep 30 >/dev/null 2>&1 &
remote=$!
sleep 0.1
peer() { nsenter -t "$remote" -n "$@"; }
ip link add wlan0 type veth peer name wifi netns "$remote"
ip link add eth0 type veth peer name wired netns "$remote"
ip addr add 10.2.3.1/24 dev wlan0
ip addr add 192.0.2.1/24 dev eth0
ip link set wlan0 up
ip link set eth0 up
peer ip addr add 10.2.3.100/24 dev wifi
peer ip addr add 192.0.2.2/24 dev wired
peer ip link set wifi up
peer ip link set wired up
peer ip route add 10.2.3.1/32 via 192.0.2.1 dev wired
peer busybox ping -c 1 -W 1 10.2.3.1 >/dev/null
install_ap_guard 10.2.3.1
# Even an earlier filter ACCEPT cannot bypass mangle INPUT.
iptables -I INPUT 1 -j ACCEPT
if peer busybox ping -c 1 -W 1 10.2.3.1 >/dev/null; then
    echo 'wired client reached AP destination' >&2; exit 1
fi
peer ip route del 10.2.3.1/32
peer busybox ping -c 1 -W 1 10.2.3.1 >/dev/null
iptables -t nat -A PREROUTING -i eth0 -d 192.0.2.1 -j DNAT --to-destination 10.2.3.1
if peer busybox ping -c 1 -W 1 192.0.2.1 >/dev/null; then
    echo 'DNAT bypassed AP ingress guard' >&2; exit 1
fi
iptables -t nat -F PREROUTING
remove_ap_guard
peer ip route add 10.2.3.1/32 via 192.0.2.1 dev wired
peer busybox ping -c 1 -W 1 10.2.3.1 >/dev/null
echo 'AP ingress (wired, wlan0, DNAT, removal): PASS'
