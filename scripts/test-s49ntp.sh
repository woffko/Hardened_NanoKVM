#!/usr/bin/env bash
# Starts S49ntp with BusyBox and a host build of the ntpd release that the
# rootfs ships, in a private user, network and mount namespace. A second
# network namespace behind a veth pair holds a test server (192.0.2.2) and an
# unconfigured client (192.0.2.3). ntpd must accept the server's replies,
# serve time to no one else, and survive local addresses it cannot bind yet
# (tentative IPv6 addresses during duplicate address detection). NTPD_BIN and
# NTPQ_BIN name host builds of ntpd and ntpq with the rootfs patches.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
S49NTP="$ROOT_DIR/kvmapp/system/init.d/S49ntp"

if [ "${1:-}" != --inside ]; then
    for tool in busybox unshare nsenter ip python3 "${NTPD_BIN:-}" "${NTPQ_BIN:-}"; do
        if [ -z "$tool" ] || ! command -v "$tool" >/dev/null; then
            echo "S49ntp test needs busybox, unshare, nsenter, ip, python3, NTPD_BIN and NTPQ_BIN" >&2
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
    echo "S49ntp test: $*" >&2
    exit 1
}

ip link set lo up
# Background processes write to files, never to a pipe of the caller.
unshare --net sleep infinity </dev/null >/dev/null 2>&1 &
remote=$!
sleep 0.3
in_remote() {
    nsenter -t "$remote" -n "$@"
}
ip link add vkvm type veth peer name vlan netns "$remote"
ip addr add 192.0.2.1/24 dev vkvm
# Keep new IPv6 addresses tentative for about five seconds.
echo 5 > /proc/sys/net/ipv6/conf/vkvm/dad_transmits
ip link set vkvm up
in_remote ip addr add 192.0.2.2/24 dev vlan
in_remote ip addr add 192.0.2.3/24 dev vlan
in_remote ip link set vlan up
mount -t tmpfs tmpfs /run
for dir in /etc /usr/sbin; do
    name="${dir//\//-}"
    mkdir -p "$TEST_ROOT/upper$name" "$TEST_ROOT/work$name"
    mount -t overlay overlay -o "lowerdir=$dir,upperdir=$TEST_ROOT/upper$name,workdir=$TEST_ROOT/work$name" "$dir"
done
mkdir -p /etc/kvm
rm -f /etc/default/ntpd /etc/ntp.conf
cp "$(command -v "$NTPD_BIN")" /usr/sbin/ntpd
[ ! -e /usr/bin/ntpdate ] || fail "a host ntpdate would step the clock of the test"

mkdir -p "$TEST_ROOT/busybox"
for applet in sh awk sed head mv mktemp rm sleep kill killall start-stop-daemon; do
    ln -s "$(command -v busybox)" "$TEST_ROOT/busybox/$applet"
done
run_ntp() {
    PATH="$TEST_ROOT/busybox" "$TEST_ROOT/busybox/sh" "$S49NTP" "$@"
}

cat > "$TEST_ROOT/server.py" <<'EOF'
import socket, struct, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], 123))
open(sys.argv[2], "w").close()
while True:
    data, peer = s.recvfrom(512)
    if len(data) < 48 or data[0] & 7 != 3:
        continue
    now = time.time() + 2208988800
    seconds, fraction = int(now), int((now % 1) * (1 << 32))
    s.sendto(struct.pack("!BBbbII4sIIIIIIII", (data[0] & 0x38) | 4, 2, 6, -20, 256, 256,
                         b"TEST", seconds - 16, 0, *struct.unpack("!II", data[40:48]),
                         seconds, fraction, seconds, fraction), peer)
EOF
cat > "$TEST_ROOT/probe.py" <<'EOF'
import socket, struct, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
s.settimeout(2)
s.sendto(struct.pack("!B47xII", 0x23, int(time.time() + 2208988800), 0), (sys.argv[2], 123))
try:
    print("reply mode %d" % (s.recvfrom(512)[0][0] & 7))
except socket.timeout:
    print("no reply")
EOF
# nsenter execs python, so this is the server's own PID.
nsenter -t "$remote" -n python3 -I "$TEST_ROOT/server.py" 192.0.2.2 "$TEST_ROOT/server.ready" \
    </dev/null >"$TEST_ROOT/server.log" 2>&1 &
server=$!
for _ in $(seq 1 50); do
    [ -e "$TEST_ROOT/server.ready" ] && break
    sleep 0.1
done
[ -e "$TEST_ROOT/server.ready" ] || fail "the test server did not start"
trap 'kill "$server" "$remote" 2>/dev/null; run_ntp stop >/dev/null 2>&1 || true' EXIT

printf '{\n  "ntpEnabled": true,\n  "servers": ["192.0.2.2"]\n}\n' > /etc/kvm/time.json
output="$(run_ntp start 2>&1)" || fail "start failed: $output"
case "$output" in
    *"ntpd daemon: OK"*) ;;
    *) fail "ntpd did not start: $output" ;;
esac
echo "--- /etc/ntp.conf"
cat /etc/ntp.conf

# The configured server's replies are accepted: its reach register fills.
reach=0
for _ in $(seq 1 30); do
    reach="$("$NTPQ_BIN" -n -c peers 127.0.0.1 2>/dev/null | awk '$1 ~ /192\.0\.2\.2$/ { print $7 }')"
    [ -n "$reach" ] && [ "$reach" != 0 ] && break
    sleep 1
done
echo "reach of 192.0.2.2: ${reach:-none}"
[ -n "$reach" ] && [ "$reach" != 0 ] || fail "ntpd did not accept the configured server's replies"

# A new address that cannot be bound yet, as when a network interface comes
# up, must not stop ntpd on its next interface scan (two seconds later).
ip -6 addr add 2001:db8::1/64 dev vkvm
sleep 4
reach="$("$NTPQ_BIN" -n -c peers 127.0.0.1 2>/dev/null | awk '$1 ~ /192\.0\.2\.2$/ { print $7 }')"
echo "reach of 192.0.2.2 after a tentative address appeared: ${reach:-none}"
[ -n "$reach" ] && [ "$reach" != 0 ] || fail "ntpd stopped after a local address could not be bound"

# Any other address gets no time service.
probe="$(in_remote python3 -I "$TEST_ROOT/probe.py" 192.0.2.3 192.0.2.1)"
echo "client request from 192.0.2.3: $probe"
[ "$probe" = "no reply" ] || fail "ntpd served time to an unconfigured address"

echo "S49ntp: PASS"
