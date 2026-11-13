#!/usr/bin/env bash
# Real BusyBox syslogd in a private PID namespace/chroot; no host /dev/log.
set -euo pipefail
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T"/{bin,sbin,etc/default,etc/init.d,dev,run,var/run,tmp}
: > "$T/dev/null"
cp "$(command -v busybox)" "$T/bin/busybox"
for applet in sh mkdir stat chmod start-stop-daemon killall logger sleep cat grep rm ln; do
    ln -s busybox "$T/bin/$applet"
done
ln -s ../bin/busybox "$T/sbin/syslogd"
cp "$ROOT_DIR/kvmapp/system/init.d/S01syslogd" "$T/etc/init.d/S01syslogd"
printf "SYSLOGD_ARGS='-O /tmp/old-log -s 1 -b 1 -l 8'\n" > "$T/etc/default/syslogd"
printf sentinel > "$T/tmp/old-log"
cat > "$T/test.sh" <<'EOF'
set -eu
export PATH=/bin:/sbin
sh /etc/init.d/S01syslogd start
i=0
while [ ! -S /dev/log ]; do
    i=$((i + 1)); [ "$i" -lt 30 ]; sleep 0.1
done
logger -t fixture migration-marker
i=0
until grep -q migration-marker /run/hardened-syslog/messages; do
    i=$((i + 1)); [ "$i" -lt 30 ]; sleep 0.1
done
[ "$(cat /tmp/old-log)" = sentinel ]
[ "$(stat -c %a /run/hardened-syslog)" = 700 ]
[ "$(stat -c %a /run/hardened-syslog/messages)" = 600 ]
i=0
while [ "$i" -lt 60 ]; do
    logger -t fixture rotation-marker-012345678901234567890123456789
    i=$((i + 1))
done
i=0
while [ ! -f /run/hardened-syslog/messages.0 ]; do
    i=$((i + 1)); [ "$i" -lt 30 ]; sleep 0.1
done
[ "$(stat -c %a /run/hardened-syslog/messages.0)" = 600 ]
[ "$(cat /tmp/old-log)" = sentinel ]
sh /etc/init.d/S01syslogd stop
rm -rf /run/hardened-syslog
ln -s /tmp /run/hardened-syslog
if sh /etc/init.d/S01syslogd start; then exit 1; fi
[ ! -e /tmp/messages ]
echo 'S01syslogd: PASS'
EOF
unshare --user --map-root-user --mount --pid --fork --kill-child \
    "$(command -v busybox)" sh -ec 'mount -o bind /dev/null "$1/dev/null"; exec chroot "$1" /bin/sh /test.sh' sh "$T"
