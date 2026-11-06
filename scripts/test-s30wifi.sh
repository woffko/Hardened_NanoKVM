#!/usr/bin/env bash
# S30wifi in a private root made of the host's static BusyBox and stubs of the
# Wi-Fi daemons, run as root of a user namespace. Every file that holds a Wi-Fi
# secret must end up 0600, whatever umask /etc/profile sets and whatever mode an
# earlier writer left. The plain passphrase that wpa_passphrase prints as a
# comment must not reach wpa_supplicant.conf. The setup access point's flag,
# which opens the Wi-Fi routes that need no login, must live in /run, where only
# root can create it, and a flag left in /tmp must go.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
S30WIFI="$ROOT_DIR/kvmapp/system/init.d/S30wifi"
for tool in busybox unshare; do
    command -v "$tool" >/dev/null || { echo "S30wifi test needs $tool" >&2; exit 2; }
done
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fail() {
    echo "S30wifi test: $*" >&2
    exit 1
}

R="$T/root"
mkdir -p "$R"/{bin,dev,stub,etc/kvm,etc/init.d,boot,kvmapp/kvm,run,tmp,var/run,usr/libexec,sys/class/cvi-base}
: > "$R/dev/null"
cp "$(command -v busybox)" "$R/bin/busybox"
for applet in sh cat chmod chown mv rm sed printf head tail sha512sum touch grep awk xargs kill; do
    ln -s busybox "$R/bin/$applet"
done
stub() {
    printf '#!/bin/sh\n%s\n' "$2" > "$R/stub/$1"
    chmod 0755 "$R/stub/$1"
}
stub wpa_passphrase 'printf "network={\n\tssid=\"%s\"\n\t#psk=\"%s\"\n\tpsk=0123abcd\n}\n" "$1" "$2"'
for daemon in wpa_supplicant udhcpc hostapd udhcpd ifconfig ip killall airmon-ng ps; do
    stub "$daemon" 'exit 0'
done
printf '#!/bin/sh\nexit 0\n' > "$R/usr/libexec/nanokvm-app-recovery"
chmod 0755 "$R/usr/libexec/nanokvm-app-recovery"
# The device's /etc/profile sets umask 022.
printf 'umask 022\nexport PATH=/stub:/bin\n' > "$R/etc/profile"
printf 'synthetic\n' > "$R/sys/class/cvi-base/base_uid"
cp "$S30WIFI" "$R/etc/init.d/S30wifi"

# The script writes to /dev/null, which the private root takes from the host.
run() {
    env -i PATH=/stub:/bin R="$R" "$(command -v unshare)" --user --map-root-user --mount \
        "$(command -v busybox)" sh -c 'mount -o bind /dev/null "$R/dev/null" &&
            exec chroot "$R" /bin/sh /etc/init.d/S30wifi "$@"' sh "$@" >"$T/out" 2>&1 ||
        fail "S30wifi $* failed: $(cat "$T/out")"
}
mode() {
    stat -c %a "$R$1"
}

# 1. Station mode from /boot, with configuration files an earlier writer left 0644.
printf 'home\n' > "$R/boot/wifi.ssid"
printf 'secret-home-pass\n' > "$R/boot/wifi.pass"
chmod 0644 "$R/boot/wifi.ssid" "$R/boot/wifi.pass"
for file in wpa_supplicant.conf hostapd.conf; do
    printf 'old\n' > "$R/etc/$file"
    chmod 0644 "$R/etc/$file"
done
run start
for file in /etc/kvm/wifi.ssid /etc/kvm/wifi.pass /etc/wpa_supplicant.conf /etc/hostapd.conf; do
    [ "$(mode "$file")" = 600 ] || fail "$file is $(mode "$file") after start"
done
grep -qx $'\tpsk=0123abcd' "$R/etc/wpa_supplicant.conf" || fail "wpa_supplicant.conf lacks the derived key"
grep -q -e '#psk' -e 'secret-home-pass' "$R/etc/wpa_supplicant.conf" &&
    fail "wpa_supplicant.conf keeps the plain passphrase"
[ ! -e "$R/etc/wpa_supplicant.conf.new" ] || fail "start left a temporary file"

# 2. The setup access point, with a flag planted in /tmp by another account.
printf 'NanoKVM\n' > "$R/kvmapp/kvm/ap.ssid"
printf 'apkey12345\n' > "$R/kvmapp/kvm/ap.pass"
touch "$R/tmp/wifiap"
run ap
[ "$(mode /etc/hostapd.conf)" = 600 ] || fail "hostapd.conf is $(mode /etc/hostapd.conf) in AP mode"
grep -qx 'wpa_passphrase=apkey12345' "$R/etc/hostapd.conf" || fail "hostapd.conf lacks the AP key"
[ -e "$R/run/nanokvm-wifiap" ] || fail "the AP flag is not in /run"
[ ! -e "$R/tmp/wifiap" ] || fail "the flag in /tmp stayed"
[ ! -e "$R/etc/hostapd.conf.new" ] || fail "ap left a temporary file"

# 3. Stopping the access point removes its flag.
run stop
[ ! -e "$R/run/nanokvm-wifiap" ] || fail "stop left the AP flag"

echo "S30wifi: PASS"
