#!/usr/bin/env bash
# Starts S50sshd with BusyBox and a host build of the OpenSSH release that the
# rootfs ships, in private user, network, mount and PID namespaces, with the
# rootfs sshd_config. sshd must run with the password guessing limits, which
# win over sshd_config, and an sshd that refuses them must still start.
# SSHD_BIN and SSH_KEYGEN_BIN name the host builds; the sshd build uses the
# privilege separation user nobody and the directory /run/sshd-empty.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
S50SSHD="$ROOT_DIR/kvmapp/system/init.d/S50sshd"
SSHD_CONFIG="$ROOT_DIR/buildroot-external/hardened-sg2002/board/sg2002/overlay/etc/ssh/sshd_config"

if [ "${1:-}" != --inside ]; then
    for tool in busybox unshare "${SSHD_BIN:-}" "${SSH_KEYGEN_BIN:-}"; do
        if [ -z "$tool" ] || ! command -v "$tool" >/dev/null; then
            echo "S50sshd test needs busybox, unshare, SSHD_BIN and SSH_KEYGEN_BIN" >&2
            exit 2
        fi
    done
    TEST_ROOT="$(mktemp -d)"
    # The overlay leaves its work directories without permissions.
    trap 'chmod -R u+rwx "$TEST_ROOT" 2>/dev/null; rm -rf "$TEST_ROOT"' EXIT
    status=0
    # A PID namespace keeps the script's "killall sshd" away from the host.
    unshare --user --map-root-user --net --mount --pid --fork --mount-proc \
        bash "$0" --inside "$TEST_ROOT" || status=$?
    exit "$status"
fi

TEST_ROOT="$2"
fail() {
    echo "S50sshd test: $*" >&2
    exit 1
}

ip link set lo up 2>/dev/null || busybox ip link set lo up
mount -t tmpfs tmpfs /run
mkdir -p /run/sshd-empty /run/lock
for dir in /etc /usr/sbin /usr/bin /var; do
    name="${dir//\//-}"
    mkdir -p "$TEST_ROOT/upper$name" "$TEST_ROOT/work$name"
    mount -t overlay overlay -o "lowerdir=$dir,upperdir=$TEST_ROOT/upper$name,workdir=$TEST_ROOT/work$name" "$dir"
done
# An empty /etc/ssh: the host's own may hold files this namespace cannot remove.
mkdir -p /etc/ssh /etc/kvm
mount -t tmpfs tmpfs /etc/ssh
cp "$SSHD_CONFIG" /etc/ssh/sshd_config
# A device setting that the limits must win over.
echo "MaxAuthTries 10" >> /etc/ssh/sshd_config
rm -f /etc/kvm/ssh_stop
# Host binaries of the same names are replaced inside the overlays only.
# /usr/sbin/sshd records each call, then runs the real build, named sshd so
# that the script's killall finds it. sshd rewrites its own command line.
mkdir -p "$TEST_ROOT/real"
cp "$(command -v "$SSHD_BIN")" "$TEST_ROOT/real/sshd"
rm -f /usr/sbin/sshd /usr/bin/ssh-keygen
install_sshd() {
    {
        printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> %s/sshd-calls\n' "$TEST_ROOT"
        printf '%s\n' "$1"
        printf 'exec %s/real/sshd "$@"\n' "$TEST_ROOT"
    } > /usr/sbin/sshd
    chmod 0755 /usr/sbin/sshd
}
install_sshd ':'
cp "$(command -v "$SSH_KEYGEN_BIN")" /usr/bin/ssh-keygen
[ -d /var/lock ] || ln -s /run/lock /var/lock

mkdir -p "$TEST_ROOT/busybox"
for applet in sh printf touch rm killall; do
    ln -s "$(command -v busybox)" "$TEST_ROOT/busybox/$applet"
done
run_s50() {
    PATH="$TEST_ROOT/busybox" "$TEST_ROOT/busybox/sh" "$S50SSHD" "$@"
}

# The arguments of the last sshd started as a daemon, one per line.
daemon_args() {
    grep -v -e '^-t\( \|$\)' "$TEST_ROOT/sshd-calls" | tail -n 1 | tr ' ' '\n' | grep -v '^$' || true
}

listening() {
    for _ in $(seq 1 50); do
        [ -n "$(ss -ltnH 'sport = :22')" ] && return 0
        sleep 0.1
    done
    return 1
}

# 1. A current sshd runs with the limits, and they are what sshd uses.
output="$(run_s50 start 2>&1)" || fail "start failed: $output"
echo "start: $output"
listening || fail "sshd is not listening: $output"
args="$(daemon_args)"
echo "daemon arguments: $(echo $args)"
argv=()
[ -z "$args" ] || mapfile -t argv <<< "$args"
effective="$("$TEST_ROOT/real/sshd" -T "${argv[@]}")"
# sshd -T prints keywords as in sshd_config and penalty times in seconds.
for expected in "MaxAuthTries 3" "LoginGraceTime 60" "PerSourceNetBlockSize 32:64" \
    "PermitRootLogin yes" "PasswordAuthentication yes"; do
    printf '%s\n' "$effective" | grep -qix -e "$expected" || fail "effective config lacks '$expected'"
done
penalties="$(printf '%s\n' "$effective" | grep -i -e '^persourcepenalties ')"
echo "effective: $penalties"
for expected in authfail:60.000000 invaliduser:60.000000 max:600.000000; do
    case " $penalties " in
        *" $expected "*) ;;
        *) fail "effective penalties lack $expected" ;;
    esac
done
run_s50 stop >/dev/null
sleep 0.5
[ -z "$(ss -ltnH 'sport = :22')" ] || fail "stop left sshd running"

# 2. An sshd that refuses the limits (as before OpenSSH 9.8) still starts.
install_sshd 'case " $* " in *PerSource*) echo "Bad configuration option: PerSourcePenalties" >&2; exit 255 ;; esac'
output="$(run_s50 start 2>&1)" || fail "start with an older sshd failed: $output"
echo "start with an older sshd: $output"
case "$output" in
    *"without password guessing limits"*) ;;
    *) fail "the fallback was not reported" ;;
esac
listening || fail "the older sshd is not listening"
[ -z "$(daemon_args)" ] || fail "the older sshd got options: $(daemon_args)"
run_s50 stop >/dev/null

# 3. One missing key type is generated, whichever it is, and the others stay.
# This host build has no RSA, so a placeholder stands for a key that exists.
printf 'not a usable key\n' > /etc/ssh/ssh_host_rsa_key
chmod 0600 /etc/ssh/ssh_host_rsa_key
kept="$(sha256sum /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key)"
rm -f /etc/ssh/ssh_host_mldsa44_ed25519_key /etc/ssh/ssh_host_mldsa44_ed25519_key.pub
install_sshd ':'
output="$(run_s50 start 2>&1)" || fail "start with a missing key failed: $output"
echo "start with a missing key: $output"
listening || fail "sshd is not listening after the key was generated"
[ -s /etc/ssh/ssh_host_mldsa44_ed25519_key ] || fail "the missing MLDSA key was not generated"
[ "$(sha256sum /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key)" = "$kept" ] ||
    fail "an existing key changed"
run_s50 stop >/dev/null

echo "S50sshd: PASS"
