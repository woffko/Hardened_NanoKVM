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
# Accounts as after the first setup: root has a hash, the image's service
# accounts have "*", one person logs in by key alone and one by password.
rm -f /etc/passwd /etc/shadow
cat > /etc/passwd <<'EOF'
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/false
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
sshd:x:101:102::/var/empty:/bin/false
alice:x:1000:1000::/home/alice:/bin/sh
bob:x:1001:1001::/home/bob:/bin/sh
EOF
cat > /etc/shadow <<'EOF'
root:$6$saltsalt$hash:19000:0:99999:7:::
daemon:*:10933:0:99999:7:::
nobody:*:10933:0:99999:7:::
sshd:!:19000::::::
alice:*:::::::
bob:$6$saltsalt$hash:::::::
EOF
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
for applet in sh printf touch rm killall awk; do
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
args="$(daemon_args)"
printf '%s\n' "$args" | grep -q -e PerSource -e MaxAuthTries && fail "the older sshd got the limits: $args"
printf '%s\n' "$args" | grep -qx -e DenyUsers=daemon || fail "the older sshd lost the account barriers: $args"
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

# 4. A pair of the type OpenSSH 10.5 generated, which 10.6 cannot read, gives way.
mldsa=/etc/ssh/ssh_host_mldsa44_ed25519_key
printf 'a key of the old type\n' > "$mldsa"
chmod 0600 "$mldsa"
printf 'ssh-mldsa44-ed25519@openssh.com AAAA root@old\n' > "$mldsa.pub"
printf 'ssh-mldsa44-ed25519-cert-v01@openssh.com AAAA\n' > "$mldsa-cert.pub"
output="$(run_s50 start 2>&1)" || fail "start with a retired key failed: $output"
listening || fail "sshd is not listening after the retired key was replaced"
[ "$(cut -d' ' -f1 "$mldsa.pub")" = ssh-mldsa44-ed25519 ] || fail "the retired key is still there"
[ ! -e "$mldsa-cert.pub" ] || fail "the certificate of the retired key stayed"
"$SSH_KEYGEN_BIN" -y -P "" -f "$mldsa" >/dev/null || fail "the new key does not load"
[ "$(sha256sum /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key)" = "$kept" ] ||
    fail "replacing the retired key changed another key"
run_s50 stop >/dev/null

# 5. A key this OpenSSH reads stays, whatever its public file says: an older
# system runs this script too, and there the old type is a working key.
sed -i 's/^ssh-mldsa44-ed25519 /ssh-mldsa44-ed25519@openssh.com /' "$mldsa.pub"
kept="$(sha256sum "$mldsa" "$mldsa.pub")"
output="$(run_s50 start 2>&1)" || fail "start with a readable key failed: $output"
[ "$(sha256sum "$mldsa" "$mldsa.pub")" = "$kept" ] || fail "a key this OpenSSH reads was replaced"
run_s50 stop >/dev/null

# 6. A damaged key of the current type is no retired key: nothing removes it.
printf 'damaged\n' > "$mldsa"
printf 'ssh-mldsa44-ed25519 AAAA root@new\n' > "$mldsa.pub"
kept="$(sha256sum "$mldsa" "$mldsa.pub")"
output="$(run_s50 start 2>&1)" || fail "start with a damaged key failed: $output"
[ "$(sha256sum "$mldsa" "$mldsa.pub")" = "$kept" ] || fail "a damaged key was replaced"
run_s50 stop >/dev/null

# 7. CVE-2026-123158: the service accounts are refused by name, and passwords
# are off for root and people whose field is no hash while another has a hash.
output="$(run_s50 start 2>&1)" || fail "start with account barriers failed: $output"
listening || fail "sshd is not listening with account barriers: $output"
args="$(daemon_args)"
for expected in DenyUsers=daemon DenyUsers=nobody DenyUsers=sshd -f /run/nanokvm-sshd_config; do
    printf '%s\n' "$args" | grep -qx -e "$expected" || fail "sshd lacks '$expected': $(echo $args)"
done
for unexpected in DenyUsers=root DenyUsers=alice DenyUsers=bob; do
    printf '%s\n' "$args" | grep -qx -e "$unexpected" && fail "sshd got '$unexpected'"
done
mapfile -t argv <<< "$args"
for case in alice:no bob:yes root:yes; do
    name="${case%%:*}"
    got="$("$TEST_ROOT/real/sshd" -T "${argv[@]}" -C "user=$name,host=client,addr=192.0.2.1" |
        grep -i '^passwordauthentication ' | cut -d' ' -f2)"
    [ "$got" = "${case#*:}" ] || fail "password authentication for $name is '$got', not '${case#*:}'"
done
# sshd -T prints one DenyUsers line for each name.
denied="$("$TEST_ROOT/real/sshd" -T "${argv[@]}" | grep -i '^denyusers ')"
echo "effective: $(echo $denied)"
for name in daemon nobody sshd; do
    printf '%s\n' "$denied" | grep -qix -e "denyusers $name" || fail "effective DenyUsers lacks $name"
done
run_s50 stop >/dev/null

# 8. Before the first setup no account has a hash to borrow a salt from: sshd
# runs without the generated configuration, so root's first password works.
sed -i 's/^root:[^:]*:/root:*:/; s/^bob:[^:]*:/bob:!:/' /etc/shadow
output="$(run_s50 start 2>&1)" || fail "start before setup failed: $output"
args="$(daemon_args)"
printf '%s\n' "$args" | grep -qx -e -f && fail "sshd got the generated configuration without a hash: $(echo $args)"
[ ! -e /run/nanokvm-sshd_config ] || fail "the generated configuration stayed"
printf '%s\n' "$args" | grep -qx -e DenyUsers=daemon || fail "the service accounts are not refused before setup"
run_s50 stop >/dev/null

echo "S50sshd: PASS"
