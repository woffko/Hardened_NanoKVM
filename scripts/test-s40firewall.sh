#!/usr/bin/env bash
# Runs S40firewall with BusyBox against real legacy iptables in a private user,
# network and mount namespace and checks every committed table.
#
# XTABLES_BIN_DIR may name a host build of the iptables release that the rootfs
# ships. IPv6 needs the host's ip6_tables module; on a host without it,
# S40FIREWALL_TEST_IPV4_ONLY=1 hides ip6tables from the script and reports
# IPv6 as not tested.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
S40FIREWALL="$ROOT_DIR/kvmapp/system/init.d/S40firewall"

if [ "${1:-}" != --inside ]; then
    [ -z "${XTABLES_BIN_DIR:-}" ] || PATH="$XTABLES_BIN_DIR:$PATH"
    export PATH
    for tool in busybox unshare setsid iptables iptables-save iptables-restore; do
        if ! command -v "$tool" >/dev/null; then
            echo "S40firewall test needs $tool (legacy iptables: set XTABLES_BIN_DIR)" >&2
            exit 2
        fi
    done
    TEST_ROOT="$(mktemp -d)"
    trap 'rm -rf "$TEST_ROOT"' EXIT
    status=0
    unshare --user --map-root-user --net --mount bash "$0" --inside "$TEST_ROOT" || status=$?
    exit "$status"
fi

TEST_ROOT="$2"
mount -t tmpfs tmpfs /run
mkdir -p "$TEST_ROOT/etc-upper" "$TEST_ROOT/etc-work"
mount -t overlay overlay -o "lowerdir=/etc,upperdir=$TEST_ROOT/etc-upper,workdir=$TEST_ROOT/etc-work" /etc
mkdir -p /etc/kvm

fail() {
    echo "S40firewall test: $*" >&2
    exit 1
}

iptables -V | grep -q legacy || fail "iptables is not the legacy backend that the rootfs uses"
if command -v ip6tables >/dev/null && ip6tables -S >/dev/null 2>&1; then
    FAMILIES="iptables ip6tables"
elif [ "${S40FIREWALL_TEST_IPV4_ONLY:-}" = 1 ]; then
    FAMILIES=iptables
else
    fail "ip6tables does not work here (load ip6_tables or set S40FIREWALL_TEST_IPV4_ONLY=1)"
fi

# The script sees BusyBox applets and the iptables tools of the families
# under test only, as on the device.
mkdir -p "$TEST_ROOT/busybox" "$TEST_ROOT/xtables"
for applet in sh awk grep sed head tr; do
    ln -s "$(command -v busybox)" "$TEST_ROOT/busybox/$applet"
done
for family in $FAMILIES; do
    for tool in "$family" "$family-save" "$family-restore"; do
        ln -s "$(command -v "$tool")" "$TEST_ROOT/xtables/$tool"
    done
done
FW_PATH="$TEST_ROOT/busybox:$TEST_ROOT/xtables"

run_fw() {
    PATH="$FW_PATH" "$TEST_ROOT/busybox/sh" "$S40FIREWALL" "$@"
}

expect_ok() {
    output="$(run_fw "$@" 2>&1)" || fail "'$*' failed: $output"
    case "$output" in
        *FAILED*) fail "'$*' reported failure: $output" ;;
    esac
}

set_mode() {
    printf '{\n  "mode": "%s"\n}\n' "$1" > /etc/kvm/firewall.json
}

set_https() {
    if [ "$1" = off ]; then
        printf 'proto: http\nport:\n  http: 80\n  https: 443\n' > /etc/kvm/server.yaml
    else
        printf 'proto: https\nport:\n  http: 80\n  https: %s\n' "$1" > /etc/kvm/server.yaml
    fi
}

snapshot() {
    for family in $FAMILIES; do
        "$family" -S > "$TEST_ROOT/$1.$family"
    done
}

same_snapshot() {
    for family in $FAMILIES; do
        cmp -s "$TEST_ROOT/$1.$family" "$TEST_ROOT/$2.$family" || return 1
    done
}

chains_header() {
    printf '%s\n' "-P INPUT $1" "-P FORWARD $2" "-P OUTPUT $3" "-N NKVM-INPUT" "-N NKVM-OUTPUT" \
        "-A INPUT -j NKVM-INPUT" "-A OUTPUT -j NKVM-OUTPUT" \
        "-A NKVM-INPUT -i usb0 -m state --state NEW -j DROP"
}

ipv6_control() {
    for type in 1 2 3 4 133 134 135 136; do
        echo "-A NKVM-$1 -p ipv6-icmp -m icmp6 --icmpv6-type $type -j ACCEPT"
    done
}

# The rules of each mode as S40firewall appended them to the built-in chains
# before it used its own chains, in iptables -S form.
expected_iptables() {
    case "$1" in
        baseline)
            chains_header ACCEPT ACCEPT ACCEPT
            cat <<'EOF'
-A NKVM-INPUT -i eth0 -p tcp -m tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
-A NKVM-INPUT -i eth0 -p tcp -m tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
-A NKVM-INPUT -i eth0 -p tcp -m tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
-A NKVM-OUTPUT -o eth0 -p tcp -m tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
-A NKVM-OUTPUT -o eth0 -p tcp -m tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
-A NKVM-OUTPUT -o eth0 -p tcp -m tcp --dport 22 -m state --state ESTABLISHED -j ACCEPT
EOF
            ;;
        moderate)
            chains_header DROP DROP ACCEPT
            cat <<'EOF'
-A NKVM-INPUT -i lo -j ACCEPT
-A NKVM-INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A NKVM-INPUT -s 10.0.0.0/8 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 172.16.0.0/12 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 192.168.0.0/16 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 169.254.0.0/16 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -p udp -m udp --sport 67 --dport 68 -j ACCEPT
-A NKVM-OUTPUT -o lo -j ACCEPT
EOF
            ;;
        restricted)
            chains_header DROP DROP DROP
            cat <<'EOF'
-A NKVM-INPUT -i lo -j ACCEPT
-A NKVM-INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A NKVM-INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 172.16.0.0/12 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 192.168.0.0/16 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 169.254.0.0/16 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 172.16.0.0/12 -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 192.168.0.0/16 -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 169.254.0.0/16 -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -p udp -m udp --sport 67 --dport 68 -j ACCEPT
-A NKVM-OUTPUT -o lo -j ACCEPT
-A NKVM-OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A NKVM-OUTPUT -p tcp -m tcp --dport 443 -m state --state NEW -j ACCEPT
-A NKVM-OUTPUT -p udp -m udp --dport 53 -j ACCEPT
-A NKVM-OUTPUT -p tcp -m tcp --dport 53 -m state --state NEW -j ACCEPT
-A NKVM-OUTPUT -p udp -m udp --dport 123 -j ACCEPT
-A NKVM-OUTPUT -p udp -m udp --dport 1514 -j ACCEPT
-A NKVM-OUTPUT -p udp -m udp --sport 68 --dport 67 -j ACCEPT
EOF
            ;;
        paranoid)
            chains_header DROP DROP DROP
            cat <<'EOF'
-A NKVM-INPUT -i lo -j ACCEPT
-A NKVM-INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A NKVM-INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 172.16.0.0/12 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 192.168.0.0/16 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s 169.254.0.0/16 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -p udp -m udp --sport 67 --dport 68 -j ACCEPT
-A NKVM-OUTPUT -o lo -j ACCEPT
-A NKVM-OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A NKVM-OUTPUT -p udp -m udp --sport 68 --dport 67 -j ACCEPT
EOF
            ;;
    esac
}

expected_ip6tables() {
    case "$1" in
        baseline)
            chains_header ACCEPT ACCEPT ACCEPT
            cat <<'EOF'
-A NKVM-INPUT -i eth0 -p tcp -m tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
-A NKVM-INPUT -i eth0 -p tcp -m tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
-A NKVM-INPUT -i eth0 -p tcp -m tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
-A NKVM-OUTPUT -o eth0 -p tcp -m tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
-A NKVM-OUTPUT -o eth0 -p tcp -m tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
-A NKVM-OUTPUT -o eth0 -p tcp -m tcp --dport 22 -m state --state ESTABLISHED -j ACCEPT
EOF
            ;;
        moderate)
            chains_header DROP DROP ACCEPT
            cat <<'EOF'
-A NKVM-INPUT -i lo -j ACCEPT
-A NKVM-INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A NKVM-INPUT -s fc00::/7 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s fe80::/10 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -p udp -m udp --sport 547 --dport 546 -j ACCEPT
EOF
            ipv6_control INPUT
            echo "-A NKVM-OUTPUT -o lo -j ACCEPT"
            ipv6_control OUTPUT
            ;;
        restricted)
            chains_header DROP DROP DROP
            cat <<'EOF'
-A NKVM-INPUT -i lo -j ACCEPT
-A NKVM-INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A NKVM-INPUT -s fc00::/7 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s fe80::/10 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s fc00::/7 -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s fe80::/10 -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -p udp -m udp --sport 547 --dport 546 -j ACCEPT
EOF
            ipv6_control INPUT
            cat <<'EOF'
-A NKVM-OUTPUT -o lo -j ACCEPT
-A NKVM-OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A NKVM-OUTPUT -p tcp -m tcp --dport 443 -m state --state NEW -j ACCEPT
-A NKVM-OUTPUT -p udp -m udp --dport 53 -j ACCEPT
-A NKVM-OUTPUT -p tcp -m tcp --dport 53 -m state --state NEW -j ACCEPT
-A NKVM-OUTPUT -p udp -m udp --dport 123 -j ACCEPT
-A NKVM-OUTPUT -p udp -m udp --dport 1514 -j ACCEPT
-A NKVM-OUTPUT -p udp -m udp --sport 546 --dport 547 -j ACCEPT
EOF
            ipv6_control OUTPUT
            ;;
        paranoid)
            chains_header DROP DROP DROP
            cat <<'EOF'
-A NKVM-INPUT -i lo -j ACCEPT
-A NKVM-INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A NKVM-INPUT -s fc00::/7 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -s fe80::/10 -p tcp -m tcp --dport 8443 -m state --state NEW -j ACCEPT
-A NKVM-INPUT -p udp -m udp --sport 547 --dport 546 -j ACCEPT
EOF
            ipv6_control INPUT
            cat <<'EOF'
-A NKVM-OUTPUT -o lo -j ACCEPT
-A NKVM-OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A NKVM-OUTPUT -p udp -m udp --sport 546 --dport 547 -j ACCEPT
EOF
            ipv6_control OUTPUT
            ;;
    esac
}

expect_tables() {
    for family in $FAMILIES; do
        "expected_$family" "$1" > "$TEST_ROOT/expected.$family"
        "$family" -S > "$TEST_ROOT/actual.$family"
        diff -u "$TEST_ROOT/expected.$family" "$TEST_ROOT/actual.$family" ||
            fail "$family table is not $1 ($2)"
    done
}

expect_jumps() {
    for family in $FAMILIES; do
        [ "$("$family" -S "$1" | grep -e '^-A' || true)" = "$2" ] ||
            fail "$family $1 jumps $3: $("$family" -S "$1")"
    done
}

printf '{\n  "remotePort": 1514\n}\n' > /etc/kvm/syslog.json

# 1. A fresh table gets the default Moderate rules; a second run changes nothing.
rm -f /etc/kvm/firewall.json
set_https off
expect_ok start
expect_tables moderate "fresh start"
snapshot first
expect_ok restart
snapshot second
same_snapshot first second || fail "a repeated start changed the tables"

# 2. Every mode, with a custom HTTPS port; without HTTPS the strict modes
# stay Moderate. Stop always leaves Baseline; status is unchanged.
set_https 8443
for mode in baseline moderate restricted paranoid; do
    set_mode "$mode"
    expect_ok restart
    expect_tables "$mode" "mode $mode"
done
set_https off
for mode in restricted paranoid; do
    set_mode "$mode"
    expect_ok reload
    expect_tables moderate "$mode without HTTPS"
done
# The computer under control stays out of management in every mode: the first
# rule any input meets stops its new connections, ahead of every ACCEPT and in
# the mode whose policy accepts. The operator opens it with a file.
for mode in baseline moderate restricted paranoid; do
    set_mode "$mode"
    set_https 8443
    expect_ok restart
    for family in $FAMILIES; do
        [ "$("$family" -S INPUT | sed -n 2p)" = "-A INPUT -j NKVM-INPUT" ] ||
            fail "$family $mode: something runs before the managed chain"
        [ "$("$family" -S NKVM-INPUT | sed -n 2p)" = "-A NKVM-INPUT -i usb0 -m state --state NEW -j DROP" ] ||
            fail "$family $mode: usb0 is not closed first"
    done
    touch /etc/kvm/usb_management
    expect_ok restart
    for family in $FAMILIES; do
        if "$family" -S NKVM-INPUT | grep -q usb0; then
            fail "$family $mode: the operator's opening was ignored"
        fi
    done
    rm /etc/kvm/usb_management
done
set_mode paranoid
set_https off

# The script reads HTTPS as the server does. A missing file is HTTP.
rm -f /etc/kvm/server.yaml
expect_ok reload
expect_tables moderate "paranoid without a configuration"
for form in 'proto: "https"' "proto: 'https'" 'proto: https # a comment' 'proto:   https  '; do
    printf '%s\nport:\n  http: 80\n  https: 8443\n' "$form" > /etc/kvm/server.yaml
    expect_ok reload
    expect_tables paranoid "$form"
done
for form in 'proto: HTTPS' 'proto: http' '# proto: https' 'proto: httpsx'; do
    printf '%s\nport:\n  http: 80\n  https: 8443\n' "$form" > /etc/kvm/server.yaml
    expect_ok reload
    expect_tables moderate "$form"
done
set_https off
expect_ok stop
expect_tables baseline "stop"
status_line='mode=paranoid effective=moderate https=disabled port=443 syslog_port=1514 local_ipv4="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 127.0.0.0/8" local_ipv6="fc00::/7 fe80::/10 ::1/128"'
[ "$(run_fw status)" = "$status_line" ] || fail "status output changed: $(run_fw status)"

# 3. Chains that other software owns, and their jumps, survive every mode
# change. The rules mirror what tailscaled installs.
for family in $FAMILIES; do
    "$family" -N ts-input
    "$family" -N ts-forward
    "$family" -A ts-input -i tailscale0 -j ACCEPT
    "$family" -A ts-forward -o tailscale0 -j ACCEPT
    "$family" -I INPUT 1 -j ts-input
    "$family" -I FORWARD 1 -j ts-forward
done
iptables -A ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
iptables -t nat -N ts-postrouting
iptables -t nat -A ts-postrouting -o tailscale0 -j MASQUERADE
iptables -t nat -A POSTROUTING -j ts-postrouting
foreign_rules() {
    for family in $FAMILIES; do
        "$family" -S ts-input
        "$family" -S ts-forward
    done
    iptables -t nat -S
}
foreign_rules > "$TEST_ROOT/foreign.before"
set_https 8443
for mode in paranoid moderate restricted baseline; do
    set_mode "$mode"
    expect_ok restart
    foreign_rules > "$TEST_ROOT/foreign.after"
    diff -u "$TEST_ROOT/foreign.before" "$TEST_ROOT/foreign.after" || fail "mode $mode changed foreign chains"
    expect_jumps INPUT "$(printf '%s\n' '-A INPUT -j ts-input' '-A INPUT -j NKVM-INPUT')" "after mode $mode"
    expect_jumps FORWARD '-A FORWARD -j ts-forward' "after mode $mode"
done
expect_ok stop
foreign_rules > "$TEST_ROOT/foreign.after"
diff -u "$TEST_ROOT/foreign.before" "$TEST_ROOT/foreign.after" || fail "stop changed foreign chains"
for family in $FAMILIES; do
    "$family" -D INPUT -j ts-input
    "$family" -D FORWARD -j ts-forward
    "$family" -F ts-input
    "$family" -F ts-forward
    "$family" -X ts-input
    "$family" -X ts-forward
done
iptables -t nat -F
iptables -t nat -X

# 4. Rules that the previous script appended straight to the built-in chains
# go on the first run; a jump to a foreign chain stays.
for family in $FAMILIES; do
    "$family" -D INPUT -j NKVM-INPUT
    "$family" -D OUTPUT -j NKVM-OUTPUT
    "$family" -F NKVM-INPUT
    "$family" -F NKVM-OUTPUT
    "$family" -X NKVM-INPUT
    "$family" -X NKVM-OUTPUT
    "$family" -N ts-input
    "$family" -A INPUT -j ts-input
    "$family" -A INPUT -i lo -j ACCEPT
    "$family" -A OUTPUT -o lo -j ACCEPT
    "$family" -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    "$family" -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
    "$family" -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
    "$family" -P INPUT DROP
done
iptables -A INPUT -s 10.0.0.0/8 -m state --state NEW -j ACCEPT
set_mode paranoid
expect_ok restart
expect_jumps INPUT "$(printf '%s\n' '-A INPUT -j ts-input' '-A INPUT -j NKVM-INPUT')" "after the upgrade"
expect_jumps OUTPUT '-A OUTPUT -j NKVM-OUTPUT' "after the upgrade"
for family in $FAMILIES; do
    "$family" -D INPUT -j ts-input
    "$family" -X ts-input
done
expect_tables paranoid "upgrade from direct rules"

# 5. A rejected candidate changes nothing and fails the command.
snapshot before
set_https 70000
if output="$(run_fw restart 2>&1)"; then
    fail "an invalid HTTPS port was accepted: $output"
fi
case "$output" in
    *FAILED*) ;;
    *) fail "a failed restart did not report FAILED: $output" ;;
esac
snapshot after
same_snapshot before after || fail "a rejected candidate changed the tables"

# 6. A commit that fails after its candidate passed --test fails the command,
# keeps that family's table and does not hold back the other family.
set_https 8443
set_mode moderate
broken="${FAMILIES##* }"
mkdir -p "$TEST_ROOT/broken"
printf '#!/bin/sh\ncase " $* " in *" --test "*) exec %s "$@" ;; esac\nexit 1\n' \
    "$(command -v "$broken-restore")" > "$TEST_ROOT/broken/$broken-restore"
chmod 0755 "$TEST_ROOT/broken/$broken-restore"
"$broken" -S > "$TEST_ROOT/broken.before"
if output="$(PATH="$TEST_ROOT/broken:$FW_PATH" "$TEST_ROOT/busybox/sh" "$S40FIREWALL" restart 2>&1)"; then
    fail "a failed $broken commit was reported as success: $output"
fi
"$broken" -S > "$TEST_ROOT/broken.after"
cmp -s "$TEST_ROOT/broken.before" "$TEST_ROOT/broken.after" || fail "a failed $broken commit changed its table"
for family in $FAMILIES; do
    [ "$family" = "$broken" ] && continue
    "expected_$family" moderate > "$TEST_ROOT/expected.$family"
    "$family" -S | diff -u "$TEST_ROOT/expected.$family" - || fail "$family was held back by the $broken failure"
done

# 7. A run killed at any point leaves each family either wholly in the old
# mode or wholly in the new one, never flushed or half built. Every iptables
# tool waits 10 ms first, so the kills land all over a run.
mkdir -p "$TEST_ROOT/slow"
for tool in "$TEST_ROOT"/xtables/*; do
    printf '#!/bin/sh\n%s 0.01\nexec %s "$@"\n' "$(command -v sleep)" "$(command -v "${tool##*/}")" \
        > "$TEST_ROOT/slow/${tool##*/}"
    chmod 0755 "$TEST_ROOT/slow/${tool##*/}"
done
for mode in moderate paranoid; do
    for family in $FAMILIES; do
        "expected_$family" "$mode" > "$TEST_ROOT/$mode.$family"
    done
done
expect_ok restart
setsid="$(command -v setsid)"
killed=0
kept=0
for round in $(seq 1 40); do
    if [ $((round % 2)) = 1 ]; then old=moderate new=paranoid; else old=paranoid new=moderate; fi
    set_mode "$new"
    PATH="$TEST_ROOT/busybox:$TEST_ROOT/slow" "$setsid" "$TEST_ROOT/busybox/sh" "$S40FIREWALL" restart > /dev/null 2>&1 &
    pid=$!
    sleep "0.0$((round % 10))"
    kill -KILL -- "-$pid" 2>/dev/null && killed=$((killed + 1))
    wait "$pid" 2>/dev/null || true
    for family in $FAMILIES; do
        "$family" -S > "$TEST_ROOT/killed.$family"
        if cmp -s "$TEST_ROOT/killed.$family" "$TEST_ROOT/$old.$family"; then
            kept=$((kept + 1))
        elif ! cmp -s "$TEST_ROOT/killed.$family" "$TEST_ROOT/$new.$family"; then
            fail "round $round left a partial $family table: $(cat "$TEST_ROOT/killed.$family")"
        fi
    done
    # Settle on the configured mode before the next round.
    expect_ok restart
done
echo "S40firewall kill rounds: 40, killed while running: $killed, tables left in the old mode: $kept"
[ "$killed" -ge 10 ] || fail "too few kills landed during a run ($killed)"

# 8. Concurrent runs end with one complete table.
set_mode restricted
pids=
for run in 1 2 3; do
    run_fw restart > "$TEST_ROOT/concurrent.$run" 2>&1 &
    pids="$pids $!"
done
ok=0
for pid in $pids; do
    if wait "$pid"; then ok=$((ok + 1)); fi
done
[ "$ok" -ge 1 ] || fail "no concurrent run succeeded: $(cat "$TEST_ROOT"/concurrent.*)"
expect_tables restricted "concurrent runs"
echo "S40firewall concurrent runs: 3, succeeded: $ok"

case "$FAMILIES" in
    *ip6tables*) echo "S40firewall: PASS (IPv4 and IPv6)" ;;
    *) echo "S40firewall: PASS for IPv4; IPv6 NOT TESTED (no ip6_tables on this host)" ;;
esac
