#!/usr/bin/env bash
# Exercise the one-shot NTP log lifecycle without changing the host clock.
set -euo pipefail
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export T
awk '$0 == "sync_time_once() {" {p=1} p {print} p && $0 == "}" {exit}' \
    "$ROOT_DIR/kvmapp/system/init.d/S49ntp" > "$T/lib.sh"
cat > "$T/ntpdate" <<'EOF'
#!/bin/sh
echo invoked >> "$T/calls"
[ "$(stat -c %a "$T"/ntpdate.*)" = 600 ] || exit 99
echo fixture-diagnostic
exit "${NTP_STATUS:-0}"
EOF
chmod +x "$T/ntpdate"
cat > "$T/run.sh" <<'EOF'
. "$T/lib.sh"
NTPDATE="$T/ntpdate"
ntp_servers() { echo 192.0.2.1; }
mktemp() {
    [ "$1" = /run/ntpdate.XXXXXX ] || return 1
    [ "${FAIL_TEMP:-0}" = 0 ] || return 1
    command mktemp "$T/ntpdate.XXXXXX"
}
sync_time_once
EOF
for shell in sh 'busybox sh'; do
    command -v "${shell%% *}" >/dev/null || continue
    for status in 0 1; do
        output=$(NTP_STATUS=$status $shell "$T/run.sh")
        if [ "$status" = 0 ]; then
            [[ "$output" == *OK* ]]
        else
            [[ "$output" == *fixture-diagnostic* ]]
        fi
        [ -z "$(find "$T" -name 'ntpdate.*' -print)" ]
    done
    before=$(wc -l < "$T/calls")
    if FAIL_TEMP=1 $shell "$T/run.sh"; then
        echo 'failed log creation was accepted' >&2
        exit 1
    fi
    [ "$(wc -l < "$T/calls")" = "$before" ]
    echo "NTP one-shot log ($shell): PASS"
done
