#!/usr/bin/env bash
# S95's native log (L-B4): the file the broker, native owners and the Pico
# gateway append to is root-only and keeps one previous generation instead of
# growing without bound. The function is taken from S95nanokvm and run under
# the host's sh and, when present, BusyBox sh with a small size limit.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
S95="$ROOT_DIR/kvmapp/system/init.d/S95nanokvm"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

fail() {
    echo "S95 native log test: $*" >&2
    exit 1
}

for name in prepare_runtime_log prepare_native_log; do
    awk -v start="$name() {" '$0 == start {p = 1} p {print} p && $0 == "}" {exit}' "$S95" >> "$T/lib.sh"
done
grep -qx 'prepare_native_log() {' "$T/lib.sh" || fail "no prepare_native_log in S95nanokvm"
grep -q '^    prepare_native_log || return 1$' "$S95" || fail "start_native_broker does not require safe log preparation"

shells="sh"
command -v busybox >/dev/null 2>&1 && shells="sh busybox"

run() {
    env NATIVE_LOG="$T/native.log" NATIVE_LOG_LIMIT=64 \
        $([ "$1" = busybox ] && echo busybox) sh -c ". '$T/lib.sh'; prepare_native_log" < /dev/null
}
mode() {
    stat -c '%a' "$1"
}

for shell in $shells; do
    rm -f "$T/native.log" "$T/native.log.1"
    (umask 022; run "$shell")
    [ -f "$T/native.log" ] && [ ! -s "$T/native.log" ] || fail "$shell: no empty log was created"
    [ "$(mode "$T/native.log")" = 600 ] || fail "$shell: a new log is mode $(mode "$T/native.log")"
    echo "ok $shell: a missing log is created empty and private under a permissive umask"

    printf 'short\n' > "$T/native.log"
    chmod 644 "$T/native.log"
    run "$shell"
    [ "$(cat "$T/native.log")" = short ] || fail "$shell: a short log was not kept"
    [ "$(mode "$T/native.log")" = 600 ] || fail "$shell: an existing log stayed mode $(mode "$T/native.log")"
    [ ! -e "$T/native.log.1" ] || fail "$shell: a short log was rotated"
    echo "ok $shell: a short log is kept and made private"

    head -c 100 /dev/zero | tr '\0' x > "$T/native.log"
    run "$shell"
    [ -f "$T/native.log.1" ] && [ "$(wc -c < "$T/native.log.1")" = 100 ] || fail "$shell: a full log was not kept as .1"
    [ ! -s "$T/native.log" ] && [ "$(mode "$T/native.log")" = 600 ] || fail "$shell: no fresh private log after rotation"
    head -c 100 /dev/zero | tr '\0' y > "$T/native.log"
    run "$shell"
    [ "$(head -c 1 "$T/native.log.1")" = y ] || fail "$shell: the second rotation did not replace .1"
    [ ! -e "$T/native.log.2" ] || fail "$shell: more than one generation kept"
    echo "ok $shell: a log over the limit becomes .1 and only one generation is kept"

    rm -f "$T/native.log"
    printf sentinel > "$T/victim"
    ln -s "$T/victim" "$T/native.log"
    if run "$shell"; then fail "$shell: accepted a symlink log"; fi
    [ "$(cat "$T/victim")" = sentinel ] || fail "$shell: touched linked victim"
    rm "$T/native.log"
    ln "$T/victim" "$T/native.log"
    if run "$shell"; then fail "$shell: accepted a hardlink log"; fi
    rm "$T/native.log"
    mkfifo "$T/native.log"
    if run "$shell"; then fail "$shell: accepted a FIFO log"; fi
    rm "$T/native.log"
done
echo "S95 native log test: PASS"
