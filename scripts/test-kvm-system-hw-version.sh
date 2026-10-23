#!/usr/bin/env bash
# kvm_system reads the hardware generation from /etc/kvm/hw (L-B12). The
# header-only reader is built for the host as C and as C++ and run against a
# missing, empty, unreadable and each known file; nothing crashes and unknown
# input means alpha, as before.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
HEADER_DIR="$ROOT_DIR/support/sg2002/kvm_system/main/lib/oled_ctrl"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

fail() {
    echo "kvm_system hw version test: $*" >&2
    exit 1
}

cat > "$T/probe.c" <<'SRC'
#include "hw_version.h"
int main(int argc, char **argv) { return argc == 2 ? hw_version_read(argv[1]) + 10 : 64; }
SRC
cp "$T/probe.c" "$T/probe.cpp"
cc -std=gnu11 -Wall -Wextra -Werror -I "$HEADER_DIR" "$T/probe.c" -o "$T/probe-c"
c++ -std=gnu++17 -Wall -Wextra -Werror -I "$HEADER_DIR" "$T/probe.cpp" -o "$T/probe-cxx"

# expect VALUE FILE_CONTENT|absent|unreadable
expect() {
    rm -f "$T/hw"
    case "$2" in
        absent) ;;
        unreadable) : > "$T/hw"; chmod 000 "$T/hw" ;;
        *) printf '%s' "$2" > "$T/hw" ;;
    esac
    for probe in probe-c probe-cxx; do
        status=0
        "$T/$probe" "$T/hw" || status=$?
        [ "$status" = "$((10 + $1))" ] || fail "$probe: $2 gave $((status - 10)), expected $1"
    done
}
expect 0 absent
expect 0 ""
expect 0 "alpha"
expect 1 "beta"
expect 2 "pcie"
expect 0 "x"
if [ "$(id -u)" != 0 ]; then
    expect 0 unreadable
fi
echo "kvm_system hw version test: PASS"
