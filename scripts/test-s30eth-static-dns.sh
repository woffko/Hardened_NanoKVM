#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
S30ETH="$ROOT_DIR/kvmapp/system/init.d/S30eth"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

export S30ETH_TEST_ONLY=1
export BOOT_RESOLV_FILE="$TEST_ROOT/boot-resolv.conf"
export ETC_RESOLV_FILE="$TEST_ROOT/etc-resolv.conf"

# shellcheck source=/dev/null
. "$S30ETH"

render_static_dns 192.0.2.1
render_static_dns 192.0.2.1

if [ "$(wc -l < "$ETC_RESOLV_FILE")" -ne 1 ]; then
    echo "gateway fallback accumulated duplicate DNS lines" >&2
    exit 1
fi
if ! grep -qx 'nameserver 192.0.2.1' "$ETC_RESOLV_FILE"; then
    echo "gateway fallback resolver is incorrect" >&2
    exit 1
fi

cat > "$BOOT_RESOLV_FILE" <<'EOF'
search test.invalid
nameserver 2001:db8::53
nameserver 192.0.2.53
nameserver 2001:db8::53
EOF
render_static_dns 192.0.2.1

cat > "$TEST_ROOT/expected-resolv.conf" <<'EOF'
search test.invalid
nameserver 2001:db8::53
nameserver 192.0.2.53
EOF

if ! cmp -s "$TEST_ROOT/expected-resolv.conf" "$ETC_RESOLV_FILE"; then
    echo "manual boot DNS configuration was not normalized" >&2
    exit 1
fi

render_static_dns 192.0.2.1
if ! cmp -s "$TEST_ROOT/expected-resolv.conf" "$ETC_RESOLV_FILE"; then
    echo "manual DNS rendering is not idempotent" >&2
    exit 1
fi

echo "S30eth static DNS idempotence: PASS"
