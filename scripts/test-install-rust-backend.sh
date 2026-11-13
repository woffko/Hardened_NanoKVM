#!/usr/bin/env bash
# scripts/install-rust-backend.sh against a temporary root. The backend that
# runs from the destination keeps running while the new binary is renamed into
# place, S95 is restarted once, and a recorded app update transaction is
# refused before anything changes.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TEST_ROOT="$(mktemp -d)"
running=""
cleanup() {
    [ -z "$running" ] || kill "$running" 2>/dev/null || true
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

fail() {
    echo "install-rust-backend test: $*" >&2
    exit 1
}

R="$TEST_ROOT/root"
mkdir -p "$R/kvmapp/server" "$R/etc/init.d" "$R/etc/kvm"
cat > "$R/etc/init.d/S95nanokvm" <<'S95'
#!/bin/sh
echo "$*" >> "${0%/etc/init.d/S95nanokvm}/restart.log"
S95
chmod 0755 "$R/etc/init.d/S95nanokvm"
printf '#!/bin/sh\necho new backend\n' > "$TEST_ROOT/new-server"
printf '#!/bin/sh\necho other backend\n' > "$TEST_ROOT/other-server"
chmod 0755 "$TEST_ROOT/new-server" "$TEST_ROOT/other-server"

# The current backend runs from the destination path.
cp "$(command -v sleep)" "$R/kvmapp/server/NanoKVM-Server"
"$R/kvmapp/server/NanoKVM-Server" 300 &
running=$!
old_inode="$(stat -c %i "$R/kvmapp/server/NanoKVM-Server")"

NANOKVM_INSTALL_ROOT="$R" sh "$ROOT_DIR/scripts/install-rust-backend.sh" "$TEST_ROOT/new-server" \
    > "$TEST_ROOT/out" 2>&1 || fail "install failed: $(cat "$TEST_ROOT/out")"
cmp -s "$R/kvmapp/server/NanoKVM-Server" "$TEST_ROOT/new-server" || fail "the new binary is not in place"
cmp -s "$R/kvmapp/backends/NanoKVM-Server.rust" "$TEST_ROOT/new-server" || fail "the backup copy is missing"
[ "$(stat -c %i "$R/kvmapp/server/NanoKVM-Server")" != "$old_inode" ] || fail "the running binary was written in place"
kill -0 "$running" 2>/dev/null || fail "the running backend was disturbed"
[ "$(cat "$R/restart.log")" = restart ] || fail "S95 calls: $(cat "$R/restart.log")"
[ -z "$(find "$R" -name '*.new.*')" ] || fail "a temporary file was left"

# A recorded app update transaction is refused before anything changes.
mkdir -p "$R/etc/kvm/application-slot/current"
status=0
NANOKVM_INSTALL_ROOT="$R" sh "$ROOT_DIR/scripts/install-rust-backend.sh" "$TEST_ROOT/other-server" \
    > "$TEST_ROOT/out" 2>&1 || status=$?
[ "$status" != 0 ] || fail "an install during an app update transaction was accepted"
grep -q 'app update transaction' "$TEST_ROOT/out" || fail "unexpected refusal: $(cat "$TEST_ROOT/out")"
cmp -s "$R/kvmapp/server/NanoKVM-Server" "$TEST_ROOT/new-server" || fail "the binary changed during a transaction"
[ "$(wc -l < "$R/restart.log")" = 1 ] || fail "S95 was restarted during a transaction"

echo "install-rust-backend: PASS"
