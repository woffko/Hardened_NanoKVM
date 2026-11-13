#!/bin/sh
# Manual deployment of a development backend build to a test device. It does
# not go through the signed app update, so it refuses while an app update
# transaction is recorded. Each file is replaced by rename, never written in
# place: the running backend keeps its own file until S95 restarts it.
set -eu

if [ "${1:-}" = "" ]; then
  echo "usage: $0 /path/to/nanokvm-rust-server" >&2
  exit 2
fi

# Tests point this at a temporary tree; on a device it is empty.
ROOT="${NANOKVM_INSTALL_ROOT:-}"
SRC="$1"
DEST_DIR="$ROOT/kvmapp/server"
DEST="$DEST_DIR/NanoKVM-Server"
BACKUP_DIR="$ROOT/kvmapp/backends"
RUST_BACKUP="$BACKUP_DIR/NanoKVM-Server.rust"

if [ ! -x "$SRC" ]; then
  echo "source binary is missing or not executable: $SRC" >&2
  exit 1
fi
if [ -e "$ROOT/etc/kvm/application-slot/current" ]; then
  echo "an app update transaction is recorded; let it end before installing" >&2
  exit 1
fi

trap 'rm -f "$DEST.new.$$" "$RUST_BACKUP.new.$$"' EXIT

# replace TARGET: copy SRC next to TARGET, then rename it over TARGET.
replace() {
  cp "$SRC" "$1.new.$$"
  chmod 0755 "$1.new.$$"
  mv -f "$1.new.$$" "$1"
}

mkdir -p "$BACKUP_DIR"
rm -f "$BACKUP_DIR/NanoKVM-Server.go" \
  "$DEST_DIR/NanoKVM-Server.go" \
  "$DEST_DIR/NanoKVM-Server.go.bak" \
  "$ROOT/etc/kvm/scripts/switch-backend-go.sh" \
  "$ROOT/etc/kvm/scripts/switch-backend-rust.sh" 2>/dev/null || true

replace "$DEST"
replace "$RUST_BACKUP"
sync
"$ROOT/etc/init.d/S95nanokvm" restart
