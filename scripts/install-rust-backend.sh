#!/bin/sh
set -eu

if [ "${1:-}" = "" ]; then
  echo "usage: $0 /path/to/nanokvm-rust-server" >&2
  exit 2
fi

SRC="$1"
DEST_DIR="/kvmapp/server"
DEST="$DEST_DIR/NanoKVM-Server"
BACKUP_DIR="/kvmapp/backends"
GO_BACKUP="$BACKUP_DIR/NanoKVM-Server.go"
RUST_BACKUP="$BACKUP_DIR/NanoKVM-Server.rust"

if [ ! -x "$SRC" ]; then
  echo "source binary is missing or not executable: $SRC" >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"

if [ ! -f "$GO_BACKUP" ] && [ -f "$DEST" ]; then
  cp "$DEST" "$GO_BACKUP"
fi

cp "$SRC" "$DEST"
chmod 0755 "$DEST"
cp "$SRC" "$RUST_BACKUP"
chmod 0755 "$RUST_BACKUP"
/etc/init.d/S95nanokvm restart
