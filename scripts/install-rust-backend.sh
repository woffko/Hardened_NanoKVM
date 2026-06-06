#!/bin/sh
set -eu

if [ "${1:-}" = "" ]; then
  echo "usage: $0 /path/to/nanokvm-rust-server" >&2
  exit 2
fi

SRC="$1"
DEST_DIR="/kvmapp/server"
DEST="$DEST_DIR/NanoKVM-Server"
BACKUP="$DEST_DIR/NanoKVM-Server.go.bak"

if [ ! -x "$SRC" ]; then
  echo "source binary is missing or not executable: $SRC" >&2
  exit 1
fi

if [ ! -f "$BACKUP" ] && [ -f "$DEST" ]; then
  cp "$DEST" "$BACKUP"
fi

cp "$SRC" "$DEST"
chmod 0755 "$DEST"
/etc/init.d/S95nanokvm restart
