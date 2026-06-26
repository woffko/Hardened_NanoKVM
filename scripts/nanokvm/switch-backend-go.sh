#!/bin/sh
set -eu

TARGET="go"
DEST="/kvmapp/server/NanoKVM-Server"
SRC="/kvmapp/backends/NanoKVM-Server.go"
FALLBACK="/kvmapp/server/NanoKVM-Server.go.bak"
STATE="/etc/kvm/backend"
LOG="/tmp/nanokvm-backend-switch.log"

if [ ! -x "$SRC" ] && [ -x "$FALLBACK" ]; then
  SRC="$FALLBACK"
fi

restart_backend() {
  /etc/init.d/S95nanokvm restart
}

{
  echo "$(date): switching to $TARGET backend"

  if [ ! -x "$SRC" ]; then
    echo "missing executable backend binary: $SRC"
    exit 1
  fi

  cp "$SRC" "$DEST"
  chmod 0755 "$DEST"
  echo "$TARGET" > "$STATE"

  restart_backend
} >>"$LOG" 2>&1
