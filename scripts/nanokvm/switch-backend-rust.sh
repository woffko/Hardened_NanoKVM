#!/bin/sh
set -eu

TARGET="rust"
DEST="/kvmapp/server/NanoKVM-Server"
SRC="/kvmapp/backends/NanoKVM-Server.rust"
STATE="/etc/kvm/backend"
LOG="/tmp/nanokvm-backend-switch.log"

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
