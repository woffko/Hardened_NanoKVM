#!/bin/sh
set -eu

TARGET="rust"
DEST="/kvmapp/server/NanoKVM-Server"
SRC="/kvmapp/server/NanoKVM-Server.rust"
STATE="/etc/kvm/backend"
LOG="/tmp/nanokvm-backend-switch.log"

{
  echo "$(date): switching to $TARGET backend"

  if [ ! -x "$SRC" ]; then
    echo "missing executable backend binary: $SRC"
    exit 1
  fi

  cp "$SRC" "$DEST"
  chmod 0755 "$DEST"
  echo "$TARGET" > "$STATE"

  rm -rf /tmp/server
  cp -r /kvmapp/server /tmp/

  nohup sh -c 'sleep 1; killall NanoKVM-Server 2>/dev/null || true; sleep 1; nohup /tmp/server/NanoKVM-Server >/tmp/nanokvm-server.log 2>&1 &' >>"$LOG" 2>&1 &
} >>"$LOG" 2>&1
