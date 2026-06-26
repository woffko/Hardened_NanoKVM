#!/bin/sh
set -eu

TARGET="go"
DEST="/kvmapp/server/NanoKVM-Server"
SRC="/kvmapp/backends/NanoKVM-Server.go"
FALLBACK="/kvmapp/server/NanoKVM-Server.go.bak"
RUNTIME="/tmp/server/NanoKVM-Server"
STATE="/etc/kvm/backend"
LOG="/tmp/nanokvm-backend-switch.log"

if [ ! -x "$SRC" ] && [ -x "$FALLBACK" ]; then
  SRC="$FALLBACK"
fi

{
  echo "$(date): switching to $TARGET backend"

  if [ ! -x "$SRC" ]; then
    echo "missing executable backend binary: $SRC"
    exit 1
  fi

  cp "$SRC" "$DEST"
  chmod 0755 "$DEST"
  echo "$TARGET" > "$STATE"

  nohup sh -c "sleep 1; killall NanoKVM-Server 2>/dev/null || true; sleep 1; rm -f '$RUNTIME'; cp '$SRC' '$RUNTIME'; chmod 0755 '$RUNTIME'; nohup '$RUNTIME' >/tmp/nanokvm-server.log 2>&1 &" >>"$LOG" 2>&1 &
} >>"$LOG" 2>&1
