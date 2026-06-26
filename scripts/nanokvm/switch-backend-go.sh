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

stop_backend() {
  signal="$1"

  for pid in $(pidof NanoKVM-Server 2>/dev/null || true); do
    state=$(awk '{print $3}' /proc/$pid/stat 2>/dev/null || true)
    if [ "$state" = D ]; then
      echo "skip D-state NanoKVM-Server pid $pid"
      continue
    fi

    if [ "$signal" = KILL ]; then
      kill -9 "$pid" 2>/dev/null || true
    else
      kill "$pid" 2>/dev/null || true
    fi
  done
}

restart_backend() {
  sleep 1
  stop_backend TERM
  sleep 1
  stop_backend KILL
  sleep 1

  rm -f "$RUNTIME"
  cp "$SRC" "$RUNTIME"
  chmod 0755 "$RUNTIME"
  (
    cd "$(dirname "$RUNTIME")"
    setsid ./NanoKVM-Server >/tmp/nanokvm-server.log 2>&1 < /dev/null &
  )
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
