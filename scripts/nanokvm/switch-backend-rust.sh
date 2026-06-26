#!/bin/sh
set -eu

TARGET="rust"
DEST="/kvmapp/server/NanoKVM-Server"
SRC="/kvmapp/backends/NanoKVM-Server.rust"
RUNTIME="/tmp/server/NanoKVM-Server"
STATE="/etc/kvm/backend"
LOG="/tmp/nanokvm-backend-switch.log"

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
  nohup "$RUNTIME" >/tmp/nanokvm-server.log 2>&1 &
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
