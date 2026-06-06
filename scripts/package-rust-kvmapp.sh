#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build}"
STAGE_DIR="${STAGE_DIR:-$BUILD_DIR/kvmapp-rust}"
KVMAPP_STAGE="$STAGE_DIR/kvmapp"
OUT_DIR="${OUT_DIR:-$BUILD_DIR/artifacts}"
RUST_TARGET="${RUST_TARGET:-}"
RUST_BINARY="${RUST_BINARY:-}"
WEB_DIST="${WEB_DIST:-$ROOT_DIR/web/dist}"

if [ -z "$RUST_BINARY" ]; then
  if [ -n "$RUST_TARGET" ]; then
    RUST_BINARY="$ROOT_DIR/server-rust/target/$RUST_TARGET/release/nanokvm-rust-server"
  else
    RUST_BINARY="$ROOT_DIR/server-rust/target/release/nanokvm-rust-server"
  fi
fi

if [ ! -x "$RUST_BINARY" ]; then
  echo "missing executable Rust backend: $RUST_BINARY" >&2
  echo "run: make rust-app RUST_TARGET=<target>" >&2
  exit 1
fi

rm -rf "$STAGE_DIR"
mkdir -p "$KVMAPP_STAGE/server" "$OUT_DIR"
cp -R "$ROOT_DIR/kvmapp/." "$KVMAPP_STAGE/"

cp "$RUST_BINARY" "$KVMAPP_STAGE/server/NanoKVM-Server"
chmod 0755 "$KVMAPP_STAGE/server/NanoKVM-Server"

if [ -d "$ROOT_DIR/server/dl_lib" ]; then
  mkdir -p "$KVMAPP_STAGE/server/dl_lib"
  cp -R "$ROOT_DIR/server/dl_lib/." "$KVMAPP_STAGE/server/dl_lib/"
fi

if [ -d "$WEB_DIST" ]; then
  mkdir -p "$KVMAPP_STAGE/server/web"
  cp -R "$WEB_DIST/." "$KVMAPP_STAGE/server/web/"
else
  echo "warning: frontend dist not found at $WEB_DIST; package has no server/web assets" >&2
fi

{
  printf 'artifact: kvmapp-rust\n'
  printf 'source: %s\n' "$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf unknown)"
  printf 'rust_binary: %s\n' "$RUST_BINARY"
  printf 'rust_target: %s\n' "${RUST_TARGET:-host}"
  printf 'web_dist: %s\n' "$WEB_DIST"
} > "$STAGE_DIR/MANIFEST.txt"

ARCHIVE="$OUT_DIR/nanokvm-kvmapp-rust.tar.gz"
tar -C "$STAGE_DIR" -czf "$ARCHIVE" kvmapp MANIFEST.txt
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"

echo "$ARCHIVE"
