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
APP_VERSION="${APP_VERSION:-}"
ARTIFACT_NAME="${ARTIFACT_NAME:-nanokvm-kvmapp-rust.tar.gz}"
BASE_ROOTFS_IMAGE="${BASE_ROOTFS_IMAGE:-$BUILD_DIR/sd-image/rootfs.ext}"
KVM_SYSTEM_SOURCE="${KVM_SYSTEM_SOURCE:-}"

restore_kvm_system_helper() {
  dest="$KVMAPP_STAGE/kvm_system/kvm_system"
  tmp="$STAGE_DIR/kvm_system.orig"

  if [ -s "$dest" ]; then
    chmod 0755 "$dest"
    return
  fi

  mkdir -p "$KVMAPP_STAGE/kvm_system"

  if [ -n "$KVM_SYSTEM_SOURCE" ] && [ -s "$KVM_SYSTEM_SOURCE" ]; then
    cp "$KVM_SYSTEM_SOURCE" "$dest"
    chmod 0755 "$dest"
    return
  fi

  if [ -f "$BASE_ROOTFS_IMAGE" ] && command -v debugfs >/dev/null 2>&1; then
    rm -f "$tmp"
    if debugfs -R "dump /kvmapp/kvm_system/kvm_system $tmp" "$BASE_ROOTFS_IMAGE" >/dev/null 2>&1 && [ -s "$tmp" ]; then
      cp "$tmp" "$dest"
      chmod 0755 "$dest"
      return
    fi
  fi

  echo "missing required NanoKVM helper: /kvmapp/kvm_system/kvm_system" >&2
  echo "set KVM_SYSTEM_SOURCE=<path> or BASE_ROOTFS_IMAGE=<rootfs.ext>" >&2
  exit 1
}

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
mkdir -p "$KVMAPP_STAGE/server" "$KVMAPP_STAGE/backends" "$OUT_DIR"
cp -R "$ROOT_DIR/kvmapp/." "$KVMAPP_STAGE/"
restore_kvm_system_helper

if [ -n "$APP_VERSION" ]; then
  printf '%s\n' "$APP_VERSION" > "$KVMAPP_STAGE/version"
elif [ ! -f "$KVMAPP_STAGE/version" ]; then
  printf '0.1.0\n' > "$KVMAPP_STAGE/version"
fi

cp "$RUST_BINARY" "$KVMAPP_STAGE/server/NanoKVM-Server"
chmod 0755 "$KVMAPP_STAGE/server/NanoKVM-Server"
cp "$RUST_BINARY" "$KVMAPP_STAGE/backends/NanoKVM-Server.rust"
chmod 0755 "$KVMAPP_STAGE/backends/NanoKVM-Server.rust"

rm -f "$KVMAPP_STAGE/backends/NanoKVM-Server.go" \
  "$KVMAPP_STAGE/server/NanoKVM-Server.go" \
  "$KVMAPP_STAGE/server/NanoKVM-Server.go.bak"

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
  printf 'app_version: %s\n' "$(cat "$KVMAPP_STAGE/version")"
  printf 'kvm_system_helper: %s\n' "$(wc -c < "$KVMAPP_STAGE/kvm_system/kvm_system" | tr -d ' ') bytes"
} > "$STAGE_DIR/MANIFEST.txt"

if find "$KVMAPP_STAGE" \( -name 'NanoKVM-Server.go' -o -name 'NanoKVM-Server.go.bak' \) | grep -q .; then
  echo "legacy Go backend found in staged kvmapp" >&2
  exit 1
fi

ARCHIVE="$OUT_DIR/$ARTIFACT_NAME"
tar -C "$STAGE_DIR" -czf "$ARCHIVE" kvmapp MANIFEST.txt
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"

echo "$ARCHIVE"
