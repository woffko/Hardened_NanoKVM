#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${RUST_TARGET:-riscv64gc-unknown-linux-musl}"
APP_VERSION="${APP_VERSION:-2.1.3}"
KVM_SYSTEM_SOURCE="${KVM_SYSTEM_SOURCE:-$ROOT/support/sg2002/kvm_system/build/kvm_system}"
STAGE_DIR="${STAGE_DIR:-$ROOT/build/kvmapp-rust}"
EXTRA_NATIVE_LIB_DIR="${EXTRA_NATIVE_LIB_DIR:-$ROOT/build/latestbuildroot/vendor-runtime-v2/kvmapp-dl-lib}"

"$ROOT/server-rust/scripts/build-linked-libkvm.sh"

RUST_TARGET="$TARGET" \
APP_VERSION="$APP_VERSION" \
KVM_SYSTEM_SOURCE="$KVM_SYSTEM_SOURCE" \
STAGE_DIR="$STAGE_DIR" \
EXTRA_NATIVE_LIB_DIR="$EXTRA_NATIVE_LIB_DIR" \
	"$ROOT/scripts/package-rust-kvmapp.sh"

test "$(cat "$STAGE_DIR/kvmapp/version")" = "$APP_VERSION"
test -x "$STAGE_DIR/kvmapp/server/NanoKVM-Server"
python3 "$ROOT/scripts/ssh-runtime-binding.py" inspect \
  --backend "$STAGE_DIR/kvmapp/server/NanoKVM-Server" --quiet
python3 "$ROOT/scripts/app-recovery-binding.py" verify \
  --backend "$STAGE_DIR/kvmapp/server/NanoKVM-Server" \
  --helper "$STAGE_DIR/kvmapp/system/bin/nanokvm-app-recovery"
test -x "$STAGE_DIR/kvmapp/hwmon/nanokvm-hwmon"
test -x "$STAGE_DIR/kvmapp/kvm_system/kvm_system"
if readelf -d "$STAGE_DIR/kvmapp/kvm_system/kvm_system" 2>/dev/null | grep -Eq '\((RPATH|RUNPATH)\)'; then
	echo "kvm_system unexpectedly contains RPATH/RUNPATH" >&2
	exit 1
fi
test -f "$STAGE_DIR/kvmapp/server/web/index.html"
test -e "$STAGE_DIR/kvmapp/server/dl_lib/libopencv_video.so.409"
test -e "$STAGE_DIR/kvmapp/server/dl_lib/libprotobuf.so.32"
test ! -e "$STAGE_DIR/kvmapp/server/dl_lib/libz.so"
test ! -e "$STAGE_DIR/kvmapp/server/dl_lib/libz.so.1"
test ! -e "$STAGE_DIR/kvmapp/server/dl_lib/libz.so.1.3"
sh -n "$STAGE_DIR/kvmapp/system/init.d/S01fs"
sh -n "$STAGE_DIR/kvmapp/system/init.d/S95nanokvm"

sha256sum \
	"$STAGE_DIR/kvmapp/server/NanoKVM-Server" \
	"$STAGE_DIR/kvmapp/hwmon/nanokvm-hwmon" \
	"$STAGE_DIR/kvmapp/kvm_system/kvm_system"
printf 'kvmapp staging ready: %s\n' "$STAGE_DIR/kvmapp"
