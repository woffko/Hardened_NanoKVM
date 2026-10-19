#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="riscv64gc-unknown-linux-musl"
SYSROOT_LIB="${NANOKVM_SYSROOT_LIB:-$ROOT/sysroot/lib}"

if [[ ! -f "$SYSROOT_LIB/libc.so" ]]; then
  echo "missing $SYSROOT_LIB/libc.so" >&2
  echo "copy NanoKVM runtime libs into server-rust/sysroot/lib or set NANOKVM_SYSROOT_LIB" >&2
  exit 1
fi

if [[ ! -e "$SYSROOT_LIB/libgcc_s.so" && -f "$SYSROOT_LIB/libgcc_s.so.1" ]]; then
  ln -sf libgcc_s.so.1 "$SYSROOT_LIB/libgcc_s.so"
fi

if [[ ! -e "$SYSROOT_LIB/libgcc_s.so" ]]; then
  echo "missing $SYSROOT_LIB/libgcc_s.so or libgcc_s.so.1" >&2
  exit 1
fi

RUST_SYSROOT="$(rustc --print sysroot)"
CRT="$RUST_SYSROOT/lib/rustlib/$TARGET/lib/self-contained"

for obj in crt1.o crti.o crtbegin.o crtend.o crtn.o; do
  if [[ ! -f "$CRT/$obj" ]]; then
    echo "missing Rust CRT object: $CRT/$obj" >&2
    exit 1
  fi
done

# Build all six static helpers before the dynamic backend. None has embedded
# bindings of its own, so this cannot recursively embed previous builds.
METADATA="$(cargo metadata --manifest-path "$ROOT/Cargo.toml" --no-deps --format-version 1 --locked --offline)"
TARGET_DIR="$(printf '%s' "$METADATA" | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
RESTORE_TARGET_DIR="${NANOKVM_RESTORE_TARGET_DIR:-$TARGET_DIR/restore-runtime}"
mkdir -p "$RESTORE_TARGET_DIR"
RESTORE_TARGET_DIR="$(cd "$RESTORE_TARGET_DIR" && pwd)"
if [[ "$RESTORE_TARGET_DIR" == "$TARGET_DIR" ]]; then
  echo "static helper must use a separate Cargo target directory" >&2
  exit 1
fi
CARGO_TARGET_DIR="$RESTORE_TARGET_DIR" "$ROOT/scripts/build-restore-runtime.sh" --locked --offline
CARGO_TARGET_DIR="$RESTORE_TARGET_DIR" "$ROOT/scripts/build-app-recovery.sh" --locked --offline
CARGO_TARGET_DIR="$RESTORE_TARGET_DIR" "$ROOT/scripts/build-native-owner.sh"
NANOKVM_SSH_RUNTIME_BINDING="$(python3 "$ROOT/../scripts/ssh-runtime-binding.py" prepare \
  --helper "$RESTORE_TARGET_DIR/$TARGET/release/nanokvm-ssh-sandbox" \
  --directory "$TARGET_DIR/ssh-runtime-bindings")"
export NANOKVM_SSH_RUNTIME_BINDING
NANOKVM_APP_RECOVERY_BINDING="$(python3 "$ROOT/../scripts/app-recovery-binding.py" prepare \
  --helper "$RESTORE_TARGET_DIR/$TARGET/release/nanokvm-app-recovery" \
  --directory "$TARGET_DIR/app-recovery-bindings")"
export NANOKVM_APP_RECOVERY_BINDING
NANOKVM_NATIVE_OWNER_BINDING="$(python3 -B "$ROOT/../scripts/native-runtime-binding.py" owner prepare --helper "$RESTORE_TARGET_DIR/$TARGET/release/nanokvm-native-owner" --directory "$TARGET_DIR/native-runtime-bindings")"
NANOKVM_NATIVE_BROKER_BINDING="$(python3 -B "$ROOT/../scripts/native-runtime-binding.py" broker prepare --helper "$RESTORE_TARGET_DIR/$TARGET/release/nanokvm-native-broker" --directory "$TARGET_DIR/native-runtime-bindings")"
NANOKVM_NATIVE_CTL_BINDING="$(python3 -B "$ROOT/../scripts/native-runtime-binding.py" ctl prepare --helper "$RESTORE_TARGET_DIR/$TARGET/release/nanokvm-native-ctl" --directory "$TARGET_DIR/native-runtime-bindings")"
NANOKVM_NATIVE_RECOVERY_BINDING="$(python3 -B "$ROOT/../scripts/native-runtime-binding.py" recovery prepare --helper "$RESTORE_TARGET_DIR/$TARGET/release/nanokvm-native-recovery" --directory "$TARGET_DIR/native-runtime-bindings")"
export NANOKVM_NATIVE_OWNER_BINDING NANOKVM_NATIVE_BROKER_BINDING NANOKVM_NATIVE_CTL_BINDING NANOKVM_NATIVE_RECOVERY_BINDING

export NANOKVM_SYSROOT_LIB="$SYSROOT_LIB"
export RUSTC_BOOTSTRAP="${RUSTC_BOOTSTRAP:-1}"
export CC_riscv64gc_unknown_linux_musl="${CC_riscv64gc_unknown_linux_musl:-clang}"
export CFLAGS_riscv64gc_unknown_linux_musl="${CFLAGS_riscv64gc_unknown_linux_musl:---target=riscv64-unknown-linux-musl -march=rv64gc -mabi=lp64d}"
export RUSTFLAGS="-Z unstable-options \
-C target-feature=-crt-static \
-C link-self-contained=no \
-C link-arg=$CRT/crt1.o \
-C link-arg=$CRT/crti.o \
-C link-arg=$CRT/crtbegin.o \
-C link-arg=$CRT/crtend.o \
-C link-arg=$CRT/crtn.o \
-C link-arg=--dynamic-linker=/lib/ld-musl-riscv64xthead.so.1 \
-C link-arg=--rpath=/kvmapp/server/dl_lib"

cargo build \
  --manifest-path "$ROOT/Cargo.toml" \
  --release \
  --target "$TARGET" \
  --bin nanokvm-rust-server \
  --bin nanokvm-hwmon \
  --features linked-libkvm \
  "$@"
