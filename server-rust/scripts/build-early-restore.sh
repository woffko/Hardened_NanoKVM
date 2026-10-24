#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="riscv64gc-unknown-linux-musl"
for argument in "$@"; do
  case "$argument" in
    --locked|--offline) ;;
    *) echo "usage: $0 [--locked] [--offline]" >&2; exit 2 ;;
  esac
done

unset NANOKVM_SSH_RUNTIME_BINDING NANOKVM_APP_RECOVERY_BINDING
unset NANOKVM_NATIVE_OWNER_BINDING NANOKVM_NATIVE_BROKER_BINDING NANOKVM_NATIVE_CTL_BINDING NANOKVM_NATIVE_RECOVERY_BINDING
export RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/restore-runtime}"
export CC_riscv64gc_unknown_linux_musl="${CC_riscv64gc_unknown_linux_musl:-clang}"
export CFLAGS_riscv64gc_unknown_linux_musl="${CFLAGS_riscv64gc_unknown_linux_musl:---target=riscv64-unknown-linux-musl -march=rv64gc -mabi=lp64d}"
cargo build \
  --manifest-path "$ROOT/Cargo.toml" \
  --release \
  --target "$TARGET" \
  --no-default-features \
  --bin nanokvm-early-restore \
  --locked \
  --offline

METADATA="$(cargo metadata --manifest-path "$ROOT/Cargo.toml" --no-deps --format-version 1 --locked --offline)"
TARGET_DIR="$(printf '%s' "$METADATA" | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
BINARY="$TARGET_DIR/$TARGET/release/nanokvm-early-restore"
HEADER="$(LC_ALL=C readelf -h "$BINARY")"
PROGRAMS="$(LC_ALL=C readelf -l "$BINARY")"
DYNAMIC="$(LC_ALL=C readelf -d "$BINARY")"
case "$HEADER" in
  *Class:*ELF64*Type:*EXEC*Machine:*RISC-V*) ;;
  *) echo "early restore is not an ELF64 RISC-V executable" >&2; exit 1 ;;
esac
case "$PROGRAMS" in
  *INTERP*) echo "early restore unexpectedly has an ELF interpreter" >&2; exit 1 ;;
esac
case "$DYNAMIC" in
  *NEEDED*|*RPATH*|*RUNPATH*) echo "early restore unexpectedly loads shared libraries" >&2; exit 1 ;;
esac
echo "early restore: independent static RISC-V ELF verified (not installed)"
