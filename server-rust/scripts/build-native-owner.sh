#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="riscv64gc-unknown-linux-musl"
[[ $# == 0 ]] || { echo "usage: $0" >&2; exit 2; }
unset NANOKVM_SSH_RUNTIME_BINDING
export RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/restore-runtime}"
export CC_riscv64gc_unknown_linux_musl="${CC_riscv64gc_unknown_linux_musl:-clang}"
export CFLAGS_riscv64gc_unknown_linux_musl="${CFLAGS_riscv64gc_unknown_linux_musl:---target=riscv64-unknown-linux-musl -march=rv64gc -mabi=lp64d}"
cargo build --manifest-path "$ROOT/Cargo.toml" --release --target "$TARGET" \
  --no-default-features --bin nanokvm-native-owner --bin nanokvm-native-broker \
  --bin nanokvm-native-ctl --locked --offline
METADATA="$(cargo metadata --manifest-path "$ROOT/Cargo.toml" --no-deps --format-version 1 --locked --offline)"
TARGET_DIR="$(printf '%s' "$METADATA" | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')"
for NAME in nanokvm-native-owner nanokvm-native-broker nanokvm-native-ctl; do
  BINARY="$TARGET_DIR/$TARGET/release/$NAME"
  HEADER="$(LC_ALL=C readelf -h "$BINARY")"
  PROGRAMS="$(LC_ALL=C readelf -l "$BINARY")"
  DYNAMIC="$(LC_ALL=C readelf -d "$BINARY")"
  case "$HEADER" in *Class:*ELF64*Machine:*RISC-V*) ;; *) echo "$NAME is not RV64 ELF64" >&2; exit 1 ;; esac
  case "$PROGRAMS" in *INTERP*) echo "$NAME unexpectedly has an interpreter" >&2; exit 1 ;; esac
  case "$DYNAMIC" in *NEEDED*|*RPATH*|*RUNPATH*) echo "$NAME unexpectedly loads shared libraries" >&2; exit 1 ;; esac
  echo "$NAME: static RISC-V ELF verified (not yet packaged/deployed)"
done
