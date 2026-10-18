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

# This privileged helper must not load the application's mutable vendor dl_lib
# before it establishes its own boundary. Never build it via linked-libkvm.
unset NANOKVM_SSH_RUNTIME_BINDING NANOKVM_APP_RECOVERY_BINDING
export RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/restore-runtime}"
export CC_riscv64gc_unknown_linux_musl="${CC_riscv64gc_unknown_linux_musl:-clang}"
export CFLAGS_riscv64gc_unknown_linux_musl="${CFLAGS_riscv64gc_unknown_linux_musl:---target=riscv64-unknown-linux-musl -march=rv64gc -mabi=lp64d}"
cargo build \
  --manifest-path "$ROOT/Cargo.toml" \
  --release \
  --target "$TARGET" \
  --no-default-features \
  --bin nanokvm-ssh-sandbox \
  --locked \
  --offline

# Ask Cargo for its effective target_directory rather than assume that a caller
# with CARGO_TARGET_DIR built into the default tree.
METADATA="$(cargo metadata --manifest-path "$ROOT/Cargo.toml" --no-deps --format-version 1 --locked --offline)"
TARGET_DIR="$(printf '%s' "$METADATA" | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
BINARY="$TARGET_DIR/$TARGET/release/nanokvm-ssh-sandbox"
HEADER="$(LC_ALL=C readelf -h "$BINARY")"
PROGRAMS="$(LC_ALL=C readelf -l "$BINARY")"
DYNAMIC="$(LC_ALL=C readelf -d "$BINARY")"
case "$HEADER" in
  *Class:*ELF64*Machine:*RISC-V*) ;;
  *) echo "restore runtime helper is not an ELF64 RISC-V binary" >&2; exit 1 ;;
esac
case "$PROGRAMS" in
  *INTERP*) echo "restore runtime helper unexpectedly has an ELF interpreter" >&2; exit 1 ;;
esac
case "$DYNAMIC" in
  *NEEDED*|*RPATH*|*RUNPATH*) echo "restore runtime helper unexpectedly loads shared libraries" >&2; exit 1 ;;
esac
echo "restore runtime helper: static RISC-V ELF verified"
