#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# == 0 ]] || { echo "usage: $0" >&2; exit 2; }
TARGET="riscv64gc-unknown-linux-musl"
METADATA="$(cargo metadata --manifest-path "$ROOT/Cargo.toml" --no-deps --format-version 1 --locked --offline)"
TARGET_DIR="$(printf '%s' "$METADATA" | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
RESTORE_TARGET_DIR="${NANOKVM_RESTORE_TARGET_DIR:-$TARGET_DIR/restore-runtime}"
NANOKVM_SSH_RUNTIME_BINDING="$(python3 "$ROOT/../scripts/ssh-runtime-binding.py" prepare \
  --helper "$RESTORE_TARGET_DIR/$TARGET/release/nanokvm-ssh-sandbox" \
  --directory "$TARGET_DIR/ssh-runtime-bindings")"
export NANOKVM_SSH_RUNTIME_BINDING

# Host-only exact capture of embedded RV64 bytes. Never execute them on the
# host and never treat this fixture as target/loop/native-login acceptance.
cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline --lib -- \
  --exact update::restore_job::tests::embedded_runtime_has_no_mutable_path_fallback
