#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# == 0 ]] || { echo "usage: $0" >&2; exit 2; }
TARGET="riscv64gc-unknown-linux-musl"
METADATA="$(cargo metadata --manifest-path "$ROOT/Cargo.toml" --no-deps --format-version 1 --locked --offline)"
TARGET_DIR="$(printf '%s' "$METADATA" | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
RESTORE_TARGET_DIR="${NANOKVM_RESTORE_TARGET_DIR:-$TARGET_DIR/restore-runtime}"
NANOKVM_APP_RECOVERY_BINDING="$(python3 "$ROOT/../scripts/app-recovery-binding.py" prepare \
  --helper "$RESTORE_TARGET_DIR/$TARGET/release/nanokvm-app-recovery" \
  --directory "$TARGET_DIR/app-recovery-bindings")"
export NANOKVM_APP_RECOVERY_BINDING

# Host consistency test of exact embedded RV64 bytes, never execute them here.
cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline --lib -- \
  --exact update::app_bootstrap::tests::embedded_recovery_has_no_path_fallback
