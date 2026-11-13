#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# == 0 ]] || { echo "usage: $0" >&2; exit 2; }
TARGET="riscv64gc-unknown-linux-musl"
METADATA="$(cargo metadata --manifest-path "$ROOT/Cargo.toml" --no-deps --format-version 1 --locked --offline)"
TARGET_DIR="$(printf '%s' "$METADATA" | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
RESTORE_TARGET_DIR="${NANOKVM_RESTORE_TARGET_DIR:-$TARGET_DIR/restore-runtime}"
HELPER="$RESTORE_TARGET_DIR/$TARGET/release/nanokvm-app-recovery"

# Consistency checks only. Both RV64 files are read as data, never executed here.
python3 -B "$ROOT/../scripts/app-recovery-binding.py" verify \
  --backend "$TARGET_DIR/$TARGET/release/nanokvm-rust-server" --helper "$HELPER"
NANOKVM_APP_RECOVERY_BINDING="$(python3 -B "$ROOT/../scripts/app-recovery-binding.py" prepare \
  --helper "$HELPER" --directory "$TARGET_DIR/app-recovery-bindings")"
export NANOKVM_APP_RECOVERY_BINDING

# Explicit opt-in: these tests require a real bound image and the exact retained
# predecessor evidence. They cannot silently pass in an ordinary unbound run.
cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline --lib \
  --features app-bootstrap-bound-test-fixture -- \
  update::app_bootstrap::root_tests:: --nocapture --test-threads=1
