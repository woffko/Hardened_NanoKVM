#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# == 0 ]] || { echo "usage: $0" >&2; exit 2; }
TARGET="riscv64gc-unknown-linux-musl"
METADATA="$(cargo metadata --manifest-path "$ROOT/Cargo.toml" --no-deps --format-version 1 --locked --offline)"
TARGET_DIR="$(printf '%s' "$METADATA" | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
STATIC_DIR="${NANOKVM_RESTORE_TARGET_DIR:-$TARGET_DIR/restore-runtime}/$TARGET/release"
python3 -B "$ROOT/../scripts/app-recovery-binding.py" verify \
  --backend "$TARGET_DIR/$TARGET/release/nanokvm-rust-server" --helper "$STATIC_DIR/nanokvm-app-recovery"
NANOKVM_APP_RECOVERY_BINDING="$(python3 -B "$ROOT/../scripts/app-recovery-binding.py" prepare \
  --helper "$STATIC_DIR/nanokvm-app-recovery" --directory "$TARGET_DIR/app-recovery-bindings")"
export NANOKVM_APP_RECOVERY_BINDING
for role in owner broker ctl recovery; do
  python3 -B "$ROOT/../scripts/native-runtime-binding.py" "$role" verify \
    --backend "$TARGET_DIR/$TARGET/release/nanokvm-rust-server" --helper "$STATIC_DIR/nanokvm-native-$role"
done
NANOKVM_NATIVE_OWNER_BINDING="$(python3 -B "$ROOT/../scripts/native-runtime-binding.py" owner prepare --helper "$STATIC_DIR/nanokvm-native-owner" --directory "$TARGET_DIR/native-runtime-bindings")"
NANOKVM_NATIVE_BROKER_BINDING="$(python3 -B "$ROOT/../scripts/native-runtime-binding.py" broker prepare --helper "$STATIC_DIR/nanokvm-native-broker" --directory "$TARGET_DIR/native-runtime-bindings")"
NANOKVM_NATIVE_CTL_BINDING="$(python3 -B "$ROOT/../scripts/native-runtime-binding.py" ctl prepare --helper "$STATIC_DIR/nanokvm-native-ctl" --directory "$TARGET_DIR/native-runtime-bindings")"
NANOKVM_NATIVE_RECOVERY_BINDING="$(python3 -B "$ROOT/../scripts/native-runtime-binding.py" recovery prepare --helper "$STATIC_DIR/nanokvm-native-recovery" --directory "$TARGET_DIR/native-runtime-bindings")"
export NANOKVM_NATIVE_OWNER_BINDING NANOKVM_NATIVE_BROKER_BINDING NANOKVM_NATIVE_CTL_BINDING NANOKVM_NATIVE_RECOVERY_BINDING
# Explicit opt-in. Actual static RV64 bytes are data only, never executed here.
cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline --lib \
  --features app-bootstrap-bound-test-fixture -- \
  update::native_bootstrap::root_tests:: --nocapture --test-threads=1
cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline --lib \
  --features app-bootstrap-bound-test-fixture,sandbox-test-fixture -- \
  update::app_trial::tests::actual_frozen_startup_keeps_identity_and_refuses_generation_under_real_parent_exclusions \
  --nocapture --test-threads=1
