#!/usr/bin/env bash
# The superseded RC11 release helpers refuse to run unless HARDENED_LEGACY_RC11=1
# asks for them. Both runs stop before any release command: the environment is
# empty and PATH holds only bash and dirname, so gh, curl, openssl and the
# signing tools are out of reach even if a guard were missing.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() {
    echo "legacy RC11 helper test: $*" >&2
    exit 1
}

mkdir "$TEST_ROOT/bin" "$TEST_ROOT/home"
for tool in bash dirname; do
    ln -s "$(command -v "$tool")" "$TEST_ROOT/bin/$tool"
done

for script in prepare-combined-rc11-release.sh publish-combined-rc11-release.sh; do
    status=0
    env -i PATH="$TEST_ROOT/bin" HOME="$TEST_ROOT/home" \
        bash "$ROOT_DIR/scripts/$script" > "$TEST_ROOT/out" 2>&1 || status=$?
    [ "$status" = 2 ] || fail "$script without legacy mode exited $status: $(cat "$TEST_ROOT/out")"
    grep -q 'HARDENED_LEGACY_RC11=1' "$TEST_ROOT/out" || fail "$script did not say how to run it"

    # Legacy mode passes the guard and reaches the script's own first check.
    status=0
    env -i PATH="$TEST_ROOT/bin" HOME="$TEST_ROOT/home" HARDENED_LEGACY_RC11=1 \
        bash "$ROOT_DIR/scripts/$script" > "$TEST_ROOT/out" 2>&1 || status=$?
    [ "$status" = 1 ] || fail "$script in legacy mode exited $status: $(cat "$TEST_ROOT/out")"
    grep -q 'is required' "$TEST_ROOT/out" || fail "$script in legacy mode: $(cat "$TEST_ROOT/out")"
done

echo "legacy RC11 helpers: PASS"
