#!/usr/bin/env bash
# The superseded RC11 and the published RC12 release helpers refuse to run
# unless HARDENED_LEGACY_RC11=1 or HARDENED_LEGACY_RC12=1 asks for them. Every
# run stops before any release command: the environment is empty and PATH holds
# only bash and dirname, so git, gh, curl, openssl and the signing tools are out
# of reach even if a guard were missing.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() {
    echo "legacy release helper test: $*" >&2
    exit 1
}

mkdir "$TEST_ROOT/bin" "$TEST_ROOT/home"
for tool in bash dirname; do
    ln -s "$(command -v "$tool")" "$TEST_ROOT/bin/$tool"
done

for release in rc11 rc12; do
    mode="HARDENED_LEGACY_${release^^}"
    for script in "prepare-combined-$release-release.sh" "publish-combined-$release-release.sh"; do
        status=0
        env -i PATH="$TEST_ROOT/bin" HOME="$TEST_ROOT/home" \
            bash "$ROOT_DIR/scripts/$script" > "$TEST_ROOT/out" 2>&1 || status=$?
        [ "$status" = 2 ] || fail "$script without legacy mode exited $status: $(cat "$TEST_ROOT/out")"
        grep -q "$mode=1" "$TEST_ROOT/out" || fail "$script did not say how to run it"

        # Legacy mode passes the guard and stops at the script's own checks.
        status=0
        env -i PATH="$TEST_ROOT/bin" HOME="$TEST_ROOT/home" "$mode=1" \
            bash "$ROOT_DIR/scripts/$script" > "$TEST_ROOT/out" 2>&1 || status=$?
        [ "$status" != 0 ] && [ "$status" != 2 ] || \
            fail "$script in legacy mode exited $status: $(cat "$TEST_ROOT/out")"
        ! grep -q "$mode=1" "$TEST_ROOT/out" || fail "$script in legacy mode: $(cat "$TEST_ROOT/out")"
    done
done

echo "legacy release helpers: PASS"
