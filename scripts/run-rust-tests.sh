#!/usr/bin/env bash
# The Rust half of the G1 gate, as one command: every test of server-rust runs
# exactly once, split by IO load. Phase 1 runs all targets at
# RUST_TEST_THREADS_MAIN (16) threads and skips the fsync-heavy
# native_owner::broker::ipc module; phase 2 runs that module alone at
# RUST_TEST_THREADS_IPC (4) threads with backtraces on; then the doctests.
# The build happens first and is flushed, because the writeback of a fresh
# debug build starved fixture fsyncs in the first minute (measured 2026-10-23).
# umask 077 is required: the fixtures stage private files and check their
# modes (about 93 tests fail under 022 for that reason alone).
#
#   RUST_TESTS_PRESSURE_LOG=path   append an IO-pressure sample every 30 s
#   RUST_TEST_THREADS_MAIN=16, RUST_TEST_THREADS_IPC=4
#
# Prints build_exit, phase1_exit, phase2_exit, doc_exit and the seconds of each
# phase; exits non-zero when any phase fails. --no-fail-fast keeps every target
# running after a failure, so one log holds the whole picture.
set -uo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT" || exit 2
MANIFEST=server-rust/Cargo.toml
MAIN="${RUST_TEST_THREADS_MAIN:-16}"
IPC="${RUST_TEST_THREADS_IPC:-4}"
umask 077
echo "rust tests on $(git rev-parse --short HEAD 2>/dev/null || echo '?') ($(git status --short 2>/dev/null | wc -l) dirty) $(date -u +%FT%TZ) threads=$MAIN/$IPC"
sampler=""
if [ -n "${RUST_TESTS_PRESSURE_LOG:-}" ] && [ -r /proc/pressure/io ]; then
	( while true; do echo "$(date -u +%H:%M:%S) $(head -1 /proc/pressure/io)" >> "$RUST_TESTS_PRESSURE_LOG"; sleep 30; done ) &
	sampler=$!
	trap '[ -z "$sampler" ] || kill "$sampler" 2>/dev/null' EXIT
fi
phase() {
	# phase NAME ARGS...: time one cargo invocation and report its exit
	name=$1; shift
	start=$(date +%s)
	"$@"
	code=$?
	echo "${name}_exit=$code"
	echo "${name}_seconds=$(( $(date +%s) - start ))"
	return $code
}
phase build cargo test --manifest-path "$MANIFEST" --locked --offline \
	--all-targets --features sandbox-test-fixture --no-run
build=$?
sync
phase phase1 env NANOKVM_APP_SLOT_TEST_TRACE=1 cargo test --manifest-path "$MANIFEST" --locked --offline \
	--no-fail-fast --all-targets --features sandbox-test-fixture -- --include-ignored --nocapture \
	--test-threads="$MAIN" --skip native_owner::broker::ipc
phase1=$?
phase phase2 env RUST_BACKTRACE=1 NANOKVM_APP_SLOT_TEST_TRACE=1 cargo test --manifest-path "$MANIFEST" --locked --offline \
	--no-fail-fast --lib --features sandbox-test-fixture -- --include-ignored --nocapture \
	--test-threads="$IPC" native_owner::broker::ipc
phase2=$?
phase doc cargo test --manifest-path "$MANIFEST" --locked --offline --no-fail-fast --doc \
	--features sandbox-test-fixture
doc=$?
echo "rust tests: build=$build phase1=$phase1 phase2=$phase2 doc=$doc on $(git rev-parse --short HEAD 2>/dev/null || echo '?') ($(git status --short 2>/dev/null | wc -l) dirty)"
[ "$build" = 0 ] && [ "$phase1" = 0 ] && [ "$phase2" = 0 ] && [ "$doc" = 0 ]
