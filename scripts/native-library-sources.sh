#!/usr/bin/env bash
# libkvm.so and libkvm_mmf.so are committed binaries. They are built with
# MaixCDK from the sources named below, outside the application build, so a
# source can change without the libraries following. The manifest
# server-rust/native/library-sources.sha256 records every source and both
# libraries as they were when the libraries were built.
#
#   native-library-sources.sh check   fail when a source or library differs
#   native-library-sources.sh write   record the present state; run this only
#                                     right after rebuilding both libraries
#                                     from these sources and committing them
#
# NATIVE_SOURCES_ROOT names another checkout (the test uses a scratch copy).
set -euo pipefail

ROOT="${NATIVE_SOURCES_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
MANIFEST=server-rust/native/library-sources.sha256
SOURCES=(
	support/sg2002/additional/kvm
	support/sg2002/additional/kvm_mmf
	support/sg2002/additional/vision
	support/sg2002/additional/peripheral
	support/sg2002/additional/sophgo-middleware
)
LIBRARIES=(
	server-rust/native/dl_lib/libkvm.so
	server-rust/native/dl_lib/libkvm_mmf.so
)

current() {
	cd "$ROOT"
	local files
	files="$(git ls-files -- "${SOURCES[@]}" | LC_ALL=C sort)"
	[ -n "$files" ] || {
		echo "native-library-sources: no tracked source found" >&2
		return 1
	}
	# shellcheck disable=SC2086 # tracked names here hold no whitespace
	sha256sum $files "${LIBRARIES[@]}"
}

case "${1:-}" in
write)
	current > "$ROOT/$MANIFEST.new"
	mv -f "$ROOT/$MANIFEST.new" "$ROOT/$MANIFEST"
	echo "native-library-sources: recorded $(wc -l < "$ROOT/$MANIFEST") files in $MANIFEST"
	;;
check)
	[ -f "$ROOT/$MANIFEST" ] || {
		echo "native-library-sources: $MANIFEST is missing" >&2
		exit 1
	}
	if ! difference="$(diff <(current) "$ROOT/$MANIFEST")"; then
		echo "native-library-sources: the libraries were not built from these sources:" >&2
		printf '%s\n' "$difference" | sed -n 's/^[<>] [0-9a-f]*  /  /p' | LC_ALL=C sort -u >&2
		echo "rebuild libkvm.so and libkvm_mmf.so, commit them, then run: $0 write" >&2
		exit 1
	fi
	echo "native-library-sources: PASS ($(wc -l < "$ROOT/$MANIFEST") files)"
	;;
*)
	echo "usage: $0 check|write" >&2
	exit 2
	;;
esac
