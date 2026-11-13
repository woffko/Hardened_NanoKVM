#!/usr/bin/env bash
# The committed native libraries match the sources they are built from, by the
# manifest of scripts/native-library-sources.sh. In a scratch copy, a changed
# source, a changed library and a new source file must each fail the check, and
# a library that names a build directory under /home/ must not be recorded.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CHECK="$ROOT_DIR/scripts/native-library-sources.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fail() {
	echo "native library sources test: $*" >&2
	exit 1
}

"$CHECK" check || fail "the committed libraries do not match their sources"

git -C "$T" init -q
(
	cd "$ROOT_DIR"
	git ls-files -- support/sg2002/additional server-rust/native/dl_lib/libkvm.so \
		server-rust/native/dl_lib/libkvm_mmf.so server-rust/native/library-sources.sha256 |
		while IFS= read -r file; do
			mkdir -p "$T/$(dirname "$file")"
			cp "$file" "$T/$file"
		done
)
git -C "$T" add -A
git -C "$T" -c user.name=test -c user.email=test@invalid commit -q -m scratch
scratch() {
	NATIVE_SOURCES_ROOT="$T" "$CHECK" check >"$T/../$(basename "$T").out" 2>&1
}
restore() {
	git -C "$T" checkout -q -- .
	git -C "$T" clean -qfd
}
trap 'rm -rf "$T" "$T/../$(basename "$T").out"' EXIT
scratch || fail "the scratch copy does not pass: $(cat "$T/../$(basename "$T").out")"

source=support/sg2002/additional/kvm/src/kvm_vision.cpp
printf '\n// changed\n' >> "$T/$source"
if scratch; then fail "a changed source passed"; fi
grep -q "$source" "$T/../$(basename "$T").out" || fail "the changed source is not named"
restore

printf 'x' >> "$T/server-rust/native/dl_lib/libkvm_mmf.so"
if scratch; then fail "a changed library passed"; fi
grep -q 'libkvm_mmf.so' "$T/../$(basename "$T").out" || fail "the changed library is not named"
restore

# A library that carries the build directory of one machine: neither recorded
# nor accepted once it is in the manifest.
printf '/home/builder/sdk/components/kvm/src/kvm_vision.cpp' >> "$T/server-rust/native/dl_lib/libkvm.so"
if NATIVE_SOURCES_ROOT="$T" "$CHECK" write >"$T/../$(basename "$T").out" 2>&1; then
	fail "a library that names a home directory was recorded"
fi
grep -q 'libkvm.so names a path under /home/' "$T/../$(basename "$T").out" ||
	fail "the library with the local path is not named"
(cd "$T" && sha256sum $(git ls-files -- support/sg2002/additional | LC_ALL=C sort) \
	server-rust/native/dl_lib/libkvm.so server-rust/native/dl_lib/libkvm_mmf.so \
	> server-rust/native/library-sources.sha256)
if scratch; then fail "a recorded library that names a home directory passed"; fi
grep -q 'libkvm.so names a path under /home/' "$T/../$(basename "$T").out" ||
	fail "the recorded library with the local path is not named"
restore

printf 'int added;\n' > "$T/support/sg2002/additional/kvm/src/added.c"
git -C "$T" add -- support/sg2002/additional/kvm/src/added.c
if scratch; then fail "a new source file passed"; fi
grep -q 'added.c' "$T/../$(basename "$T").out" || fail "the new source is not named"
git -C "$T" rm -q -f --cached support/sg2002/additional/kvm/src/added.c
restore

rm "$T/server-rust/native/library-sources.sha256"
if scratch; then fail "a missing manifest passed"; fi
echo "native library sources test: PASS"
