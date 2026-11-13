#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BASE_RUNTIME_DIR="${BASE_VENDOR_RUNTIME_DIR:-$ROOT_DIR/build/latestbuildroot/vendor-runtime-source-media-v1}"
KERNEL_DIR="${KERNEL_5_10_265_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-5.10.265-v6/output}"
EXTERNAL_DIR="${EXTERNAL_MODULE_5_10_265_DIR:-$ROOT_DIR/build/latestbuildroot/external-modules-5.10.265-v3/artifacts}"
MEDIA_DIR="${MEDIA_MODULE_5_10_265_DIR:-$ROOT_DIR/build/latestbuildroot/media-modules-5.10.265-v5/artifacts}"
OUTPUT_DIR="${KERNEL_5_10_265_VENDOR_RUNTIME_DIR:-$ROOT_DIR/build/latestbuildroot/vendor-runtime-source-kernel-5.10.265-v1}"
REPORT_DIR="${KERNEL_5_10_265_VENDOR_RUNTIME_REPORT_DIR:-$ROOT_DIR/build/latestbuildroot/vendor-runtime-kernel-5.10.265-v1-report}"
TOOLCHAIN_BIN="${HARDENED_SG2002_TOOLCHAIN_BIN:-/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build/host-tools/gcc/riscv64-linux-musl-x86_64/bin}"
STRIP="$TOOLCHAIN_BIN/riscv64-unknown-linux-musl-strip"
EXPECTED_KERNEL_RELEASE="${EXPECTED_KERNEL_RELEASE:-5.10.265-tag-}"

require_file() {
	[ -f "$1" ] || {
		echo "required runtime candidate input is missing: $1" >&2
		exit 1
	}
}

require_dir() {
	[ -d "$1" ] || {
		echo "required runtime candidate directory is missing: $1" >&2
		exit 1
	}
}

for command in cp depmod find install modinfo sha256sum sort awk cmp rg
do
	command -v "$command" >/dev/null 2>&1 || {
		echo "required command is missing: $command" >&2
		exit 1
	}
done

require_dir "$BASE_RUNTIME_DIR/system/ko"
require_dir "$EXTERNAL_DIR"
require_dir "$MEDIA_DIR"
require_file "$KERNEL_DIR/include/generated/utsrelease.h"
require_file "$KERNEL_DIR/System.map"
require_file "$KERNEL_DIR/report/source-commit.txt"
require_file "$STRIP"

kernel_release="$(sed -n 's/^#define UTS_RELEASE "\(.*\)"$/\1/p' \
	"$KERNEL_DIR/include/generated/utsrelease.h")"
read -r kernel_source_commit < "$KERNEL_DIR/report/source-commit.txt"
if [ "$kernel_release" != "$EXPECTED_KERNEL_RELEASE" ]; then
	echo "unexpected runtime module kernel release: $kernel_release" >&2
	exit 1
fi

if [ -e "$OUTPUT_DIR" ] || [ -e "$REPORT_DIR" ]; then
	echo "refusing to reuse runtime candidate output or report" >&2
	exit 1
fi

mkdir -p "$OUTPUT_DIR" "$REPORT_DIR"
cp -a "$BASE_RUNTIME_DIR/." "$OUTPUT_DIR/"

EXPECTED_LIST="$REPORT_DIR/expected-modules.txt"
REPLACED_LIST="$REPORT_DIR/replaced-modules.tsv"
ACTUAL_LIST="$REPORT_DIR/actual-modules.txt"
find "$BASE_RUNTIME_DIR/system/ko" -type f -name '*.ko' -printf '%P\n' | \
	LC_ALL=C sort > "$EXPECTED_LIST"
: > "$REPLACED_LIST"

replace_by_basename() {
	origin="$1"
	source="$2"
	name="$(basename "$source")"
	mapfile -t destinations < <(find "$OUTPUT_DIR/system/ko" -type f \
		-name "$name" -printf '%P\n')
	if [ "${#destinations[@]}" -ne 1 ]; then
		echo "expected one runtime destination for $name, found ${#destinations[@]}" >&2
		exit 1
	fi
	destination="${destinations[0]}"
	install -m 0644 "$source" "$OUTPUT_DIR/system/ko/$destination"
	printf '%s\t%s\n' "$origin" "$destination" >> "$REPLACED_LIST"
}

while IFS= read -r source
do
	replace_by_basename in-tree "$source"
done < <(find "$KERNEL_DIR" -type f -name '*.ko' | LC_ALL=C sort)

while IFS= read -r source
do
	relative="${source#"$EXTERNAL_DIR/"}"
	require_file "$OUTPUT_DIR/system/ko/$relative"
	install -m 0644 "$source" "$OUTPUT_DIR/system/ko/$relative"
	printf 'external\t%s\n' "$relative" >> "$REPLACED_LIST"
done < <(find "$EXTERNAL_DIR" -type f -name '*.ko' | LC_ALL=C sort)

while IFS= read -r source
do
	replace_by_basename media "$source"
done < <(find "$MEDIA_DIR" -type f -name '*.ko' | LC_ALL=C sort)

LC_ALL=C sort -k2,2 "$REPLACED_LIST" -o "$REPLACED_LIST"
if [ "$(wc -l < "$REPLACED_LIST")" -ne 57 ]; then
	echo "runtime replacement inventory is not 57 modules" >&2
	exit 1
fi
if [ "$(cut -f2 "$REPLACED_LIST" | LC_ALL=C sort -u | wc -l)" -ne 57 ]; then
	echo "runtime replacement inventory contains duplicate destinations" >&2
	exit 1
fi

find "$OUTPUT_DIR/system/ko" -type f -name '*.ko' -printf '%P\n' | \
	LC_ALL=C sort > "$ACTUAL_LIST"
cmp -s "$EXPECTED_LIST" "$ACTUAL_LIST" || {
	echo "runtime module inventory changed while replacing kernel modules" >&2
	diff -u "$EXPECTED_LIST" "$ACTUAL_LIST" >&2 || true
	exit 1
}

while IFS= read -r relative
do
	module="$OUTPUT_DIR/system/ko/$relative"
	"$STRIP" --strip-unneeded "$module"
	chmod 0644 "$module"
done < "$ACTUAL_LIST"

MANIFEST="$REPORT_DIR/module-manifest.tsv"
printf 'origin\tpath\tname\tdepends\tvermagic\tsrcversion\tsha256\n' > "$MANIFEST"
while IFS=$'\t' read -r origin relative
do
	module="$OUTPUT_DIR/system/ko/$relative"
	vermagic="$(modinfo -F vermagic "$module" | tr '\r\n' ' ')"
	case "$vermagic" in
		"$kernel_release "*) ;;
		*)
			echo "runtime module vermagic mismatch: $relative: $vermagic" >&2
			exit 1
			;;
	esac
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$origin" "$relative" \
		"$(modinfo -F name "$module")" \
		"$(modinfo -F depends "$module")" \
		"$vermagic" \
		"$(modinfo -F srcversion "$module")" \
		"$(sha256sum "$module" | awk '{print $1}')" >> "$MANIFEST"
done < "$REPLACED_LIST"

DEPMOD_ROOT="$REPORT_DIR/depmod-root"
DEPMOD_MODULE_DIR="$DEPMOD_ROOT/lib/modules/$kernel_release"
mkdir -p "$DEPMOD_MODULE_DIR"
while IFS= read -r relative
do
	cp "$OUTPUT_DIR/system/ko/$relative" "$DEPMOD_MODULE_DIR/$(basename "$relative")"
done < "$ACTUAL_LIST"
if ! depmod -e -F "$KERNEL_DIR/System.map" -b "$DEPMOD_ROOT" \
	"$kernel_release" 2> "$REPORT_DIR/depmod.stderr"; then
	cat "$REPORT_DIR/depmod.stderr" >&2
	exit 1
fi
if rg -n 'needs unknown symbol|disagrees about version|not an ELF' \
	"$REPORT_DIR/depmod.stderr" > "$REPORT_DIR/depmod-errors.txt"; then
	cat "$REPORT_DIR/depmod-errors.txt" >&2
	exit 1
fi

cat > "$OUTPUT_DIR/system/ko/hardened-kernel-5.10.265-provenance.txt" <<EOF
kernel_release=$kernel_release
kernel_source_commit=$kernel_source_commit
in_tree_modules=24
external_modules=30
media_modules=3
redistribution=disabled-pending-license-grant
EOF
cp "$OUTPUT_DIR/system/ko/hardened-kernel-5.10.265-provenance.txt" \
	"$OUTPUT_DIR/system/ko/hardened-kernel-provenance.txt"

cat > "$OUTPUT_DIR/system/ko/hardened-source-media-provenance.txt" <<EOF
kernel_release=$kernel_release
sophgo_current_commit=aa542c41df94f7bc656cb740f6622a5dca7dc403
sophgo_vc_commit=5ed7cc28daf7194885d87df2aa534a27a1956c70
soph_vcodec_sha256=$(sha256sum "$OUTPUT_DIR/system/ko/soph_vcodec.ko" | awk '{print $1}')
soph_jpeg_sha256=$(sha256sum "$OUTPUT_DIR/system/ko/soph_jpeg.ko" | awk '{print $1}')
soph_vc_driver_sha256=$(sha256sum "$OUTPUT_DIR/system/ko/soph_vc_driver.ko" | awk '{print $1}')
device_acceptance=pending-recovery-sd
redistribution=disabled-pending-license-grant
EOF

find "$OUTPUT_DIR" -type f -exec touch -d '@0' {} +
find "$OUTPUT_DIR" -type d -exec touch -d '@0' {} +
sha256sum "$MANIFEST" "$REPLACED_LIST" "$REPORT_DIR/depmod.stderr" \
	> "$REPORT_DIR/SHA256SUMS"

cat > "$REPORT_DIR/summary.md" <<EOF
# SG2002 vendor runtime with Linux $kernel_release modules

- kernel release: **$kernel_release**
- retained runtime module inventory: **57/57**
- in-tree replacements: **24**
- external replacements: **30**
- media replacements: **3**
- duplicate destinations: **0**
- vermagic failures: **0**
- depmod unknown-symbol/version/ELF failures: **0**

The non-module userspace and proprietary BSP payload is copied unchanged from
the accepted raw.11 vendor-runtime staging. Redistribution remains disabled.
EOF

cat "$REPORT_DIR/summary.md"
printf 'kernel runtime staging report: %s\n' "$REPORT_DIR/summary.md"
