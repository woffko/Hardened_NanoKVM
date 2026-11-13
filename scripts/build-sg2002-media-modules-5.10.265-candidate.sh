#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
KERNEL_DIR="${KERNEL_5_10_265_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-5.10.265-v6/output}"
OUTPUT_DIR="${MEDIA_MODULE_5_10_265_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/media-modules-5.10.265-v1}"
MINIMAL_DIR="$OUTPUT_DIR/minimal-vcodec"
CURRENT_DIR="$OUTPUT_DIR/sophgo-current"
HISTORICAL_DIR="$OUTPUT_DIR/historical-vc"
ARTIFACT_DIR="$OUTPUT_DIR/artifacts"
REPORT_DIR="$OUTPUT_DIR/report"
EXTERNAL_BUILD_DIR="${MEDIA_MODULE_5_10_265_EXTERNAL_BUILD_DIR:-$ROOT_DIR/build/latestbuildroot/external-modules-5.10.265-v3}"
BASE_SYMVERS="$EXTERNAL_BUILD_DIR/osdrv/interdrv/v2/base/Module.symvers"
SYS_SYMVERS="$EXTERNAL_BUILD_DIR/osdrv/interdrv/v2/sys/Module.symvers"
EXPECTED_KERNEL_RELEASE="${EXPECTED_KERNEL_RELEASE:-5.10.265-tag-}"
SOPHGO_COMPAT_PATCH="$ROOT_DIR/buildroot-external/hardened-sg2002/board/sg2002/kernel/patches/sophgo-osdrv-linux-5.10.265-compat.patch"
HISTORICAL_COMPAT_PATCH="$ROOT_DIR/buildroot-external/hardened-sg2002/board/sg2002/kernel/patches/sophgo-osdrv-v2-linux-5.10.265-compat.patch"
EXPECTED_JPEG_SRCVERSION="${EXPECTED_JPEG_SRCVERSION:-EBFE55AAD3BE9DD11AF3F51}"

require_file() {
	[ -f "$1" ] || {
		echo "required media candidate input is missing: $1" >&2
		exit 1
	}
}

for command in modinfo sha256sum cmp
do
	command -v "$command" >/dev/null 2>&1 || {
		echo "required command is missing: $command" >&2
		exit 1
	}
done

require_file "$KERNEL_DIR/include/generated/utsrelease.h"
require_file "$KERNEL_DIR/Module.symvers"
require_file "$KERNEL_DIR/arch/riscv/boot/Image"
require_file "$SOPHGO_COMPAT_PATCH"
require_file "$HISTORICAL_COMPAT_PATCH"
require_file "$BASE_SYMVERS"
require_file "$SYS_SYMVERS"

kernel_release="$(sed -n 's/^#define UTS_RELEASE "\(.*\)"$/\1/p' \
	"$KERNEL_DIR/include/generated/utsrelease.h")"
if [ "$kernel_release" != "$EXPECTED_KERNEL_RELEASE" ]; then
	echo "unexpected media-module kernel release: $kernel_release" >&2
	exit 1
fi

if [ -e "$OUTPUT_DIR" ]; then
	echo "refusing to reuse media-module candidate output: $OUTPUT_DIR" >&2
	exit 1
fi
mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR" "$REPORT_DIR"

sha256sum "$KERNEL_DIR/Module.symvers" "$KERNEL_DIR/arch/riscv/boot/Image" \
	> "$REPORT_DIR/kernel-input-before.sha256"

MINIMAL_VCODEC_KERNEL_DIR="$KERNEL_DIR" \
MINIMAL_VCODEC_OUTPUT_DIR="$MINIMAL_DIR" \
MINIMAL_VCODEC_KCFLAGS="-fmacro-prefix-map=$MINIMAL_DIR/work=/usr/src/vendor-vcodec" \
	"$ROOT_DIR/scripts/build-minimal-vendor-vcodec-compat.sh"

SOPHGO_MEDIA_KERNEL_DIR="$KERNEL_DIR" \
SOPHGO_MEDIA_OUTPUT_DIR="$CURRENT_DIR" \
SOPHGO_MEDIA_KERNEL_COMPAT_PATCH="$SOPHGO_COMPAT_PATCH" \
SOPHGO_MEDIA_BASE_SYMVERS="$BASE_SYMVERS" \
SOPHGO_MEDIA_SYS_SYMVERS="$SYS_SYMVERS" \
SOPHGO_MEDIA_EXPECTED_JPEG_SRCVERSION="$EXPECTED_JPEG_SRCVERSION" \
SOPHGO_MEDIA_KCFLAGS="-fmacro-prefix-map=$CURRENT_DIR/osdrv=/usr/src/sophgo-osdrv" \
	"$ROOT_DIR/scripts/build-sophgo-media-module-replacements.sh"

HISTORICAL_VC_KERNEL_DIR="$KERNEL_DIR" \
HISTORICAL_VC_VCODEC_DIR="$MINIMAL_DIR/work/osdrv/interdrv/v2/vcodec" \
HISTORICAL_VC_JPEG_DIR="$CURRENT_DIR/osdrv/interdrv/jpeg" \
HISTORICAL_VC_KERNEL_COMPAT_PATCH="$HISTORICAL_COMPAT_PATCH" \
HISTORICAL_VC_BASE_SYMVERS="$BASE_SYMVERS" \
HISTORICAL_VC_SYS_SYMVERS="$SYS_SYMVERS" \
HISTORICAL_VC_OUTPUT_DIR="$HISTORICAL_DIR" \
HISTORICAL_VC_KCFLAGS="-fmacro-prefix-map=$HISTORICAL_DIR/osdrv=/usr/src/sophgo-osdrv-v2" \
	"$ROOT_DIR/scripts/build-historical-sophgo-vc-driver.sh"

cp "$MINIMAL_DIR/artifacts/soph_vcodec.ko" "$ARTIFACT_DIR/"
cp "$CURRENT_DIR/artifacts/soph_jpeg.ko" "$ARTIFACT_DIR/"
cp "$HISTORICAL_DIR/artifacts/soph_vc_driver.ko" "$ARTIFACT_DIR/"

assert_modinfo() {
	field="$1"
	module="$2"
	expected="$3"
	actual="$(modinfo -F "$field" "$ARTIFACT_DIR/$module")"
	if [ "$actual" != "$expected" ]; then
		echo "unexpected $field for $module: $actual" >&2
		exit 1
	fi
}

assert_modinfo name soph_vcodec.ko soph_vcodec
assert_modinfo name soph_jpeg.ko soph_jpeg
assert_modinfo name soph_vc_driver.ko soph_vc_driver
assert_modinfo depends soph_jpeg.ko soph_vcodec
assert_modinfo depends soph_vc_driver.ko soph_jpeg,soph_vcodec,soph_base,soph_sys
assert_modinfo srcversion soph_jpeg.ko "$EXPECTED_JPEG_SRCVERSION"

for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko
do
	vermagic="$(modinfo -F vermagic "$ARTIFACT_DIR/$module")"
	case "$vermagic" in
		"$kernel_release "*) ;;
		*)
			echo "unexpected vermagic for $module: $vermagic" >&2
			exit 1
			;;
	esac
	modinfo "$ARTIFACT_DIR/$module" >> "$REPORT_DIR/modinfo.txt"
done

sha256sum "$KERNEL_DIR/Module.symvers" "$KERNEL_DIR/arch/riscv/boot/Image" \
	> "$REPORT_DIR/kernel-input-after.sha256"
cmp -s "$REPORT_DIR/kernel-input-before.sha256" \
	"$REPORT_DIR/kernel-input-after.sha256" || {
	echo "media-module builds modified candidate kernel inputs" >&2
	exit 1
}

sha256sum "$ARTIFACT_DIR"/*.ko > "$REPORT_DIR/module-sha256.txt"
find "$ARTIFACT_DIR" -type f -exec touch -d '@0' {} +

cat > "$REPORT_DIR/summary.md" <<EOF
# SG2002 media modules for Linux 5.10.265

- target kernel release: **$kernel_release**
- source-built modules: **3/3**
- module names and dependency sets: **match**
- vermagic failures: **0**
- kernel input mutation: **none**
- vcodec source path: minimal accepted vendor compatibility build
- JPEG source path: pinned SOPHGO current source
- VC source path: pinned historical compatibility source

This is build and ABI evidence only. Runtime media acceptance remains gated on
a recovery-SD boot and the existing HDMI/H.264 soak procedure.
EOF

cat "$REPORT_DIR/summary.md"
printf 'media-module candidate report: %s\n' "$REPORT_DIR/summary.md"
