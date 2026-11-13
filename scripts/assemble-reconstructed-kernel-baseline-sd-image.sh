#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build}"
VENDOR_OUTPUT_DIR="${HARDENED_SG2002_VENDOR_OUTPUT_DIR:-$VENDOR_SDK_DIR/install/soc_sg2002_licheervnano_sd}"
BUILDROOT_OUTPUT_DIR="${HARDENED_SG2002_BUILDROOT_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/sg2002-config-2026.05.1-raw10}"
REBUILT_BOOT_SD="${REBUILT_BOOT_SD:-$ROOT_DIR/build/latestbuildroot/boot-sd-5.10.4-v3/workspace/boot.itb}"
OUTPUT_DIR="${RECOVERABLE_BASELINE_SD_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/recoverable-kernel-baseline-sd-v2}"
ASSEMBLY_DIR="$OUTPUT_DIR/assembly"
VENDOR_STAGE="$OUTPUT_DIR/vendor-output"
EXTRACT_DIR="$OUTPUT_DIR/extracted"
REPORT_DIR="$OUTPUT_DIR/report"
REFERENCE_BOOT_SD="$VENDOR_OUTPUT_DIR/rawimages/boot.sd"
ROOTFS_IMAGE="$BUILDROOT_OUTPUT_DIR/images/rootfs.ext2"
MCOPY="${MCOPY:-$ROOT_DIR/build/host-deps/usr/bin/mcopy}"

for path in \
	"$VENDOR_OUTPUT_DIR/fip.bin" \
	"$REFERENCE_BOOT_SD" \
	"$REBUILT_BOOT_SD" \
	"$ROOTFS_IMAGE" \
	"$MCOPY"
do
	[ -e "$path" ] || {
		echo "required recoverable baseline input is missing: $path" >&2
		exit 1
	}
done

if [ -e "$OUTPUT_DIR" ]; then
	echo "refusing to overwrite recoverable baseline SD output: $OUTPUT_DIR" >&2
	exit 1
fi

cmp -s "$REBUILT_BOOT_SD" "$REFERENCE_BOOT_SD" || {
	echo "reconstructed boot.sd is not the accepted byte-exact baseline" >&2
	exit 1
}

mkdir -p "$VENDOR_STAGE/rawimages" "$EXTRACT_DIR" "$REPORT_DIR"
cp "$VENDOR_OUTPUT_DIR/fip.bin" "$VENDOR_STAGE/fip.bin"
cp "$REBUILT_BOOT_SD" "$VENDOR_STAGE/rawimages/boot.sd"

HARDENED_SG2002_BUILDROOT_OUTPUT_DIR="$BUILDROOT_OUTPUT_DIR" \
HARDENED_SG2002_VENDOR_SDK_DIR="$VENDOR_SDK_DIR" \
HARDENED_SG2002_VENDOR_OUTPUT_DIR="$VENDOR_STAGE" \
HARDENED_SG2002_SD_OUTPUT_DIR="$ASSEMBLY_DIR" \
EXPECTED_KVMAPP_VERSION=2.0.40 \
	"$ROOT_DIR/scripts/assemble-latest-buildroot-sg2002-sd-image.sh"

IMAGE="$ASSEMBLY_DIR/images/hardened-sg2002-port.img"
"$ROOT_DIR/scripts/extract-sd-raw-images.sh" "$IMAGE" "$EXTRACT_DIR"
cmp -s "$EXTRACT_DIR/rootfs.sd" "$ROOTFS_IMAGE" || {
	echo "reassembled SD rootfs partition differs from accepted raw.10 rootfs" >&2
	exit 1
}

mkdir -p "$OUTPUT_DIR/extracted-boot-files"
MTOOLS_SKIP_CHECK=1 "$MCOPY" -i "$EXTRACT_DIR/boot.vfat" \
	::fip.bin "$OUTPUT_DIR/extracted-boot-files/fip.bin"
MTOOLS_SKIP_CHECK=1 "$MCOPY" -i "$EXTRACT_DIR/boot.vfat" \
	::/boot.sd "$OUTPUT_DIR/extracted-boot-files/boot.sd"

cmp -s "$OUTPUT_DIR/extracted-boot-files/fip.bin" "$VENDOR_OUTPUT_DIR/fip.bin" || {
	echo "reassembled SD fip.bin differs from pinned vendor input" >&2
	exit 1
}
cmp -s "$OUTPUT_DIR/extracted-boot-files/boot.sd" "$REBUILT_BOOT_SD" || {
	echo "reassembled SD boot.sd differs from reconstructed baseline" >&2
	exit 1
}

sha256sum \
	"$IMAGE" \
	"$EXTRACT_DIR/boot.vfat" \
	"$EXTRACT_DIR/rootfs.sd" \
	"$OUTPUT_DIR/extracted-boot-files/fip.bin" \
	"$OUTPUT_DIR/extracted-boot-files/boot.sd" > "$REPORT_DIR/SHA256SUMS"

cat > "$REPORT_DIR/summary.md" <<EOF
# Recoverable vendor-kernel baseline SD candidate

- system: \`0.3.0-raw.10\`
- application: \`2.0.40\`
- kernel: unchanged \`5.10.4-tag-\`
- reconstructed boot.sd embedded and extracted: **match**
- pinned fip.bin embedded and extracted: **match**
- accepted raw.10 rootfs partition embedded and extracted: **match**
- SD image SHA-256:
  \`$(sha256sum "$IMAGE" | awk '{print $1}')\`

This is a local candidate for an explicitly identified sacrificial/recoverable
SD card. It is not authorization to overwrite the accepted test card or any
unidentified block device.
EOF

cat "$REPORT_DIR/summary.md"
printf 'recoverable baseline SD report: %s\n' "$REPORT_DIR/summary.md"
