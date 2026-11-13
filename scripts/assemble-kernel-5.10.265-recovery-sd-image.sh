#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-$ROOT_DIR/build/vendor/LicheeRV-Nano-Build}"
BUILDROOT_OUTPUT_DIR="${KERNEL_5_10_265_BUILDROOT_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/sg2002-config-2026.05.1-kernel-5.10.265-v2}"
VENDOR_RUNTIME_DIR="${KERNEL_5_10_265_VENDOR_RUNTIME_DIR:-$ROOT_DIR/build/latestbuildroot/vendor-runtime-source-kernel-5.10.265-v2}"
KVMAPP_DIR="${NANOKVM_KVMAPP_SOURCE_DIR:-$ROOT_DIR/build/kvmapp-rust/kvmapp}"
BOOT_SD="${KERNEL_5_10_265_BOOT_SD:-$ROOT_DIR/build/latestbuildroot/boot-sd-5.10.265-v1/workspace/boot.itb}"
OUTPUT_DIR="${KERNEL_5_10_265_RECOVERY_SD_DIR:-$ROOT_DIR/build/latestbuildroot/recovery-sd-kernel-5.10.265-v1}"
ASSEMBLY_DIR="$OUTPUT_DIR/assembly"
EXTRACT_DIR="$OUTPUT_DIR/extracted"
REPORT_DIR="$OUTPUT_DIR/report"
ROOTFS_IMAGE="$BUILDROOT_OUTPUT_DIR/images/rootfs.ext2"
FIP_IMAGE="${KERNEL_5_10_265_FIP_IMAGE:-$VENDOR_SDK_DIR/install/soc_sg2002_licheervnano_sd/fip.bin}"
MCOPY="${MCOPY:-$ROOT_DIR/build/host-deps/usr/bin/mcopy}"
EXPECTED_KERNEL_RELEASE="${EXPECTED_KERNEL_RELEASE:-5.10.265-tag-}"
EXPECTED_SYSTEM_VERSION="${EXPECTED_SYSTEM_VERSION:-0.3.0-raw.11}"
EXPECTED_KVMAPP_VERSION="${EXPECTED_KVMAPP_VERSION:-2.0.41}"
EXPECTED_SECURITY_PATCH_LEVEL="${EXPECTED_SECURITY_PATCH_LEVEL:-Buildroot 2026.05.1 security maintenance; Linux 5.10.265 stable with SG2002 vendor port}"

require_file() {
	[ -f "$1" ] || {
		echo "required recovery-SD input is missing: $1" >&2
		exit 1
	}
}

for command in cmp sha256sum xz
do
	command -v "$command" >/dev/null 2>&1 || {
		echo "required command is missing: $command" >&2
		exit 1
	}
done

require_file "$ROOTFS_IMAGE"
require_file "$FIP_IMAGE"
require_file "$BOOT_SD"
require_file "$MCOPY"
require_file "$KVMAPP_DIR/server/NanoKVM-Server"
require_file "$VENDOR_RUNTIME_DIR/system/ko/soph_vcodec.ko"
require_file "$VENDOR_RUNTIME_DIR/system/ko/soph_jpeg.ko"
require_file "$VENDOR_RUNTIME_DIR/system/ko/soph_vc_driver.ko"

if [ -e "$OUTPUT_DIR" ]; then
	echo "refusing to reuse recovery-SD output: $OUTPUT_DIR" >&2
	exit 1
fi
mkdir -p "$OUTPUT_DIR" "$REPORT_DIR"

expected_vcodec="$(sha256sum "$VENDOR_RUNTIME_DIR/system/ko/soph_vcodec.ko" | awk '{print $1}')"
expected_jpeg="$(sha256sum "$VENDOR_RUNTIME_DIR/system/ko/soph_jpeg.ko" | awk '{print $1}')"
expected_vc="$(sha256sum "$VENDOR_RUNTIME_DIR/system/ko/soph_vc_driver.ko" | awk '{print $1}')"

EXPECTED_SOPH_VCODEC_SHA256="$expected_vcodec" \
EXPECTED_SOPH_JPEG_SHA256="$expected_jpeg" \
EXPECTED_SOPH_VC_DRIVER_SHA256="$expected_vc" \
EXPECTED_MEDIA_DEVICE_ACCEPTANCE=pending-recovery-sd \
EXPECTED_RUNTIME_KERNEL_RELEASE="$EXPECTED_KERNEL_RELEASE" \
EXPECTED_SYSTEM_VERSION="$EXPECTED_SYSTEM_VERSION" \
EXPECTED_SYSTEM_KERNEL_VERSION="$EXPECTED_KERNEL_RELEASE" \
EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL="$EXPECTED_SECURITY_PATCH_LEVEL" \
HARDENED_SG2002_VENDOR_SDK_DIR="$VENDOR_SDK_DIR" \
HARDENED_SG2002_BUILDROOT_OUTPUT_DIR="$BUILDROOT_OUTPUT_DIR" \
HARDENED_SG2002_ROOTFS_IMAGE="$ROOTFS_IMAGE" \
HARDENED_SG2002_FIP_IMAGE="$FIP_IMAGE" \
HARDENED_SG2002_BOOT_IMAGE="$BOOT_SD" \
HARDENED_SG2002_SD_OUTPUT_DIR="$ASSEMBLY_DIR" \
EXPECTED_KVMAPP_VERSION="$EXPECTED_KVMAPP_VERSION" \
STAGED_KVMAPP_DIR="$KVMAPP_DIR" \
	"$ROOT_DIR/scripts/assemble-latest-buildroot-sg2002-sd-image.sh"

IMAGE="$ASSEMBLY_DIR/images/hardened-sg2002-port.img"
require_file "$IMAGE"
"$ROOT_DIR/scripts/extract-sd-raw-images.sh" "$IMAGE" "$EXTRACT_DIR"
cmp -s "$EXTRACT_DIR/rootfs.sd" "$ROOTFS_IMAGE" || {
	echo "recovery SD rootfs partition differs from selected Buildroot image" >&2
	exit 1
}

mkdir -p "$OUTPUT_DIR/extracted-boot-files"
MTOOLS_SKIP_CHECK=1 "$MCOPY" -i "$EXTRACT_DIR/boot.vfat" \
	::fip.bin "$OUTPUT_DIR/extracted-boot-files/fip.bin"
MTOOLS_SKIP_CHECK=1 "$MCOPY" -i "$EXTRACT_DIR/boot.vfat" \
	::/boot.sd "$OUTPUT_DIR/extracted-boot-files/boot.sd"
cmp -s "$OUTPUT_DIR/extracted-boot-files/fip.bin" "$FIP_IMAGE" || {
	echo "recovery SD fip.bin differs from pinned vendor input" >&2
	exit 1
}
cmp -s "$OUTPUT_DIR/extracted-boot-files/boot.sd" "$BOOT_SD" || {
	echo "recovery SD boot.sd differs from the candidate FIT" >&2
	exit 1
}

xz -T0 -9 -c "$IMAGE" > "$IMAGE.xz"
sha256sum \
	"$IMAGE" \
	"$IMAGE.xz" \
	"$EXTRACT_DIR/boot.vfat" \
	"$EXTRACT_DIR/rootfs.sd" \
	"$OUTPUT_DIR/extracted-boot-files/fip.bin" \
	"$OUTPUT_DIR/extracted-boot-files/boot.sd" \
	> "$REPORT_DIR/SHA256SUMS"

cat > "$REPORT_DIR/summary.md" <<EOF
# Linux $EXPECTED_KERNEL_RELEASE recovery-SD candidate

- kernel release contract: **$EXPECTED_KERNEL_RELEASE**
- userspace system: **$EXPECTED_SYSTEM_VERSION**
- application: **$EXPECTED_KVMAPP_VERSION**
- embedded/extracted candidate boot.sd: **match**
- embedded/extracted Buildroot rootfs: **match**
- embedded/extracted pinned fip.bin: **match**
- module inventory already validated in rootfs: **57/57**
- compressed image: \`$IMAGE.xz\`
- media runtime acceptance: **pending-recovery-sd**

This image is recovery-media only. It is not a raw partition update and must
not be installed first through the web updater.
EOF

cat "$REPORT_DIR/summary.md"
printf 'recovery-SD candidate report: %s\n' "$REPORT_DIR/summary.md"
