#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BUILDROOT_SOURCE="${LATEST_BUILDROOT_SOURCE_DIR:-$ROOT_DIR/build/latestbuildroot/buildroot-2026.05.1-raw11-security}"
VENDOR_RUNTIME_DIR="${KERNEL_5_10_265_VENDOR_RUNTIME_DIR:-$ROOT_DIR/build/latestbuildroot/vendor-runtime-source-kernel-5.10.265-v2}"
KVMAPP_DIR="${NANOKVM_KVMAPP_SOURCE_DIR:-$ROOT_DIR/build/kvmapp-rust/kvmapp}"
OUTPUT_DIR="${KERNEL_5_10_265_BUILDROOT_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/sg2002-config-2026.05.1-kernel-5.10.265-v1}"
REPORT_DIR="${KERNEL_5_10_265_ROOTFS_REPORT_DIR:-$ROOT_DIR/build/latestbuildroot/rootfs-kernel-5.10.265-v1-report}"
EXPECTED_KERNEL_RELEASE="${EXPECTED_KERNEL_RELEASE:-5.10.265-tag-}"
EXPECTED_SYSTEM_VERSION="${EXPECTED_SYSTEM_VERSION:-0.3.0-raw.11}"
EXPECTED_KVMAPP_VERSION="${EXPECTED_KVMAPP_VERSION:-2.0.41}"
EXPECTED_SECURITY_PATCH_LEVEL="${EXPECTED_SECURITY_PATCH_LEVEL:-Buildroot 2026.05.1 security maintenance; Linux 5.10.265 stable with SG2002 vendor port}"

require_file() {
	[ -f "$1" ] || {
		echo "required candidate rootfs input is missing: $1" >&2
		exit 1
	}
}

require_dir() {
	[ -d "$1" ] || {
		echo "required candidate rootfs directory is missing: $1" >&2
		exit 1
	}
}

for command in cmp debugfs find sha256sum sort awk
do
	command -v "$command" >/dev/null 2>&1 || {
		echo "required command is missing: $command" >&2
		exit 1
	}
done

require_file "$BUILDROOT_SOURCE/Makefile"
require_dir "$VENDOR_RUNTIME_DIR/system/ko"
require_file "$KVMAPP_DIR/server/NanoKVM-Server"

if [ -e "$OUTPUT_DIR" ] || [ -e "$REPORT_DIR" ]; then
	echo "refusing to reuse candidate Buildroot output or report" >&2
	exit 1
fi
mkdir -p "$OUTPUT_DIR" "$REPORT_DIR"

LATEST_BUILDROOT_SOURCE_DIR="$BUILDROOT_SOURCE" \
HARDENED_SG2002_BUILDROOT_OUTPUT_DIR="$OUTPUT_DIR" \
	"$ROOT_DIR/scripts/configure-latest-buildroot-sg2002.sh"

LATEST_BUILDROOT_SOURCE_DIR="$BUILDROOT_SOURCE" \
HARDENED_SG2002_BUILDROOT_OUTPUT_DIR="$OUTPUT_DIR" \
NANOKVM_VENDOR_RUNTIME_SOURCE_DIR="$VENDOR_RUNTIME_DIR" \
NANOKVM_KVMAPP_SOURCE_DIR="$KVMAPP_DIR" \
HARDENED_SG2002_RUNTIME_SYSTEM_VERSION="$EXPECTED_SYSTEM_VERSION" \
HARDENED_SG2002_RUNTIME_KERNEL_VERSION="$EXPECTED_KERNEL_RELEASE" \
HARDENED_SG2002_RUNTIME_SECURITY_PATCH_LEVEL="$EXPECTED_SECURITY_PATCH_LEVEL" \
	"$ROOT_DIR/scripts/build-latest-buildroot-sg2002-rootfs.sh"

ROOTFS_IMAGE="$OUTPUT_DIR/images/rootfs.ext2"
require_file "$ROOTFS_IMAGE"

expected_vcodec="$(sha256sum "$VENDOR_RUNTIME_DIR/system/ko/soph_vcodec.ko" | awk '{print $1}')"
expected_jpeg="$(sha256sum "$VENDOR_RUNTIME_DIR/system/ko/soph_jpeg.ko" | awk '{print $1}')"
expected_vc="$(sha256sum "$VENDOR_RUNTIME_DIR/system/ko/soph_vc_driver.ko" | awk '{print $1}')"

EXPECTED_SOPH_VCODEC_SHA256="$expected_vcodec" \
EXPECTED_SOPH_JPEG_SHA256="$expected_jpeg" \
EXPECTED_SOPH_VC_DRIVER_SHA256="$expected_vc" \
EXPECTED_MEDIA_DEVICE_ACCEPTANCE=pending-recovery-sd \
EXPECTED_RUNTIME_KERNEL_RELEASE="$EXPECTED_KERNEL_RELEASE" \
EXPECTED_KVMAPP_VERSION="$EXPECTED_KVMAPP_VERSION" \
EXPECTED_SYSTEM_VERSION="$EXPECTED_SYSTEM_VERSION" \
EXPECTED_SYSTEM_KERNEL_VERSION="$EXPECTED_KERNEL_RELEASE" \
EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL="$EXPECTED_SECURITY_PATCH_LEVEL" \
STAGED_KVMAPP_DIR="$KVMAPP_DIR" \
	"$ROOT_DIR/scripts/validate-latest-buildroot-sg2002-rootfs.sh" \
	"$ROOTFS_IMAGE"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-kernel-rootfs.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM
EXPECTED_LIST="$REPORT_DIR/expected-modules.txt"
find "$VENDOR_RUNTIME_DIR/system/ko" -type f -name '*.ko' -printf '%P\n' | \
	LC_ALL=C sort > "$EXPECTED_LIST"
if [ "$(wc -l < "$EXPECTED_LIST")" -ne 57 ]; then
	echo "candidate vendor runtime does not contain 57 modules" >&2
	exit 1
fi

printf 'path\tsha256\n' > "$REPORT_DIR/rootfs-module-sha256.tsv"
while IFS= read -r relative
do
	extracted="$TMP_DIR/$(basename "$relative")"
	debugfs -R "dump /mnt/system/ko/$relative $extracted" \
		"$ROOTFS_IMAGE" >/dev/null 2>&1 || {
		echo "could not extract packaged module: $relative" >&2
		exit 1
	}
	cmp -s "$VENDOR_RUNTIME_DIR/system/ko/$relative" "$extracted" || {
		echo "Buildroot modified packaged module: $relative" >&2
		exit 1
	}
	printf '%s\t%s\n' "$relative" \
		"$(sha256sum "$extracted" | awk '{print $1}')" \
		>> "$REPORT_DIR/rootfs-module-sha256.tsv"
done < "$EXPECTED_LIST"

sha256sum "$ROOTFS_IMAGE" "$OUTPUT_DIR/images/rootfs.tar" \
	> "$REPORT_DIR/rootfs-sha256.txt"

cat > "$REPORT_DIR/summary.md" <<EOF
# Buildroot 2026.05.1 rootfs with Linux $EXPECTED_KERNEL_RELEASE modules

- userspace system version: **$EXPECTED_SYSTEM_VERSION**
- application version: **$EXPECTED_KVMAPP_VERSION**
- runtime kernel release contract: **$EXPECTED_KERNEL_RELEASE**
- packaged module inventory: **57/57**
- modules byte-identical to reviewed staging: **57/57**
- selected rootfs validation: **pass**
- media acceptance marker: **pending-recovery-sd**

This rootfs is intended only for the recovery-SD kernel candidate. It is not a
raw partition update artifact.
EOF

cat "$REPORT_DIR/summary.md"
printf 'candidate Buildroot rootfs report: %s\n' "$REPORT_DIR/summary.md"
