#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
RC12_RUN_ROOT="${RC12_RUN_ROOT:-$ROOT_DIR/build/latestbuildroot/kernel-5.10.265-rc12-bridge-a}"
SECURITY_PATCH_LEVEL="${RC12_SECURITY_PATCH_LEVEL:-Buildroot 2026.05.1 security maintenance Linux 5.10.265 SG2002 vendor port}"
SD_IMAGE="$RC12_RUN_ROOT/recovery/assembly/images/hardened-sg2002-port.img"
BUILD_COMMIT_FILE="$RC12_RUN_ROOT/_reports/outer-commit.txt"
RAW_OUTPUT_ROOT="${RC12_RAW_OUTPUT_ROOT:-$ROOT_DIR/build/latestbuildroot/raw-system-update-0.3.0-raw.12-bridge}"
VENDOR_RUNTIME_DIR="$RC12_RUN_ROOT/runtime"
PRODUCTION_PUBLIC_KEY="${SYSTEM_UPDATE_PUBLIC_KEY:-$ROOT_DIR/kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem}"
KVMAPP_DIR="${NANOKVM_KVMAPP_SOURCE_DIR:-$ROOT_DIR/build/key-transition-2.0.42-bootstrap/app-a/stage/kvmapp}"
EXPECTED_SERVER_SHA256=fd116fc459a1961cfc16fd0c7077a8f4c5e24d8f32d8745fd3b9744217083d6d

[ -f "$SD_IMAGE" ] || {
	echo "missing accepted RC12 SD image: $SD_IMAGE" >&2
	exit 1
}
[ -f "$BUILD_COMMIT_FILE" ] || {
	echo "missing RC12 build commit evidence: $BUILD_COMMIT_FILE" >&2
	exit 1
}
[ -f "$KVMAPP_DIR/server/NanoKVM-Server" ] || {
	echo "missing accepted RC12 bridge server" >&2
	exit 1
}
[ "$(sha256sum "$KVMAPP_DIR/server/NanoKVM-Server" | awk '{print $1}')" = "$EXPECTED_SERVER_SHA256" ] || {
	echo "RC12 raw packaging bridge server hash mismatch" >&2
	exit 1
}
BUILD_COMMIT="$(cat "$BUILD_COMMIT_FILE")"
git -C "$ROOT_DIR" cat-file -e "$BUILD_COMMIT^{commit}"
for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko
do
	[ -f "$VENDOR_RUNTIME_DIR/system/ko/$module" ] || {
		echo "missing selected RC12 media module: $module" >&2
		exit 1
	}
done
expected_vcodec="$(sha256sum "$VENDOR_RUNTIME_DIR/system/ko/soph_vcodec.ko" | awk '{print $1}')"
expected_jpeg="$(sha256sum "$VENDOR_RUNTIME_DIR/system/ko/soph_jpeg.ko" | awk '{print $1}')"
expected_vc="$(sha256sum "$VENDOR_RUNTIME_DIR/system/ko/soph_vc_driver.ko" | awk '{print $1}')"

HARDENED_SG2002_SYSTEM_VERSION=0.3.0-raw.12 \
HARDENED_SG2002_SYSTEM_TAG=hardened-system-0.3.0-raw.12 \
HARDENED_SG2002_SYSTEM_TARGET=sg2002-licheervnano-sd \
HARDENED_SG2002_KERNEL_VERSION=5.10.265-tag- \
HARDENED_SG2002_SECURITY_PATCH_LEVEL="$SECURITY_PATCH_LEVEL" \
HARDENED_SG2002_ROOTFS_SECURITY_PATCH_LEVEL="$SECURITY_PATCH_LEVEL" \
HARDENED_SG2002_SD_IMAGE="$SD_IMAGE" \
HARDENED_SG2002_RAW_IMAGES_DIR="$RAW_OUTPUT_ROOT/images" \
HARDENED_SG2002_RAW_UPDATE_OUT="$RAW_OUTPUT_ROOT/artifacts" \
EXPECTED_KVMAPP_VERSION=2.0.42 \
SYSTEM_UPDATE_REQUIRED_APP_VERSION=2.0.42 \
	SYSTEM_UPDATE_SIGNATURE_KEY_ID=hardened-system-prod-2026q3 \
	SYSTEM_UPDATE_SOURCE_COMMIT="$BUILD_COMMIT" \
	EXPECTED_SOPH_VCODEC_SHA256="$expected_vcodec" \
	EXPECTED_SOPH_JPEG_SHA256="$expected_jpeg" \
	EXPECTED_SOPH_VC_DRIVER_SHA256="$expected_vc" \
	EXPECTED_MEDIA_DEVICE_ACCEPTANCE=pending-recovery-sd \
EXPECTED_RUNTIME_KERNEL_RELEASE=5.10.265-tag- \
	EXPECTED_UPDATE_KEY_ID=hardened-system-prod-2026q3 \
	EXPECTED_UPDATE_KEY_POLICY='hardened-system-dev hardened-system-test hardened-system-prod-2026q3' \
	EXPECTED_UPDATE_PUBLIC_KEY_DER_SHA256=97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75 \
	SYSTEM_UPDATE_PUBLIC_KEY="$PRODUCTION_PUBLIC_KEY" \
	NANOKVM_KVMAPP_SOURCE_DIR="$KVMAPP_DIR" \
	exec "$ROOT_DIR/scripts/package-latest-buildroot-sg2002-raw-update.sh"
