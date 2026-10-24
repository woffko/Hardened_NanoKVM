#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDROOT_VERSION="${BUILDROOT_VERSION:-2026.05.1}"
SYSTEM_VERSION="${HARDENED_SG2002_SYSTEM_VERSION:-0.3.0-raw.11}"
SYSTEM_TAG="${HARDENED_SG2002_SYSTEM_TAG:-hardened-system-${SYSTEM_VERSION}}"
SYSTEM_TARGET="${HARDENED_SG2002_SYSTEM_TARGET:-sg2002-licheervnano-sd}"
SECURITY_PATCH_LEVEL="${HARDENED_SG2002_SECURITY_PATCH_LEVEL:-Buildroot 2026.05.1 security maintenance vendor-kernel-5.10.4}"
KERNEL_VERSION="${HARDENED_SG2002_KERNEL_VERSION:-5.10.4-tag-}"
ROOTFS_SECURITY_PATCH_LEVEL="${HARDENED_SG2002_ROOTFS_SECURITY_PATCH_LEVEL:-}"
ROOTFS_BASE_VERSION="${HARDENED_SG2002_ROOTFS_BASE_VERSION:-Buildroot ${BUILDROOT_VERSION} port}"
PROBE_ROOT="${LATEST_BUILDROOT_PROBE_ROOT:-$ROOT/build/latestbuildroot}"
SD_OUTPUT_DIR="${HARDENED_SG2002_SD_OUTPUT_DIR:-$PROBE_ROOT/sg2002-sd-image-${BUILDROOT_VERSION}}"
SD_IMAGE="${HARDENED_SG2002_SD_IMAGE:-$SD_OUTPUT_DIR/images/hardened-sg2002-port.img}"
RAW_IMAGES_DIR="${HARDENED_SG2002_RAW_IMAGES_DIR:-$PROBE_ROOT/raw-system-update-${SYSTEM_VERSION}/images}"
OUTPUT_DIR="${HARDENED_SG2002_RAW_UPDATE_OUT:-$PROBE_ROOT/raw-system-update-${SYSTEM_VERSION}/artifacts}"
SIGNING_KEY="${SYSTEM_UPDATE_SIGNING_KEY:-}"
PUBLIC_KEY="${SYSTEM_UPDATE_PUBLIC_KEY:-$ROOT/kvmapp/system/keys/system-update-signing.pub.pem}"
KVMAPP_DIR="${NANOKVM_KVMAPP_SOURCE_DIR:-$ROOT/build/kvmapp-rust/kvmapp}"
ALLOW_UNSIGNED="${ALLOW_UNSIGNED_SYSTEM_UPDATE:-0}"
EARLY_RESTORE_BIN="${NANOKVM_EARLY_RESTORE_BIN:-$ROOT/server-rust/target/restore-runtime/riscv64gc-unknown-linux-musl/release/nanokvm-early-restore}"
EARLY_RESTORE_SCRIPT="${NANOKVM_EARLY_RESTORE_SCRIPT:-$ROOT/support/sg2002/raw/S01restore}"

[ -f "$EARLY_RESTORE_BIN" ] || {
	echo "missing early restore helper: $EARLY_RESTORE_BIN" >&2
	echo "run server-rust/scripts/build-early-restore.sh" >&2
	exit 1
}
[ -f "$EARLY_RESTORE_SCRIPT" ] || {
	echo "missing S01restore source: $EARLY_RESTORE_SCRIPT" >&2
	exit 1
}

[ -f "$SD_IMAGE" ] || {
	echo "missing SG2002 SD image: $SD_IMAGE" >&2
	exit 1
}

if [ -n "$SIGNING_KEY" ]; then
	[ -f "$SIGNING_KEY" ] || {
		echo "system update signing key does not exist: $SIGNING_KEY" >&2
		exit 1
	}
else
	[ "$ALLOW_UNSIGNED" = 1 ] || {
		echo "SYSTEM_UPDATE_SIGNING_KEY is required for an installable raw update" >&2
		exit 1
	}
	echo "building an explicitly unsigned preflight bundle; it is not installable or publishable" >&2
fi
[ -f "$PUBLIC_KEY" ] || {
	echo "system update public key does not exist: $PUBLIC_KEY" >&2
	exit 1
}

if [ -e "$RAW_IMAGES_DIR" ] || [ -e "$OUTPUT_DIR" ]; then
	echo "refusing to overwrite existing raw-update output" >&2
	echo "images: $RAW_IMAGES_DIR" >&2
	echo "artifacts: $OUTPUT_DIR" >&2
	exit 1
fi

"$ROOT/scripts/extract-sd-raw-images.sh" "$SD_IMAGE" "$RAW_IMAGES_DIR"
EXPECTED_BUILDROOT_VERSION="$BUILDROOT_VERSION" \
EXPECTED_KVMAPP_VERSION="${EXPECTED_KVMAPP_VERSION:-2.0.41}" \
	EXPECTED_SYSTEM_VERSION="$SYSTEM_VERSION" \
	EXPECTED_SYSTEM_KERNEL_VERSION="$KERNEL_VERSION" \
EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL="$ROOTFS_SECURITY_PATCH_LEVEL" \
	STAGED_KVMAPP_DIR="$KVMAPP_DIR" \
	"$ROOT/scripts/validate-latest-buildroot-sg2002-rootfs.sh" "$RAW_IMAGES_DIR/rootfs.sd"

BASE_VERSION="Buildroot-${BUILDROOT_VERSION}-port" \
ROOTFS_SYSTEM_BASE_VERSION="$ROOTFS_BASE_VERSION" \
KERNEL_VERSION="$KERNEL_VERSION" \
SECURITY_PATCH_LEVEL="$SECURITY_PATCH_LEVEL" \
RAW_IMAGE_COMPRESSION=gzip \
SYSTEM_UPDATE_FORMAT=2 \
SYSTEM_UPDATE_REQUIRED_APP_VERSION="${SYSTEM_UPDATE_REQUIRED_APP_VERSION:-2.0.41}" \
NANOKVM_EARLY_RESTORE_BIN="$EARLY_RESTORE_BIN" \
NANOKVM_EARLY_RESTORE_SCRIPT="$EARLY_RESTORE_SCRIPT" \
	"$ROOT/scripts/create-raw-system-update-bundle.sh" \
	"$SYSTEM_VERSION" "$SYSTEM_TARGET" \
	"$RAW_IMAGES_DIR/boot.vfat" "$RAW_IMAGES_DIR/rootfs.sd" "$OUTPUT_DIR"

ARCHIVE="$OUTPUT_DIR/hardened-nanokvm-system-${SYSTEM_VERSION}.tar.gz"
METADATA="$OUTPUT_DIR/system-latest.json"

CHANNEL=preview \
TARGET="$SYSTEM_TARGET" \
SECURITY_PATCH_LEVEL="$SECURITY_PATCH_LEVEL" \
SYSTEM_UPDATE_FORMAT=2 \
SYSTEM_UPDATE_REQUIRED_APP_VERSION="${SYSTEM_UPDATE_REQUIRED_APP_VERSION:-2.0.41}" \
SYSTEM_UPDATE_SIGNING_KEY="$SIGNING_KEY" \
	"$ROOT/scripts/create-system-update-metadata.sh" \
	"$SYSTEM_VERSION" "$SYSTEM_TAG" "$ARCHIVE" "$METADATA"

if [ -n "$SIGNING_KEY" ]; then
	"$ROOT/scripts/verify-system-update-metadata.sh" \
		"$METADATA" "$METADATA.sig" "$PUBLIC_KEY"
	sha256sum "$ARCHIVE" "$METADATA" "$METADATA.sig"
else
	grep -Fq '"signature_algorithm": "unsigned"' "$METADATA"
	grep -Fq '"signature_key_id": "unsigned"' "$METADATA"
	[ ! -e "$METADATA.sig" ] || {
		echo "unsigned preflight unexpectedly produced a signature" >&2
		exit 1
	}
	sha256sum "$ARCHIVE" "$METADATA"
fi

printf '%s\n' "$ARCHIVE"
printf '%s\n' "$METADATA"
if [ -n "$SIGNING_KEY" ]; then
	printf '%s\n' "$METADATA.sig"
fi
