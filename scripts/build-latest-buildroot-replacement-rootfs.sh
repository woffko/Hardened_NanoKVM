#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDROOT_VERSION="${BUILDROOT_VERSION:-2026.05.1}"
SYSTEM_VERSION="${HARDENED_SG2002_SYSTEM_VERSION:-0.3.0-raw.11}"
OUTPUT_DIR="${HARDENED_SG2002_BUILDROOT_OUTPUT_DIR:-$ROOT/build/latestbuildroot/sg2002-config-${BUILDROOT_VERSION}-raw11}"
VENDOR_RUNTIME_DIR="${NANOKVM_VENDOR_RUNTIME_SOURCE_DIR:-$ROOT/build/latestbuildroot/vendor-runtime-source-media-v1}"
KVMAPP_DIR="${NANOKVM_KVMAPP_SOURCE_DIR:-$ROOT/build/kvmapp-rust/kvmapp}"
ROOTFS_IMAGE="$OUTPUT_DIR/images/rootfs.ext2"

test -f "$OUTPUT_DIR/.config"
test -d "$VENDOR_RUNTIME_DIR/system/ko"
test -x "$KVMAPP_DIR/server/NanoKVM-Server"

HARDENED_SG2002_BUILDROOT_OUTPUT_DIR="$OUTPUT_DIR" \
NANOKVM_VENDOR_RUNTIME_SOURCE_DIR="$VENDOR_RUNTIME_DIR" \
NANOKVM_KVMAPP_SOURCE_DIR="$KVMAPP_DIR" \
BUILDROOT_PORT_JOBS="${BUILDROOT_PORT_JOBS:-4}" \
	"$ROOT/scripts/build-latest-buildroot-sg2002-rootfs.sh"

EXPECTED_BUILDROOT_VERSION="$BUILDROOT_VERSION" \
EXPECTED_KVMAPP_VERSION="${EXPECTED_KVMAPP_VERSION:-2.0.41}" \
EXPECTED_SYSTEM_VERSION="$SYSTEM_VERSION" \
	"$ROOT/scripts/validate-latest-buildroot-sg2002-rootfs.sh" "$ROOTFS_IMAGE"

sha256sum "$ROOTFS_IMAGE" "$OUTPUT_DIR/images/rootfs.tar"
printf 'replacement rootfs ready: %s\n' "$ROOTFS_IMAGE"
