#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDROOT_VERSION="${BUILDROOT_VERSION:-2026.05.1}"
SYSTEM_VERSION="${HARDENED_SG2002_SYSTEM_VERSION:-0.3.0-raw.11}"
CONFIG_OUTPUT_DIR="${HARDENED_SG2002_BUILDROOT_OUTPUT_DIR:-$ROOT/build/latestbuildroot/sg2002-config-${BUILDROOT_VERSION}-raw11}"
SD_OUTPUT_DIR="${HARDENED_SG2002_SD_OUTPUT_DIR:-$ROOT/build/latestbuildroot/sg2002-sd-image-${BUILDROOT_VERSION}-raw11}"
RAW_OUTPUT_ROOT="${HARDENED_SG2002_RAW_OUTPUT_ROOT:-$ROOT/build/latestbuildroot/raw-system-update-${SYSTEM_VERSION}}"
SIGNING_KEY="${SYSTEM_UPDATE_SIGNING_KEY:-}"

test -n "$SIGNING_KEY" || {
	echo "SYSTEM_UPDATE_SIGNING_KEY is required" >&2
	exit 1
}
test -f "$SIGNING_KEY"

HARDENED_SG2002_BUILDROOT_OUTPUT_DIR="$CONFIG_OUTPUT_DIR" \
HARDENED_SG2002_SD_OUTPUT_DIR="$SD_OUTPUT_DIR" \
EXPECTED_KVMAPP_VERSION="${EXPECTED_KVMAPP_VERSION:-2.0.41}" \
	"$ROOT/scripts/assemble-latest-buildroot-sg2002-sd-image.sh"

SYSTEM_UPDATE_SIGNING_KEY="$SIGNING_KEY" \
HARDENED_SG2002_SYSTEM_VERSION="$SYSTEM_VERSION" \
HARDENED_SG2002_SD_OUTPUT_DIR="$SD_OUTPUT_DIR" \
HARDENED_SG2002_RAW_IMAGES_DIR="$RAW_OUTPUT_ROOT/images" \
HARDENED_SG2002_RAW_UPDATE_OUT="$RAW_OUTPUT_ROOT/artifacts" \
EXPECTED_KVMAPP_VERSION="${EXPECTED_KVMAPP_VERSION:-2.0.41}" \
	"$ROOT/scripts/package-latest-buildroot-sg2002-raw-update.sh"

ARCHIVE="$RAW_OUTPUT_ROOT/artifacts/hardened-nanokvm-system-${SYSTEM_VERSION}.tar.gz"
METADATA="$RAW_OUTPUT_ROOT/artifacts/system-latest.json"
SIGNATURE="$METADATA.sig"

"$ROOT/scripts/verify-system-update-metadata.sh" \
	"$METADATA" "$SIGNATURE" "$ROOT/kvmapp/system/keys/system-update-signing.pub.pem"
test "$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$METADATA" | head -n 1)" = "$SYSTEM_VERSION"

sha256sum \
	"$SD_OUTPUT_DIR/images/hardened-sg2002-port.img" \
	"$ARCHIVE" \
	"$METADATA" \
	"$SIGNATURE"
printf 'replacement SD image: %s\n' "$SD_OUTPUT_DIR/images/hardened-sg2002-port.img"
printf 'replacement raw update: %s\n' "$ARCHIVE"
