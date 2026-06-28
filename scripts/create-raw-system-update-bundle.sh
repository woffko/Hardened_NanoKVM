#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <version> <target> <boot.vfat> <rootfs.sd> <output-dir>" >&2
  echo "" >&2
  echo "environment:" >&2
  echo "  BASE_VERSION=<current base image marker>" >&2
  echo "  KERNEL_VERSION=<kernel version after update>" >&2
  echo "  REQUIRED_FREE_BYTES=<bytes required on staging filesystem>" >&2
  echo "  BUNDLE_NAME=<archive filename>" >&2
  exit 1
}

die() {
  echo "error: $*" >&2
  exit 1
}

validate_token() {
  name="$1"
  value="$2"
  case "$value" in
    "" | *[!A-Za-z0-9._+-]* | .* | *..* | *.)
      die "invalid $name: $value"
      ;;
  esac
}

json_image() {
  label="$1"
  payload="$2"
  device="$3"
  file="$4"
  size=$(wc -c < "$file" | tr -d ' ')
  sha256=$(sha256sum "$file" | awk '{print $1}')
  printf '    {"payload": "%s", "device": "%s", "label": "%s", "size": %s, "sha256": "%s"}' \
    "$payload" "$device" "$label" "$size" "$sha256"
}

if [ "$#" -ne 5 ]; then
  usage
fi

VERSION="$1"
TARGET="$2"
BOOT_IMAGE="$3"
ROOTFS_IMAGE="$4"
OUT_DIR="$5"

validate_token "version" "$VERSION"
validate_token "target" "$TARGET"
[ -f "$BOOT_IMAGE" ] || die "boot image does not exist: $BOOT_IMAGE"
[ -f "$ROOTFS_IMAGE" ] || die "rootfs image does not exist: $ROOTFS_IMAGE"

BASE_VERSION="${BASE_VERSION:-unknown}"
KERNEL_VERSION="${KERNEL_VERSION:-unknown}"
REQUIRED_FREE_BYTES="${REQUIRED_FREE_BYTES:-2147483648}"
BUNDLE_NAME="${BUNDLE_NAME:-hardened-nanokvm-system-$VERSION.tar.gz}"

case "$REQUIRED_FREE_BYTES" in
  "" | *[!0-9]*) die "invalid REQUIRED_FREE_BYTES: $REQUIRED_FREE_BYTES" ;;
esac

case "$BUNDLE_NAME" in
  hardened-nanokvm-system-*.tar.gz) ;;
  *) die "invalid system update bundle name: $BUNDLE_NAME" ;;
esac

STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/hardened-raw-system-update.XXXXXX")
trap 'rm -rf "$STAGE_DIR"' EXIT INT TERM

mkdir -p "$STAGE_DIR/payload/images" "$OUT_DIR"
cp -f "$BOOT_IMAGE" "$STAGE_DIR/payload/images/boot.vfat"
cp -f "$ROOTFS_IMAGE" "$STAGE_DIR/payload/images/rootfs.sd"

CREATED_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
SOURCE_COMMIT=$(git -C "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)" rev-parse --short HEAD 2>/dev/null || printf unknown)
MANIFEST="$STAGE_DIR/manifest.json"

{
  printf '{\n'
  printf '  "format": "hardened-nanokvm-system-update-v1",\n'
  printf '  "version": "%s",\n' "$VERSION"
  printf '  "target": "%s",\n' "$TARGET"
  printf '  "base_version": "%s",\n' "$BASE_VERSION"
  printf '  "kernel_version": "%s",\n' "$KERNEL_VERSION"
  printf '  "source_commit": "%s",\n' "$SOURCE_COMMIT"
  printf '  "created_utc": "%s",\n' "$CREATED_UTC"
  printf '  "required_free_bytes": %s,\n' "$REQUIRED_FREE_BYTES"
  printf '  "requires_reboot": true,\n'
  printf '  "operations": ["stage", "write-raw-devices", "sync", "reboot", "manual-recovery-only"],\n'
  printf '  "files": [],\n'
  printf '  "raw_images": [\n'
  json_image "ROOTFS" "images/rootfs.sd" "/dev/mmcblk0p2" "$STAGE_DIR/payload/images/rootfs.sd"
  printf ',\n'
  json_image "BOOT" "images/boot.vfat" "/dev/mmcblk0p1" "$STAGE_DIR/payload/images/boot.vfat"
  printf '\n  ]\n'
  printf '}\n'
} > "$MANIFEST"

ARCHIVE="$OUT_DIR/$BUNDLE_NAME"
tar -C "$STAGE_DIR" -czf "$ARCHIVE" manifest.json payload
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
openssl dgst -sha512 "$ARCHIVE" > "$ARCHIVE.sha512"

echo "$ARCHIVE"
