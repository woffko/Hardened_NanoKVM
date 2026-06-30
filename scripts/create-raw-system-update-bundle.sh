#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <version> <target> <boot.vfat> <rootfs.sd> <output-dir>" >&2
  echo "" >&2
  echo "environment:" >&2
  echo "  BASE_VERSION=<current base image marker>" >&2
  echo "  KERNEL_VERSION=<kernel version after update>" >&2
  echo "  SECURITY_PATCH_LEVEL=<optional security patch/backport label>" >&2
  echo "  RAW_IMAGE_COMPRESSION=gzip|none (default: gzip)" >&2
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
  raw_file="$4"
  stored_file="$5"
  compression="$6"
  size=$(wc -c < "$raw_file" | tr -d ' ')
  sha256=$(sha256sum "$raw_file" | awk '{print $1}')
  if [ "$compression" = "gzip" ]; then
    compressed_size=$(wc -c < "$stored_file" | tr -d ' ')
    compressed_sha256=$(sha256sum "$stored_file" | awk '{print $1}')
    printf '    {"payload": "%s", "device": "%s", "label": "%s", "size": %s, "sha256": "%s", "compression": "gzip", "compressed_size": %s, "compressed_sha256": "%s"}' \
      "$payload" "$device" "$label" "$size" "$sha256" "$compressed_size" "$compressed_sha256"
  else
    printf '    {"payload": "%s", "device": "%s", "label": "%s", "size": %s, "sha256": "%s"}' \
      "$payload" "$device" "$label" "$size" "$sha256"
  fi
}

patch_rootfs_image() {
  rootfs="$1"
  fstab_file="$STAGE_DIR/rootfs-fstab"
  version_file="$STAGE_DIR/system-version.json"
  debugfs_cmds="$STAGE_DIR/rootfs-patch.debugfs"

  command -v debugfs >/dev/null 2>&1 || die "debugfs is required"
  debugfs -R "dump /etc/fstab $fstab_file" "$rootfs" >/dev/null 2>&1 || : > "$fstab_file"
  if ! grep -Eq '^[[:space:]]*[^#]+[[:space:]]+/data[[:space:]]+' "$fstab_file"; then
    printf '\n/dev/mmcblk0p3\t/data\texfat\tdefaults\t0\t0\n' >> "$fstab_file"
  fi

  {
    printf '{\n'
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "target": "%s",\n' "$TARGET"
    printf '  "base_version": "%s",\n' "$BASE_VERSION"
    printf '  "kernel_version": "%s"' "$KERNEL_VERSION"
    if [ -n "$SECURITY_PATCH_LEVEL" ]; then
      printf ',\n  "security_patch_level": "%s"' "$SECURITY_PATCH_LEVEL"
    fi
    printf '\n'
    printf '}\n'
  } > "$version_file"

  {
    printf 'mkdir /etc/kvm\n'
    printf 'rm /etc/fstab\n'
    printf 'write %s /etc/fstab\n' "$fstab_file"
    printf 'sif /etc/fstab mode 0100644\n'
    printf 'sif /etc/fstab uid 0\n'
    printf 'sif /etc/fstab gid 0\n'
    printf 'rm /etc/kvm/system-version.json\n'
    printf 'write %s /etc/kvm/system-version.json\n' "$version_file"
    printf 'sif /etc/kvm/system-version.json mode 0100644\n'
    printf 'sif /etc/kvm/system-version.json uid 0\n'
    printf 'sif /etc/kvm/system-version.json gid 0\n'
  } > "$debugfs_cmds"

  debugfs -w -f "$debugfs_cmds" "$rootfs" >/dev/null 2>&1
}

if [ "$#" -ne 5 ]; then
  usage
fi

VERSION="$1"
TARGET="$2"
BOOT_IMAGE="$3"
ROOTFS_IMAGE="$4"
OUT_DIR="$5"
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

validate_token "version" "$VERSION"
validate_token "target" "$TARGET"
[ -f "$BOOT_IMAGE" ] || die "boot image does not exist: $BOOT_IMAGE"
[ -f "$ROOTFS_IMAGE" ] || die "rootfs image does not exist: $ROOTFS_IMAGE"
"$ROOT_DIR/scripts/validate-nanokvm-rootfs.sh" "$ROOTFS_IMAGE" >/dev/null

BASE_VERSION="${BASE_VERSION:-unknown}"
KERNEL_VERSION="${KERNEL_VERSION:-unknown}"
SECURITY_PATCH_LEVEL="${SECURITY_PATCH_LEVEL:-}"
RAW_IMAGE_COMPRESSION="${RAW_IMAGE_COMPRESSION:-gzip}"
REQUIRED_FREE_BYTES="${REQUIRED_FREE_BYTES:-2147483648}"
BUNDLE_NAME="${BUNDLE_NAME:-hardened-nanokvm-system-$VERSION.tar.gz}"

case "$RAW_IMAGE_COMPRESSION" in
  gzip | none) ;;
  *) die "invalid RAW_IMAGE_COMPRESSION: $RAW_IMAGE_COMPRESSION" ;;
esac

case "$REQUIRED_FREE_BYTES" in
  "" | *[!0-9]*) die "invalid REQUIRED_FREE_BYTES: $REQUIRED_FREE_BYTES" ;;
esac

if [ -n "$SECURITY_PATCH_LEVEL" ]; then
  case "$SECURITY_PATCH_LEVEL" in
    .* | *..* | *.) die "invalid SECURITY_PATCH_LEVEL: $SECURITY_PATCH_LEVEL" ;;
  esac
  printf '%s' "$SECURITY_PATCH_LEVEL" | grep -Eq '^[A-Za-z0-9._+:/ -]+$' ||
    die "invalid SECURITY_PATCH_LEVEL: $SECURITY_PATCH_LEVEL"
fi

case "$BUNDLE_NAME" in
  hardened-nanokvm-system-*.tar.gz) ;;
  *) die "invalid system update bundle name: $BUNDLE_NAME" ;;
esac

STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/hardened-raw-system-update.XXXXXX")
trap 'rm -rf "$STAGE_DIR"' EXIT INT TERM

mkdir -p "$STAGE_DIR/payload/images" "$STAGE_DIR/raw" "$OUT_DIR"
cp -f "$BOOT_IMAGE" "$STAGE_DIR/raw/boot.vfat"
cp -f "$ROOTFS_IMAGE" "$STAGE_DIR/raw/rootfs.sd"
patch_rootfs_image "$STAGE_DIR/raw/rootfs.sd"
"$ROOT_DIR/scripts/validate-nanokvm-rootfs.sh" "$STAGE_DIR/raw/rootfs.sd" >/dev/null

if [ "$RAW_IMAGE_COMPRESSION" = "gzip" ]; then
  gzip -n -c "$STAGE_DIR/raw/boot.vfat" > "$STAGE_DIR/payload/images/boot.vfat.gz"
  gzip -n -c "$STAGE_DIR/raw/rootfs.sd" > "$STAGE_DIR/payload/images/rootfs.sd.gz"
  BOOT_PAYLOAD="images/boot.vfat.gz"
  ROOTFS_PAYLOAD="images/rootfs.sd.gz"
  BOOT_STORED="$STAGE_DIR/payload/images/boot.vfat.gz"
  ROOTFS_STORED="$STAGE_DIR/payload/images/rootfs.sd.gz"
else
  cp -f "$STAGE_DIR/raw/boot.vfat" "$STAGE_DIR/payload/images/boot.vfat"
  cp -f "$STAGE_DIR/raw/rootfs.sd" "$STAGE_DIR/payload/images/rootfs.sd"
  BOOT_PAYLOAD="images/boot.vfat"
  ROOTFS_PAYLOAD="images/rootfs.sd"
  BOOT_STORED="$STAGE_DIR/payload/images/boot.vfat"
  ROOTFS_STORED="$STAGE_DIR/payload/images/rootfs.sd"
fi

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
  if [ -n "$SECURITY_PATCH_LEVEL" ]; then
    printf '  "security_patch_level": "%s",\n' "$SECURITY_PATCH_LEVEL"
  fi
  printf '  "source_commit": "%s",\n' "$SOURCE_COMMIT"
  printf '  "created_utc": "%s",\n' "$CREATED_UTC"
  printf '  "required_free_bytes": %s,\n' "$REQUIRED_FREE_BYTES"
  printf '  "requires_reboot": true,\n'
  printf '  "operations": ["stage", "write-raw-devices", "sync", "reboot", "manual-recovery-only"],\n'
  printf '  "files": [],\n'
  printf '  "raw_images": [\n'
  json_image "ROOTFS" "$ROOTFS_PAYLOAD" "/dev/mmcblk0p2" "$STAGE_DIR/raw/rootfs.sd" "$ROOTFS_STORED" "$RAW_IMAGE_COMPRESSION"
  printf ',\n'
  json_image "BOOT" "$BOOT_PAYLOAD" "/dev/mmcblk0p1" "$STAGE_DIR/raw/boot.vfat" "$BOOT_STORED" "$RAW_IMAGE_COMPRESSION"
  printf '\n  ]\n'
  printf '}\n'
} > "$MANIFEST"

ARCHIVE="$OUT_DIR/$BUNDLE_NAME"
tar -C "$STAGE_DIR" -czf "$ARCHIVE" manifest.json payload
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
openssl dgst -sha512 "$ARCHIVE" > "$ARCHIVE.sha512"

echo "$ARCHIVE"
