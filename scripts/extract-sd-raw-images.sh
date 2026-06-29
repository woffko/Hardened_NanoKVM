#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: scripts/extract-sd-raw-images.sh <hardened-sd.img|hardened-sd.img.xz> <output-dir>

Extracts the boot and rootfs partitions from a full Hardened NanoKVM SD image
for the experimental raw system-update bundle.
USAGE
  exit 1
}

if [ "$#" -ne 2 ]; then
  usage
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT_IMAGE="$1"
OUT_DIR="$2"
SD_IMAGE="$INPUT_IMAGE"
SD_TMP=""

if [ ! -f "$INPUT_IMAGE" ]; then
  echo "missing SD image: $INPUT_IMAGE" >&2
  exit 1
fi

command -v partx >/dev/null 2>&1 || {
  echo "partx is required" >&2
  exit 1
}

mkdir -p "$OUT_DIR"

case "$INPUT_IMAGE" in
  *.xz)
    command -v xz >/dev/null 2>&1 || {
      echo "xz is required for compressed SD images" >&2
      exit 1
    }
    SD_TMP=$(mktemp "${TMPDIR:-/tmp}/nanokvm-sd-image.XXXXXX.img")
    echo "Decompressing SD image..."
    xz -dc "$INPUT_IMAGE" > "$SD_TMP"
    SD_IMAGE="$SD_TMP"
    ;;
esac

cleanup() {
  rm -f "${BOOT_TMP:-}" "${ROOTFS_TMP:-}" "$SD_TMP"
}
trap cleanup EXIT INT TERM

read -r BOOT_START BOOT_SECTORS <<EOF
$(partx -g -o NR,START,SECTORS "$SD_IMAGE" | awk '$1 == 1 { print $2, $3; exit }')
EOF

read -r ROOTFS_START ROOTFS_SECTORS <<EOF
$(partx -g -o NR,START,SECTORS "$SD_IMAGE" | awk '$1 == 2 { print $2, $3; exit }')
EOF

if [ -z "${BOOT_START:-}" ] || [ -z "${BOOT_SECTORS:-}" ]; then
  echo "could not find boot partition in $SD_IMAGE" >&2
  exit 1
fi

if [ -z "${ROOTFS_START:-}" ] || [ -z "${ROOTFS_SECTORS:-}" ]; then
  echo "could not find rootfs partition in $SD_IMAGE" >&2
  exit 1
fi

BOOT_IMAGE="$OUT_DIR/boot.vfat"
ROOTFS_IMAGE="$OUT_DIR/rootfs.sd"
BOOT_TMP="$BOOT_IMAGE.tmp.$$"
ROOTFS_TMP="$ROOTFS_IMAGE.tmp.$$"

echo "Extracting boot partition..."
dd if="$SD_IMAGE" of="$BOOT_TMP" bs=512 skip="$BOOT_START" count="$BOOT_SECTORS" status=none

echo "Extracting rootfs partition..."
dd if="$SD_IMAGE" of="$ROOTFS_TMP" bs=512 skip="$ROOTFS_START" count="$ROOTFS_SECTORS" status=none

"$ROOT/scripts/validate-nanokvm-rootfs.sh" "$ROOTFS_TMP" >/dev/null

mv -f "$BOOT_TMP" "$BOOT_IMAGE"
mv -f "$ROOTFS_TMP" "$ROOTFS_IMAGE"

sha256sum "$BOOT_IMAGE" "$ROOTFS_IMAGE" > "$OUT_DIR/SHA256SUMS"

printf '%s\n' "$BOOT_IMAGE"
printf '%s\n' "$ROOTFS_IMAGE"
