#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
OUT_DIR="${OUT_DIR:-$BUILD_DIR/sd-image}"
BASE_IMAGE="${NANOKVM_BASE_IMAGE:-$OUT_DIR/20260123_NanoKVM_Rev1_4_2.img}"
KVMAPP_DIR="${KVMAPP_DIR:-$BUILD_DIR/kvmapp-rust/kvmapp}"
VERSION="${HARDENED_RELEASE_VERSION:-alpha-0.1}"
OUTPUT_BASENAME="${OUTPUT_BASENAME:-Hardened_NanoKVM_${VERSION//[^A-Za-z0-9]/_}_Rev1_4_2_rust}"

OUT_IMAGE="$OUT_DIR/$OUTPUT_BASENAME.img"
ROOTFS_IMAGE="$OUT_DIR/$OUTPUT_BASENAME.rootfs.ext"
STATE_FILE="$OUT_DIR/$OUTPUT_BASENAME.backend-state"
DEBUGFS_CMDS="$OUT_DIR/$OUTPUT_BASENAME.debugfs.cmd"
FSTAB_FILE="$OUT_DIR/$OUTPUT_BASENAME.fstab"

require_file() {
  if [ ! -f "$1" ]; then
    echo "missing required file: $1" >&2
    exit 1
  fi
}

require_dir() {
  if [ ! -d "$1" ]; then
    echo "missing required directory: $1" >&2
    exit 1
  fi
}

require_file "$BASE_IMAGE"
require_dir "$KVMAPP_DIR"
require_file "$KVMAPP_DIR/server/NanoKVM-Server"

mkdir -p "$OUT_DIR"

read -r ROOTFS_START ROOTFS_SECTORS <<EOF
$(partx -g -o NR,START,SECTORS "$BASE_IMAGE" | awk '$1 == 2 { print $2, $3; exit }')
EOF

if [ -z "${ROOTFS_START:-}" ] || [ -z "${ROOTFS_SECTORS:-}" ]; then
  echo "could not find Linux rootfs partition in $BASE_IMAGE" >&2
  exit 1
fi

echo "Copying base image..."
cp -f "$BASE_IMAGE" "$OUT_IMAGE"

echo "Extracting rootfs partition..."
dd if="$OUT_IMAGE" of="$ROOTFS_IMAGE" bs=512 skip="$ROOTFS_START" count="$ROOTFS_SECTORS" status=none

printf 'rust\n' > "$STATE_FILE"

debugfs -R "dump /etc/fstab $FSTAB_FILE" "$ROOTFS_IMAGE" >/dev/null 2>&1 || : > "$FSTAB_FILE"
if ! grep -Eq '^[[:space:]]*[^#]+[[:space:]]+/data[[:space:]]+' "$FSTAB_FILE"; then
  printf '\n/dev/mmcblk0p3\t/data\texfat\tdefaults\t0\t0\n' >> "$FSTAB_FILE"
fi

{
  printf 'mkdir /kvmapp\n'
  find "$KVMAPP_DIR" -type d | sort | while IFS= read -r dir; do
    rel="${dir#$KVMAPP_DIR/}"
    [ "$rel" = "$dir" ] && continue
    printf 'mkdir /kvmapp/%s\n' "$rel"
  done

  find "$KVMAPP_DIR" -type f | sort | while IFS= read -r file; do
    rel="${file#$KVMAPP_DIR/}"
    perm="$(stat -c '%a' "$file")"
    printf 'rm /kvmapp/%s\n' "$rel"
    printf 'write %s /kvmapp/%s\n' "$file" "$rel"
    printf 'sif /kvmapp/%s mode 0100%s\n' "$rel" "$perm"
    printf 'sif /kvmapp/%s uid 1000\n' "$rel"
    printf 'sif /kvmapp/%s gid 1000\n' "$rel"
  done

  printf 'mkdir /kvmapp/backends\n'
  printf 'rm /kvmapp/backends/NanoKVM-Server.go\n'
  printf 'rm /kvmapp/server/NanoKVM-Server.go\n'
  printf 'rm /kvmapp/server/NanoKVM-Server.go.bak\n'
  printf 'rm /kvmapp/backends/NanoKVM-Server.rust\n'
  printf 'write %s /kvmapp/backends/NanoKVM-Server.rust\n' "$KVMAPP_DIR/server/NanoKVM-Server"
  printf 'sif /kvmapp/backends/NanoKVM-Server.rust mode 0100755\n'
  printf 'sif /kvmapp/backends/NanoKVM-Server.rust uid 1000\n'
  printf 'sif /kvmapp/backends/NanoKVM-Server.rust gid 1000\n'

  printf 'mkdir /etc/kvm\n'
  printf 'rm /etc/fstab\n'
  printf 'write %s /etc/fstab\n' "$FSTAB_FILE"
  printf 'sif /etc/fstab mode 0100644\n'
  printf 'sif /etc/fstab uid 0\n'
  printf 'sif /etc/fstab gid 0\n'
  printf 'rm /etc/kvm/backend\n'
  printf 'write %s /etc/kvm/backend\n' "$STATE_FILE"
  printf 'sif /etc/kvm/backend mode 0100644\n'
  printf 'sif /etc/kvm/backend uid 0\n'
  printf 'sif /etc/kvm/backend gid 0\n'
  printf 'rm /etc/kvm/scripts/switch-backend-go.sh\n'
  printf 'rm /etc/kvm/scripts/switch-backend-rust.sh\n'

  printf 'rm /etc/init.d/S95nanokvm\n'
  printf 'write %s /etc/init.d/S95nanokvm\n' "$KVMAPP_DIR/system/init.d/S95nanokvm"
  printf 'sif /etc/init.d/S95nanokvm mode 0100755\n'
  printf 'sif /etc/init.d/S95nanokvm uid 0\n'
  printf 'sif /etc/init.d/S95nanokvm gid 0\n'
} > "$DEBUGFS_CMDS"

echo "Updating rootfs with Hardened kvmapp..."
debugfs -w -f "$DEBUGFS_CMDS" "$ROOTFS_IMAGE" >/dev/null

echo "Validating Hardened rootfs..."
EXPECTED_BACKEND="${EXPECTED_BACKEND:-rust}" \
EXPECTED_KVMAPP_VERSION="$(cat "$KVMAPP_DIR/version")" \
  "$ROOT/scripts/validate-nanokvm-rootfs.sh" "$ROOTFS_IMAGE" >/dev/null

echo "Writing rootfs partition back into SD image..."
dd if="$ROOTFS_IMAGE" of="$OUT_IMAGE" bs=512 seek="$ROOTFS_START" conv=notrunc status=none

echo "Compressing image..."
xz -T0 -f -k "$OUT_IMAGE"

echo "Writing checksums..."
sha256sum "$OUT_IMAGE" "$OUT_IMAGE.xz" > "$OUT_DIR/$OUTPUT_BASENAME.sha256"

printf '%s\n' "$OUT_IMAGE"
printf '%s\n' "$OUT_IMAGE.xz"
printf '%s\n' "$OUT_DIR/$OUTPUT_BASENAME.sha256"
