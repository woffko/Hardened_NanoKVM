#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
OUT_DIR="${OUT_DIR:-$BUILD_DIR/sd-image}"
BASE_IMAGE="${NANOKVM_BASE_IMAGE:-$OUT_DIR/20260123_NanoKVM_Rev1_4_2.img}"
KVMAPP_DIR="${KVMAPP_DIR:-$BUILD_DIR/kvmapp-rust/kvmapp}"
SENSOR_DATA_DIR="${SENSOR_DATA_DIR:-$KVMAPP_DIR/system/mnt-data}"
VERSION="${HARDENED_RELEASE_VERSION:-alpha-0.1}"
SYSTEM_VERSION="${HARDENED_SYSTEM_VERSION:-}"
SYSTEM_TARGET="${HARDENED_SYSTEM_TARGET:-sg2002-licheervnano-sd}"
SYSTEM_BASE_VERSION="${HARDENED_SYSTEM_BASE_VERSION:-}"
SYSTEM_KERNEL_VERSION="${HARDENED_SYSTEM_KERNEL_VERSION:-}"
SYSTEM_SECURITY_PATCH_LEVEL="${HARDENED_SYSTEM_SECURITY_PATCH_LEVEL:-}"
OUTPUT_BASENAME="${OUTPUT_BASENAME:-Hardened_NanoKVM_${VERSION//[^A-Za-z0-9]/_}_Rev1_4_2_rust}"
BOOT_INIT_SCRIPTS=(
  S00kmod
  S01fs
  S03usbdev
  S15kvmhwd
  S30eth
  S30wifi
  S50avahi-daemon
  S50sshd
  S80dnsmasq
  S95nanokvm
)

OUT_IMAGE="$OUT_DIR/$OUTPUT_BASENAME.img"
ROOTFS_IMAGE="$OUT_DIR/$OUTPUT_BASENAME.rootfs.ext"
STATE_FILE="$OUT_DIR/$OUTPUT_BASENAME.backend-state"
SYSTEM_VERSION_FILE="$OUT_DIR/$OUTPUT_BASENAME.system-version.json"
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
if [ -n "$SYSTEM_VERSION" ]; then
  {
    printf '{\n'
    printf '  "version": "%s",\n' "$SYSTEM_VERSION"
    printf '  "target": "%s",\n' "$SYSTEM_TARGET"
    printf '  "base_version": "%s",\n' "$SYSTEM_BASE_VERSION"
    printf '  "kernel_version": "%s"' "$SYSTEM_KERNEL_VERSION"
    if [ -n "$SYSTEM_SECURITY_PATCH_LEVEL" ]; then
      printf ',\n  "security_patch_level": "%s"' "$SYSTEM_SECURITY_PATCH_LEVEL"
    fi
    printf '\n}\n'
  } > "$SYSTEM_VERSION_FILE"
fi

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

  if [ -n "$SYSTEM_VERSION" ]; then
    printf 'rm /etc/kvm/system-version.json\n'
    printf 'write %s /etc/kvm/system-version.json\n' "$SYSTEM_VERSION_FILE"
    printf 'sif /etc/kvm/system-version.json mode 0100644\n'
    printf 'sif /etc/kvm/system-version.json uid 0\n'
    printf 'sif /etc/kvm/system-version.json gid 0\n'
  fi

  if [ -d "$SENSOR_DATA_DIR" ]; then
    printf 'mkdir /mnt\n'
    printf 'mkdir /mnt/data\n'
    find "$SENSOR_DATA_DIR" -type f | sort | while IFS= read -r file; do
      rel="${file#$SENSOR_DATA_DIR/}"
      perm="$(stat -c '%a' "$file")"
      printf 'rm /mnt/data/%s\n' "$rel"
      printf 'write %s /mnt/data/%s\n' "$file" "$rel"
      printf 'sif /mnt/data/%s mode 0100%s\n' "$rel" "$perm"
      printf 'sif /mnt/data/%s uid 0\n' "$rel"
      printf 'sif /mnt/data/%s gid 0\n' "$rel"
    done
    if [ -f "$SENSOR_DATA_DIR/sensor_cfg.ini.LT" ]; then
      printf 'rm /mnt/data/sensor_cfg.ini\n'
      printf 'write %s /mnt/data/sensor_cfg.ini\n' "$SENSOR_DATA_DIR/sensor_cfg.ini.LT"
      printf 'sif /mnt/data/sensor_cfg.ini mode 0100644\n'
      printf 'sif /mnt/data/sensor_cfg.ini uid 0\n'
      printf 'sif /mnt/data/sensor_cfg.ini gid 0\n'
    fi
  fi

  for script in "${BOOT_INIT_SCRIPTS[@]}"; do
    script_path="$KVMAPP_DIR/system/init.d/$script"
    [ -f "$script_path" ] || continue
    printf 'rm /etc/init.d/%s\n' "$script"
    printf 'write %s /etc/init.d/%s\n' "$script_path" "$script"
    printf 'sif /etc/init.d/%s mode 0100755\n' "$script"
    printf 'sif /etc/init.d/%s uid 0\n' "$script"
    printf 'sif /etc/init.d/%s gid 0\n' "$script"
  done
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
