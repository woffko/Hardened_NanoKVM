#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <rootfs.ext4>" >&2
  echo "Current security-candidate protocol only (independent app recovery required)." >&2
  echo "Historical RC12 raw assets: scripts/verify-rc12-raw-bundle.sh (fixed hashes)." >&2
  echo "" >&2
  echo "environment:" >&2
  echo "  EXPECTED_BACKEND=rust|any      default: rust" >&2
  echo "  EXPECTED_KVMAPP_VERSION=<version> optional" >&2
  exit 1
}

die() {
  echo "error: $*" >&2
  exit 1
}

if [ "$#" -ne 1 ]; then
  usage
fi

IMAGE="$1"
EXPECTED_BACKEND="${EXPECTED_BACKEND:-rust}"
EXPECTED_KVMAPP_VERSION="${EXPECTED_KVMAPP_VERSION:-}"
EXPECTED_UPDATE_KEY_ID="${EXPECTED_UPDATE_KEY_ID:-}"
EXPECTED_UPDATE_PUBLIC_KEY_DER_SHA256="${EXPECTED_UPDATE_PUBLIC_KEY_DER_SHA256:-}"
BOOT_INIT_SCRIPTS="S00kmod S01fs S03usbdev S15kvmhwd S30eth S30wifi S50avahi-daemon S50sshd S95nanokvm"

[ -f "$IMAGE" ] || die "rootfs image does not exist: $IMAGE"
command -v debugfs >/dev/null 2>&1 || die "debugfs is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required"

case "$EXPECTED_BACKEND" in
  rust | any) ;;
  *) die "invalid EXPECTED_BACKEND: $EXPECTED_BACKEND" ;;
esac

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-rootfs-validate.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

debugfs_output() {
  command="$1"
  output=$(LC_ALL=C debugfs -R "$command" "$IMAGE" 2>&1 || true)
  case "$output" in
    *"Bad magic number"* | *"Filesystem not open"* | *"File not found"* | \
    *"not found by ext2_lookup"* | *"No such file or directory"* | \
    *"Command not found"*)
      return 1
      ;;
  esac
  printf '%s\n' "$output"
}

require_type() {
  path="$1"
  type="$2"
  output=$(debugfs_output "stat $path") || die "missing required $type: $path"
  printf '%s\n' "$output" | grep -q "Type: $type" || die "required $path is not a $type"
}

require_dir() {
  require_type "$1" "directory"
}

require_regular() {
  require_type "$1" "regular"
}

reject_path() {
  path="$1"
  if debugfs_output "stat $path" >/dev/null; then
    die "forbidden path exists: $path"
  fi
}

dump_file() {
  path="$1"
  name="$2"
  dest="$TMP_DIR/$name"
  output=$(LC_ALL=C debugfs -R "dump $path $dest" "$IMAGE" 2>&1 || true)
  case "$output" in
    *"Bad magic number"* | *"Filesystem not open"* | *"File not found"* | \
    *"not found by ext2_lookup"* | *"No such file or directory"* | \
    *"Command not found"*)
      die "missing required file: $path"
      ;;
  esac
  [ -s "$dest" ] || die "required file is empty: $path"
  printf '%s\n' "$dest"
}

trim_file() {
  tr -d '\r' < "$1" | awk 'NF { value=$0 } END { print value }'
}

require_boot_state_boundary() {
  s01=$(dump_file /kvmapp/system/init.d/S01fs no-legacy-S01fs) || return 1
  s95=$(dump_file /kvmapp/system/init.d/S95nanokvm no-legacy-S95nanokvm) || return 1
  installed_s01=$(dump_file /etc/init.d/S01fs installed-no-legacy-S01fs) || return 1
  installed_s95=$(dump_file /etc/init.d/S95nanokvm installed-no-legacy-S95nanokvm) || return 1
  cmp -s "$s01" "$installed_s01" || die "packaged and installed S01fs differ"
  cmp -s "$s95" "$installed_s95" || die "packaged and installed S95nanokvm differ"
  if grep -Eq 'RAW_RESTORE_|restore_raw_root_config|restore_preserved_path|fix_restored_permissions' "$s01"; then
    die "S01fs contains legacy p3 restore authority"
  else
    [ "$?" -eq 1 ] || die "could not inspect S01fs boot authority"
  fi
  if grep -Fq 'SYSTEM_RAW_INSTALL_MARKER' "$s95"; then
    die "S95nanokvm imports legacy p3 boot/rollback authority"
  else
    [ "$?" -eq 1 ] || die "could not inspect S95nanokvm boot authority"
  fi
}

debugfs_output "stats" >/dev/null || die "not a readable ext rootfs image: $IMAGE"

require_dir /kvmapp
require_dir /kvmapp/server
require_dir /kvmapp/backends
require_dir /kvmapp/system
require_dir /kvmapp/system/init.d
require_dir /kvmapp/system/mnt-data
require_dir /kvmapp/server/web
require_dir /etc/init.d
require_dir /etc/kvm
require_dir /mnt/data

require_regular /kvmapp/version
require_regular /kvmapp/server/NanoKVM-Server
require_regular /kvmapp/backends/NanoKVM-Server.rust
python3 "$(dirname "$0")/verify-app-recovery-rootfs.py" "$IMAGE" || \
  die "independent app recovery is missing/unsafe/mismatched; this validator is for current candidates, not historical RC12"
require_regular /kvmapp/hwmon/nanokvm-hwmon
require_regular /kvmapp/kvm_system/kvm_system
require_regular /kvmapp/system/keys/system-update-signing.pub.pem
if [ -n "$EXPECTED_UPDATE_KEY_ID" ]; then
  [ -n "$EXPECTED_UPDATE_PUBLIC_KEY_DER_SHA256" ] || \
    die "EXPECTED_UPDATE_PUBLIC_KEY_DER_SHA256 is required with EXPECTED_UPDATE_KEY_ID"
  require_dir /kvmapp/system/keys/update-keys
  require_regular "/kvmapp/system/keys/update-keys/$EXPECTED_UPDATE_KEY_ID.pub.pem"
  require_regular /kvmapp/system/keys/update-key-policy
fi
require_regular /kvmapp/system/mnt-data/sensor_cfg.ini.LT
require_regular /kvmapp/server/web/index.html
require_regular /etc/kvm/backend
require_regular /mnt/data/sensor_cfg.ini.LT
require_regular /mnt/data/sensor_cfg.ini

for script in $BOOT_INIT_SCRIPTS; do
  require_regular "/kvmapp/system/init.d/$script"
  require_regular "/etc/init.d/$script"
done

require_boot_state_boundary || die "unsafe boot restore/rollback boundary"

reject_path /kvmapp/backends/NanoKVM-Server.go
reject_path /kvmapp/server/NanoKVM-Server.go
reject_path /kvmapp/server/NanoKVM-Server.go.bak
reject_path /kvmapp/jpg_stream
reject_path /kvmapp/kvm_system/kvm_stream
reject_path /kvmapp/kvm_new_app
reject_path /kvmapp/kvm_new_img
reject_path /etc/kvm/scripts/switch-backend-go.sh
reject_path /etc/kvm/scripts/switch-backend-rust.sh
reject_path /etc/init.d/S02udisk
reject_path /etc/init.d/S04backlight
reject_path /etc/init.d/S05tp
reject_path /etc/init.d/S40bluetoothd
reject_path /etc/init.d/S50ssdpd

version_file=$(dump_file /kvmapp/version version)
version=$(trim_file "$version_file")
[ -n "$version" ] || die "/kvmapp/version is empty"

if [ -n "$EXPECTED_KVMAPP_VERSION" ] && [ "$version" != "$EXPECTED_KVMAPP_VERSION" ]; then
  die "unexpected /kvmapp/version: $version, expected $EXPECTED_KVMAPP_VERSION"
fi

if [ -n "$EXPECTED_UPDATE_KEY_ID" ]; then
  update_public_key=$(dump_file "/kvmapp/system/keys/update-keys/$EXPECTED_UPDATE_KEY_ID.pub.pem" update-public-key)
  update_public_key_fingerprint="$(openssl pkey -pubin -in "$update_public_key" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  [ "$update_public_key_fingerprint" = "$EXPECTED_UPDATE_PUBLIC_KEY_DER_SHA256" ] || \
    die "unexpected production update public key fingerprint"
  update_key_policy=$(dump_file /kvmapp/system/keys/update-key-policy update-key-policy)
  normalized_policy="$TMP_DIR/update-key-policy.normalized"
  sed -e 's/[[:space:]]*$//' -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' \
    "$update_key_policy" | LC_ALL=C sort > "$normalized_policy"
  cat > "$TMP_DIR/update-key-policy.expected" <<EOF
hardened-system-dev
hardened-system-prod-2026q3
hardened-system-test
EOF
  cmp -s "$normalized_policy" "$TMP_DIR/update-key-policy.expected" || \
    die "unexpected RC12 update key policy"
fi

backend_file=$(dump_file /etc/kvm/backend backend)
backend=$(trim_file "$backend_file")
case "$backend" in
  rust) ;;
  *) die "unexpected /etc/kvm/backend value: $backend" ;;
esac

if [ "$EXPECTED_BACKEND" != "any" ] && [ "$backend" != "$EXPECTED_BACKEND" ]; then
  die "unexpected /etc/kvm/backend: $backend, expected $EXPECTED_BACKEND"
fi

echo "validated Hardened NanoKVM rootfs: $IMAGE"
echo "kvmapp version: $version"
echo "backend: $backend"
