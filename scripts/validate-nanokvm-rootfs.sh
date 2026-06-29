#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <rootfs.ext4>" >&2
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

[ -f "$IMAGE" ] || die "rootfs image does not exist: $IMAGE"
command -v debugfs >/dev/null 2>&1 || die "debugfs is required"

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

debugfs_output "stats" >/dev/null || die "not a readable ext rootfs image: $IMAGE"

require_dir /kvmapp
require_dir /kvmapp/server
require_dir /kvmapp/backends
require_dir /kvmapp/system
require_dir /kvmapp/system/init.d
require_dir /kvmapp/server/web
require_dir /etc/init.d
require_dir /etc/kvm

require_regular /kvmapp/version
require_regular /kvmapp/server/NanoKVM-Server
require_regular /kvmapp/backends/NanoKVM-Server.rust
require_regular /kvmapp/kvm_system/kvm_system
require_regular /kvmapp/system/init.d/S95nanokvm
require_regular /kvmapp/system/keys/system-update-signing.pub.pem
require_regular /kvmapp/server/web/index.html
require_regular /etc/init.d/S95nanokvm
require_regular /etc/kvm/backend

reject_path /kvmapp/backends/NanoKVM-Server.go
reject_path /kvmapp/server/NanoKVM-Server.go
reject_path /kvmapp/server/NanoKVM-Server.go.bak
reject_path /etc/kvm/scripts/switch-backend-go.sh

version_file=$(dump_file /kvmapp/version version)
version=$(trim_file "$version_file")
[ -n "$version" ] || die "/kvmapp/version is empty"

if [ -n "$EXPECTED_KVMAPP_VERSION" ] && [ "$version" != "$EXPECTED_KVMAPP_VERSION" ]; then
  die "unexpected /kvmapp/version: $version, expected $EXPECTED_KVMAPP_VERSION"
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
