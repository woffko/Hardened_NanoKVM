#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <version> <target> <payload-dir> <output-dir>" >&2
  echo "" >&2
  echo "payload-dir layout:" >&2
  echo "  boot/<file>        -> installs to /boot/<file>" >&2
  echo "  rootfs/<path>      -> installs to /<path>" >&2
  echo "" >&2
  echo "environment:" >&2
  echo "  BASE_VERSION=<current base image marker>" >&2
  echo "  KERNEL_VERSION=<kernel version after update>" >&2
  echo "  REQUIRED_FREE_BYTES=<bytes required on /data>" >&2
  echo "  REQUIRES_REBOOT=true|false" >&2
  echo "  BUNDLE_NAME=<archive filename>" >&2
  exit 1
}

die() {
  echo "error: $*" >&2
  exit 1
}

json_bool() {
  case "$1" in
    true | false) printf '%s' "$1" ;;
    *) die "invalid boolean: $1" ;;
  esac
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

safe_payload_path() {
  rel="$1"
  case "$rel" in
    "" | /* | ../* | */../* | */.. | ..)
      return 1
      ;;
    boot/* | rootfs/*) ;;
    *)
      return 1
      ;;
  esac

  case "$rel" in
    *[!A-Za-z0-9._+/@=-]*)
      return 1
      ;;
  esac

  return 0
}

install_path_for_payload() {
  rel="$1"
  case "$rel" in
    boot/*) printf '/%s' "$rel" ;;
    rootfs/*) printf '/%s' "${rel#rootfs/}" ;;
    *) die "unsupported payload path: $rel" ;;
  esac
}

if [ "$#" -ne 4 ]; then
  usage
fi

VERSION="$1"
TARGET="$2"
PAYLOAD_DIR="${3%/}"
OUT_DIR="$4"

validate_token "version" "$VERSION"
validate_token "target" "$TARGET"

[ -d "$PAYLOAD_DIR" ] || die "payload directory does not exist: $PAYLOAD_DIR"

BASE_VERSION="${BASE_VERSION:-unknown}"
KERNEL_VERSION="${KERNEL_VERSION:-unknown}"
REQUIRED_FREE_BYTES="${REQUIRED_FREE_BYTES:-67108864}"
REQUIRES_REBOOT="${REQUIRES_REBOOT:-true}"
BUNDLE_NAME="${BUNDLE_NAME:-hardened-nanokvm-system-$VERSION.tar.gz}"

case "$REQUIRED_FREE_BYTES" in
  "" | *[!0-9]*) die "invalid REQUIRED_FREE_BYTES: $REQUIRED_FREE_BYTES" ;;
esac

case "$BUNDLE_NAME" in
  hardened-nanokvm-system-*.tar.gz) ;;
  *) die "invalid system update bundle name: $BUNDLE_NAME" ;;
esac

if find "$PAYLOAD_DIR" -type l | grep -q .; then
  die "payload must not contain symlinks"
fi

if ! find "$PAYLOAD_DIR" -type f | grep -q .; then
  die "payload directory has no files"
fi

STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/hardened-system-update.XXXXXX")
trap 'rm -rf "$STAGE_DIR"' EXIT INT TERM

mkdir -p "$STAGE_DIR/payload" "$OUT_DIR"
cp -Rp "$PAYLOAD_DIR/." "$STAGE_DIR/payload/"

FILE_LIST="$STAGE_DIR/files.list"
find "$STAGE_DIR/payload" -type f | LC_ALL=C sort > "$FILE_LIST"

if [ ! -s "$FILE_LIST" ]; then
  die "staged payload has no files"
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
  printf '  "source_commit": "%s",\n' "$SOURCE_COMMIT"
  printf '  "created_utc": "%s",\n' "$CREATED_UTC"
  printf '  "required_free_bytes": %s,\n' "$REQUIRED_FREE_BYTES"
  printf '  "requires_reboot": '
  json_bool "$REQUIRES_REBOOT"
  printf ',\n'
  printf '  "operations": ["backup", "stage", "install-known-paths", "mark-pending", "reboot", "health-check"],\n'
  printf '  "files": [\n'

  first=1
  while IFS= read -r file; do
    rel="${file#$STAGE_DIR/payload/}"
    safe_payload_path "$rel" || die "unsafe payload path: $rel"
    install_path=$(install_path_for_payload "$rel")
    size=$(wc -c < "$file" | tr -d ' ')
    sha256=$(sha256sum "$file" | awk '{print $1}')

    if [ "$first" -eq 0 ]; then
      printf ',\n'
    fi
    first=0
    printf '    {"payload": "%s", "install": "%s", "size": %s, "sha256": "%s"}' \
      "$rel" "$install_path" "$size" "$sha256"
  done < "$FILE_LIST"

  printf '\n  ]\n'
  printf '}\n'
} > "$MANIFEST"

ARCHIVE="$OUT_DIR/$BUNDLE_NAME"
tar -C "$STAGE_DIR" -czf "$ARCHIVE" manifest.json payload
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
openssl dgst -sha512 "$ARCHIVE" > "$ARCHIVE.sha512"

echo "$ARCHIVE"
