#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDROOT_VERSION="${BUILDROOT_VERSION:-2026.05.1}"
BUILDROOT_DOWNLOAD_BASE="${BUILDROOT_DOWNLOAD_BASE:-https://buildroot.org/downloads}"
PROBE_ROOT="${LATEST_BUILDROOT_PROBE_ROOT:-$ROOT/build/latestbuildroot}"
DOWNLOAD_DIR="${BUILDROOT_DOWNLOAD_DIR:-$ROOT/build/downloads}"
ARCHIVE="${DOWNLOAD_DIR}/buildroot-${BUILDROOT_VERSION}.tar.xz"
SOURCE_DIR="${PROBE_ROOT}/buildroot-${BUILDROOT_VERSION}"
URL="${BUILDROOT_DOWNLOAD_BASE}/buildroot-${BUILDROOT_VERSION}.tar.xz"

case "$BUILDROOT_VERSION" in
  2026.05.1) ;;
  *)
    echo "unsupported probe version: $BUILDROOT_VERSION" >&2
    echo "set BUILDROOT_VERSION only after recording the new upstream source" >&2
    exit 1
    ;;
esac

mkdir -p "$DOWNLOAD_DIR" "$PROBE_ROOT"

if [ ! -f "$ARCHIVE" ]; then
  curl --fail --location --retry 2 --output "$ARCHIVE" "$URL"
fi

if [ -e "$SOURCE_DIR" ]; then
  [ -f "$SOURCE_DIR/Makefile" ] || {
    echo "probe source path is not a Buildroot tree: $SOURCE_DIR" >&2
    exit 1
  }
else
  tar -C "$PROBE_ROOT" -xf "$ARCHIVE"
fi

printf 'Buildroot port probe source:\n'
printf '  version: %s\n' "$BUILDROOT_VERSION"
printf '  url:     %s\n' "$URL"
printf '  archive: %s\n' "$ARCHIVE"
printf '  sha256:  '
sha256sum "$ARCHIVE" | awk '{print $1}'
printf '  source:  %s\n' "$SOURCE_DIR"
