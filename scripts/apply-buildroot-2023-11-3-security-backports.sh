#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_DIR="${LICHEERV_NANO_SDK_DIR:-$ROOT/build/vendor/LicheeRV-Nano-Build}"
UPSTREAM_BUILDROOT="${BUILDROOT_UPSTREAM_REPO:-/tmp/buildroot-security-probe}"
BASE_REF="${BUILDROOT_BACKPORT_BASE_REF:-2023.11.2}"
TARGET_REF="${BUILDROOT_BACKPORT_TARGET_REF:-2023.11.3}"
PATCH_OUT="${BUILDROOT_BACKPORT_PATCH:-$ROOT/build/buildroot-2023.11.2-to-2023.11.3-security.patch}"

PACKAGES=(
  package/libopenssl
  package/libcurl
  package/python3
  package/expat
  package/libxml2
)

die() {
  echo "error: $*" >&2
  exit 1
}

[ -d "$SDK_DIR/.git" ] || die "missing SDK git checkout: $SDK_DIR"
[ -d "$SDK_DIR/buildroot" ] || die "missing SDK buildroot directory: $SDK_DIR/buildroot"
[ -d "$UPSTREAM_BUILDROOT/.git" ] || die "missing upstream Buildroot git checkout: $UPSTREAM_BUILDROOT"

if [ -n "$(git -C "$SDK_DIR" status --porcelain -- buildroot/package/libopenssl buildroot/package/libcurl buildroot/package/python3 buildroot/package/expat buildroot/package/libxml2)" ]; then
  die "refusing to apply over dirty Buildroot package backport paths in $SDK_DIR"
fi

mkdir -p "$(dirname "$PATCH_OUT")"
git -C "$UPSTREAM_BUILDROOT" diff --output "$PATCH_OUT" "$BASE_REF" "$TARGET_REF" -- "${PACKAGES[@]}"

if [ ! -s "$PATCH_OUT" ]; then
  die "empty backport patch: $PATCH_OUT"
fi

git -C "$SDK_DIR" apply --check --directory=buildroot "$PATCH_OUT"
git -C "$SDK_DIR" apply --directory=buildroot "$PATCH_OUT"

echo "Applied Buildroot package backports:"
echo "  upstream: $UPSTREAM_BUILDROOT"
echo "  range:    $BASE_REF..$TARGET_REF"
echo "  sdk:      $SDK_DIR"
echo "  patch:    $PATCH_OUT"
