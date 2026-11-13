#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDROOT_VERSION="${BUILDROOT_VERSION:-2026.05.1}"
PROBE_ROOT="${LATEST_BUILDROOT_PROBE_ROOT:-$ROOT/build/latestbuildroot}"
UPSTREAM_DIR="${LATEST_BUILDROOT_SOURCE_DIR:-$PROBE_ROOT/buildroot-${BUILDROOT_VERSION}}"
LEGACY_SDK_DIR="${LICHEERV_NANO_SDK_DIR:-$ROOT/build/vendor/LicheeRV-Nano-Build}"
LEGACY_CONFIG="${LICHEERV_NANO_BUILDROOT_CONFIG:-$LEGACY_SDK_DIR/buildroot/.config}"
OUTPUT_DIR="${LATEST_BUILDROOT_OUTPUT_DIR:-$PROBE_ROOT/config-probe-${BUILDROOT_VERSION}}"

[ -f "$UPSTREAM_DIR/Makefile" ] || {
  echo "missing Buildroot probe source: $UPSTREAM_DIR" >&2
  echo "run: make latest-buildroot-bootstrap" >&2
  exit 1
}

[ -f "$LEGACY_CONFIG" ] || {
  echo "missing legacy vendor Buildroot config: $LEGACY_CONFIG" >&2
  exit 1
}

if [ -e "$OUTPUT_DIR/.config" ]; then
  echo "refusing to overwrite existing probe config: $OUTPUT_DIR/.config" >&2
  echo "set LATEST_BUILDROOT_OUTPUT_DIR to a new path for another probe" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
cp "$LEGACY_CONFIG" "$OUTPUT_DIR/.config"

make -C "$UPSTREAM_DIR" O="$OUTPUT_DIR" olddefconfig

if grep -qx 'BR2_LEGACY=y' "$OUTPUT_DIR/.config"; then
  echo "legacy options need an explicit porting decision before a defconfig can be saved:" >&2
  awk '
    FNR == NR {
      if ($1 == "config") symbol = $2
      if ($1 == "select" && $2 == "BR2_LEGACY") legacy[symbol] = 1
      next
    }
    /^[A-Z0-9_]+=y$/ {
      split($0, fields, "=")
      if (legacy[fields[1]]) print "  " fields[1]
    }
  ' "$UPSTREAM_DIR/Config.in.legacy" "$OUTPUT_DIR/.config" >&2
  echo "the converted .config is retained at: $OUTPUT_DIR/.config" >&2
  exit 2
fi

make -C "$UPSTREAM_DIR" O="$OUTPUT_DIR" savedefconfig

printf 'Converted config written to: %s/.config\n' "$OUTPUT_DIR"
printf 'Minimal converted defconfig: %s/defconfig\n' "$OUTPUT_DIR"
printf 'This is a Kconfig compatibility probe only; it does not build or flash an image.\n'
