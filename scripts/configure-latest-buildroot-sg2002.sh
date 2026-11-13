#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDROOT_VERSION="${BUILDROOT_VERSION:-2026.05.1}"
PROBE_ROOT="${LATEST_BUILDROOT_PROBE_ROOT:-$ROOT/build/latestbuildroot}"
UPSTREAM_DIR="${LATEST_BUILDROOT_SOURCE_DIR:-$PROBE_ROOT/buildroot-${BUILDROOT_VERSION}-raw11-security}"
EXTERNAL_DIR="${HARDENED_SG2002_EXTERNAL_DIR:-$ROOT/buildroot-external/hardened-sg2002}"
OUTPUT_DIR="${HARDENED_SG2002_BUILDROOT_OUTPUT_DIR:-$PROBE_ROOT/sg2002-config-${BUILDROOT_VERSION}-raw11}"
DEFCONFIG="${HARDENED_SG2002_DEFCONFIG:-hardened_sg2002_licheervnano_defconfig}"

[ -f "$UPSTREAM_DIR/Makefile" ] || {
  echo "missing Buildroot probe source: $UPSTREAM_DIR" >&2
  echo "run: make latest-buildroot-security-source" >&2
  exit 1
}

[ -f "$EXTERNAL_DIR/external.desc" ] || {
  echo "missing SG2002 BR2_EXTERNAL tree: $EXTERNAL_DIR" >&2
  exit 1
}

if [ -e "$OUTPUT_DIR/.config" ]; then
  echo "refusing to overwrite existing SG2002 port config: $OUTPUT_DIR/.config" >&2
  echo "set HARDENED_SG2002_BUILDROOT_OUTPUT_DIR to a new path for another probe" >&2
  exit 1
fi

make -C "$UPSTREAM_DIR" O="$OUTPUT_DIR" BR2_EXTERNAL="$EXTERNAL_DIR" "$DEFCONFIG"
make -C "$UPSTREAM_DIR" O="$OUTPUT_DIR" \
  BR2_DEFCONFIG="$OUTPUT_DIR/defconfig" savedefconfig

printf 'SG2002 port configuration written to: %s/.config\n' "$OUTPUT_DIR"
printf 'Minimal defconfig written to: %s/defconfig\n' "$OUTPUT_DIR"
printf 'Configuration success does not authorize an image build or device flash.\n'
