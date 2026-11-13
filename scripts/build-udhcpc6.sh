#!/usr/bin/env bash
# Build the bundled /kvmapp/system/bin/udhcpc6: BusyBox 1.38.0 from the pinned
# tarball, the Buildroot and board patches in order, one static applet (the
# DHCPv6 client), the Buildroot musl toolchain. The result is reproducible:
# the same inputs give the same bytes, and the script prints their hashes.
#
#   scripts/build-udhcpc6.sh [out dir]
#
# Environment (defaults are the local Buildroot trees):
#   BUSYBOX_TARBALL   busybox-1.38.0.tar.bz2 (its SHA-256 is checked)
#   BUILDROOT_TREE    the Buildroot tree whose package/busybox patches apply
#   TOOLCHAIN_PREFIX  riscv64-buildroot-linux-musl- with its directory
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT_DIR/build/udhcpc6}
LATEST=$ROOT_DIR/build/latestbuildroot
TARBALL=${BUSYBOX_TARBALL:-$LATEST/buildroot-2026.05.1/dl/busybox/busybox-1.38.0.tar.bz2}
BUILDROOT=${BUILDROOT_TREE:-$LATEST/buildroot-2026.05.1-raw11-security}
PREFIX=${TOOLCHAIN_PREFIX:-$LATEST/sg2002-config-2026.05.1-raw11-repro6/host/bin/riscv64-buildroot-linux-musl-}
FRAGMENT=$ROOT_DIR/buildroot-external/hardened-sg2002/board/sg2002/udhcpc6.fragment
BOARD_PATCHES=$ROOT_DIR/buildroot-external/hardened-sg2002/board/sg2002/patches/busybox/1.38.0
TARBALL_SHA256=34f9ea6ff8636f2c9241153b9114eefa9e65674a45318ae1ef95bb5f31c53bb2

fail() { echo "build-udhcpc6: $*" >&2; exit 1; }
[ -f "$TARBALL" ] || fail "tarball not found: $TARBALL"
[ -x "${PREFIX}gcc" ] || fail "toolchain not found: ${PREFIX}gcc"
[ -f "$FRAGMENT" ] || fail "fragment not found: $FRAGMENT"
echo "$TARBALL_SHA256  $TARBALL" | sha256sum -c --quiet - || fail "tarball hash mismatch"
# The Buildroot package patches, then the board patches, each set in name order.
patches=()
for patch in "$BUILDROOT"/package/busybox/0*.patch "$BOARD_PATCHES"/0*.patch; do
  [ -f "$patch" ] || fail "no patches under $(dirname "$patch")"
  patches+=("$patch")
done
mkdir -p "$OUT"
WORK=$OUT/src
rm -rf "$WORK"; mkdir -p "$WORK"
tar -xjf "$TARBALL" -C "$WORK" --strip-components=1
for patch in "${patches[@]}"; do
  patch -s -p1 -d "$WORK" < "$patch"
done
echo "patches applied: ${#patches[@]}"
# BusyBox's kconfig keeps the FIRST assignment of a symbol, so each fragment
# symbol replaces its line in the all-no config; oldconfig settles the rest
# (yes may die of SIGPIPE once make exits: harmless).
make -C "$WORK" -s allnoconfig >/dev/null
while IFS= read -r line; do
  case "$line" in
    '# CONFIG_'*' is not set') sym=${line#\# }; sym=${sym%% *} ;;
    ''|'#'*) continue ;;
    *) sym=${line%%=*} ;;
  esac
  sed -i "/^$sym=/d;/^# $sym is not set\$/d" "$WORK/.config"
  printf '%s\n' "$line" >> "$WORK/.config"
done < "$FRAGMENT"
( yes '' || true ) | make -C "$WORK" -s oldconfig >/dev/null
lost=0
while IFS= read -r line; do
  case "$line" in
    CONFIG_*=*) grep -qxF "$line" "$WORK/.config" || { echo "config lost $line" >&2; lost=1; } ;;
  esac
done < "$FRAGMENT"
[ "$lost" = 0 ] || fail "the fragment did not survive oldconfig"
make -C "$WORK" -s CROSS_COMPILE="$PREFIX" -j"$(nproc)" >/dev/null 2>"$OUT/build-warnings.log"
cp "$WORK/busybox" "$OUT/udhcpc6"
cp "$WORK/.config" "$OUT/udhcpc6.config"
{
  sha256sum "$TARBALL" "$FRAGMENT" "${patches[@]}"
  "${PREFIX}gcc" --version | head -1
} > "$OUT/inputs.sha256"
echo "== result"
file "$OUT/udhcpc6"
sha256sum "$OUT/udhcpc6"
bash "$ROOT_DIR/scripts/test-udhcpc6-binary.sh" "$OUT/udhcpc6"
