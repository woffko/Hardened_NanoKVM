#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDROOT_VERSION="${BUILDROOT_VERSION:-2026.05.1}"
UPSTREAM_DIR="${LATEST_BUILDROOT_SOURCE_DIR:-$ROOT/build/latestbuildroot/buildroot-${BUILDROOT_VERSION}-raw11-security}"
OUTPUT_DIR="${HARDENED_SG2002_BUILDROOT_OUTPUT_DIR:-$ROOT/build/latestbuildroot/sg2002-config-${BUILDROOT_VERSION}-raw11}"
HOST_DEPS_ROOT="${BUILDROOT_PORT_HOST_DEPS:-$ROOT/build/host-deps}"
USER_HOME="${HOME:-/home/w0w}"
CLEAN_PATH="$HOST_DEPS_ROOT/usr/sbin:$HOST_DEPS_ROOT/usr/bin:$USER_HOME/.local/bin:$USER_HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

env -i \
	HOME="$USER_HOME" \
	USER="${USER:-$(id -un)}" \
	LOGNAME="${LOGNAME:-${USER:-$(id -un)}}" \
	SHELL=/bin/bash \
	PATH="$CLEAN_PATH" \
	make -C "$UPSTREAM_DIR" O="$OUTPUT_DIR" hardened-nanokvm-kvmapp-dirclean

HARDENED_SG2002_SYSTEM_VERSION="${HARDENED_SG2002_SYSTEM_VERSION:-0.3.0-raw.11}" \
HARDENED_SG2002_BUILDROOT_OUTPUT_DIR="$OUTPUT_DIR" \
NANOKVM_VENDOR_RUNTIME_SOURCE_DIR="${NANOKVM_VENDOR_RUNTIME_SOURCE_DIR:-$ROOT/build/latestbuildroot/vendor-runtime-source-media-v1}" \
NANOKVM_KVMAPP_SOURCE_DIR="${NANOKVM_KVMAPP_SOURCE_DIR:-$ROOT/build/kvmapp-rust/kvmapp}" \
	"$ROOT/scripts/build-latest-buildroot-replacement-rootfs.sh"
