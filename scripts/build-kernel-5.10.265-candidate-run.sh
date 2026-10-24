#!/usr/bin/env bash
# The candidate run of the kernel 5.10.265 pipeline (kernel -> modules ->
# runtime -> rootfs -> boot.itb -> recovery SD) for the first fixing release
# after RC12, in the style of build-kernel-5.10.265-rc12-run.sh.
#
# Pinned here, because the remediation goal fixes them: the accepted RC12
# kernel fragment (by hash), kernel release 5.10.265-tag- (no kernel upgrade
# is coupled with the first fixing release), the production update key, and
# the refreshed Buildroot security source (OpenSSL 3.6.5, OpenSSH 10.6p1,
# expat 2.9.0, curl 8.23.0, wpa_supplicant 2.12, hostapd 2.12 without 11be).
# Taken from the environment, and refused when absent, because the owner
# decides them: the system and application versions, the SHA-256 of the
# accepted application stage's server binary, the stage itself, the run root.
#
# Required:
#   EXPECTED_SYSTEM_VERSION        the new system version (0.3.0-raw.N; a published one is refused)
#   EXPECTED_KVMAPP_VERSION        the new application version (2.0.N; a published one is refused);
#                                  must equal <stage>/version
#   EXPECTED_KVMAPP_SERVER_SHA256  SHA-256 of <stage>/server/NanoKVM-Server from the accepted G2 run
#   NANOKVM_KVMAPP_SOURCE_DIR      the accepted application stage directory
#   KERNEL_5_10_265_REPRO_ROOT     a new absolute run root; G5 needs two independent runs
# Optional:
#   EXPECTED_SECURITY_PATCH_LEVEL  bundle label without ';' (metadata regex); default below
#   LATEST_BUILDROOT_SOURCE_DIR    default: the refreshed tree that
#                                  prepare-buildroot-2026.05.1-security-source.sh produces
#
# The run itself is scripts/build-kernel-5.10.265-repro-run.sh, which also
# refuses a dirty worktree and an existing run root. Nothing here signs or
# publishes anything.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
FRAGMENT="$ROOT_DIR/support/sg2002/kernel/5.10.265/configs/phase3-04-init-on-alloc.config"
FRAGMENT_SHA256=13c9fede1fdc4cfe59d1b6f2f90d4ae28d0b7e32876c9145b9999bb09816f750
SOURCE_DIR="${LATEST_BUILDROOT_SOURCE_DIR:-$ROOT_DIR/build/latestbuildroot/buildroot-2026.05.1-raw11-security-r2}"
EXPECTED_SECURITY_PATCH_LEVEL="${EXPECTED_SECURITY_PATCH_LEVEL:-Buildroot 2026.05.1 security maintenance Linux 5.10.265 SG2002 vendor port}"

refuse() {
	echo "candidate run: $*" >&2
	exit 1
}
for name in EXPECTED_SYSTEM_VERSION EXPECTED_KVMAPP_VERSION EXPECTED_KVMAPP_SERVER_SHA256 \
	NANOKVM_KVMAPP_SOURCE_DIR KERNEL_5_10_265_REPRO_ROOT; do
	[ -n "${!name:-}" ] || refuse "$name is required (an owner decision, not a default)"
done
[[ "$EXPECTED_SYSTEM_VERSION" =~ ^0\.3\.0-raw\.[0-9]+$ ]] || refuse "EXPECTED_SYSTEM_VERSION must look like 0.3.0-raw.N"
[[ "$EXPECTED_KVMAPP_VERSION" =~ ^2\.0\.[0-9]+$ ]] || refuse "EXPECTED_KVMAPP_VERSION must look like 2.0.N"
[[ "$EXPECTED_KVMAPP_SERVER_SHA256" =~ ^[0-9a-f]{64}$ ]] || refuse "EXPECTED_KVMAPP_SERVER_SHA256 must be 64 hex digits"
case "$EXPECTED_SYSTEM_VERSION" in
	0.3.0-raw.10|0.3.0-raw.11|0.3.0-raw.12) refuse "system $EXPECTED_SYSTEM_VERSION is already published" ;;
esac
case "$EXPECTED_KVMAPP_VERSION" in
	2.0.40|2.0.41|2.0.42) refuse "application $EXPECTED_KVMAPP_VERSION is already published" ;;
esac
case "$EXPECTED_SECURITY_PATCH_LEVEL" in
	*';'*) refuse "EXPECTED_SECURITY_PATCH_LEVEL must not contain ';'" ;;
esac
[ -f "$FRAGMENT" ] || refuse "missing accepted RC12 kernel fragment: $FRAGMENT"
[ "$(sha256sum "$FRAGMENT" | awk '{print $1}')" = "$FRAGMENT_SHA256" ] \
	|| refuse "kernel fragment $FRAGMENT does not match the accepted hash"
[ -f "$NANOKVM_KVMAPP_SOURCE_DIR/version" ] || refuse "application stage is missing its version file"
[ -f "$NANOKVM_KVMAPP_SOURCE_DIR/server/NanoKVM-Server" ] || refuse "application stage is missing NanoKVM-Server"
[ "$(cat "$NANOKVM_KVMAPP_SOURCE_DIR/version")" = "$EXPECTED_KVMAPP_VERSION" ] \
	|| refuse "application stage version does not match $EXPECTED_KVMAPP_VERSION"
[ "$(sha256sum "$NANOKVM_KVMAPP_SOURCE_DIR/server/NanoKVM-Server" | awk '{print $1}')" = "$EXPECTED_KVMAPP_SERVER_SHA256" ] \
	|| refuse "application server hash does not match the accepted artifact"
MARKER="$SOURCE_DIR/.hardened-security-backports"
[ -f "$MARKER" ] || refuse "Buildroot security source is not prepared: $SOURCE_DIR (run scripts/prepare-buildroot-2026.05.1-security-source.sh)"
for pin in buildroot=2026.05.1 openssh=10.6p1 libopenssl=3.6.5 expat=2.9.0 libcurl=8.23.0 wpa_supplicant=2.12 hostapd=2.12-no-11be; do
	grep -qx "$pin" "$MARKER" || refuse "Buildroot security source lacks $pin: $SOURCE_DIR"
done

export EXPECTED_SYSTEM_VERSION
export EXPECTED_KVMAPP_VERSION
export EXPECTED_KERNEL_RELEASE=5.10.265-tag-
export EXPECTED_SECURITY_PATCH_LEVEL
export KERNEL_5_10_265_CONFIG_FRAGMENT="$FRAGMENT"
export EXPECTED_UPDATE_KEY_ID=hardened-system-prod-2026q3
export EXPECTED_UPDATE_PUBLIC_KEY_DER_SHA256=97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75
export LATEST_BUILDROOT_SOURCE_DIR="$SOURCE_DIR"
export NANOKVM_KVMAPP_SOURCE_DIR
export KERNEL_5_10_265_REPRO_ROOT
exec "$ROOT_DIR/scripts/build-kernel-5.10.265-repro-run.sh"
