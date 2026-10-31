#!/usr/bin/env bash
# The candidate run of the kernel 5.10.272 pipeline for the first fixing
# release after RC12. The accepted RC12 fragment, production key and refreshed
# Buildroot r2 source stay fixed here; the source tree, system/app versions and
# the accepted app stage are owner inputs. Nothing here signs or publishes.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$ROOT_DIR/scripts/lib/release-versions.sh"
FRAGMENT="$ROOT_DIR/support/sg2002/kernel/5.10.265/configs/phase3-05-runtime-children.config"
FRAGMENT_SHA256=82390ad4f7992a666efee6a2c0fe3e7b0ddc31a2e5c2d021990b792f6b241b3a
SOURCE_DIR="${KERNEL_5_10_272_SOURCE_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-5.10.272-v1/repo}"
EXPECTED_SOURCE_COMMIT="${EXPECTED_KERNEL_SOURCE_COMMIT:-ddef97c3d978b67f7852dca05f0b3505f798c0b2}"
EXPECTED_STABLE_PARENT="${EXPECTED_KERNEL_STABLE_PARENT:-aca95a35f1bcc0626c4fa4d1252bf2d4c990a1a2}"
RUN_ROOT="${KERNEL_5_10_272_REPRO_ROOT:-}"
SOURCE="${LATEST_BUILDROOT_SOURCE_DIR:-$ROOT_DIR/build/latestbuildroot/buildroot-2026.05.1-raw11-security-r2}"
EXPECTED_SECURITY_PATCH_LEVEL="${EXPECTED_SECURITY_PATCH_LEVEL:-Buildroot 2026.05.1 security maintenance Linux 5.10.272 SG2002 vendor port}"

refuse() {
	echo "5.10.272 candidate run: $*" >&2
	exit 1
}
for name in EXPECTED_SYSTEM_VERSION EXPECTED_KVMAPP_VERSION EXPECTED_KVMAPP_SERVER_SHA256 \
	NANOKVM_KVMAPP_SOURCE_DIR KERNEL_5_10_272_REPRO_ROOT; do
	[ -n "${!name:-}" ] || refuse "$name is required (an owner decision, not a default)"
done
release_check_versions "$EXPECTED_SYSTEM_VERSION" "$EXPECTED_KVMAPP_VERSION" || exit 1
[[ "$EXPECTED_KVMAPP_SERVER_SHA256" =~ ^[0-9a-f]{64}$ ]] || refuse "EXPECTED_KVMAPP_SERVER_SHA256 must be 64 hex digits"
case "$EXPECTED_SECURITY_PATCH_LEVEL" in
	*';'*) refuse "EXPECTED_SECURITY_PATCH_LEVEL must not contain ';'" ;;
esac
[ -d "$SOURCE_DIR" ] || refuse "kernel source tree does not exist: $SOURCE_DIR"
[ -f "$FRAGMENT" ] || refuse "missing accepted RC12 kernel fragment: $FRAGMENT"
[ "$(sha256sum "$FRAGMENT" | awk '{print $1}')" = "$FRAGMENT_SHA256" ] \
	|| refuse "kernel fragment $FRAGMENT does not match the accepted hash"
[ -f "$NANOKVM_KVMAPP_SOURCE_DIR/version" ] || refuse "application stage is missing its version file"
[ -f "$NANOKVM_KVMAPP_SOURCE_DIR/server/NanoKVM-Server" ] || refuse "application stage is missing NanoKVM-Server"
[ "$(cat "$NANOKVM_KVMAPP_SOURCE_DIR/version")" = "$EXPECTED_KVMAPP_VERSION" ] \
	|| refuse "application stage version does not match $EXPECTED_KVMAPP_VERSION"
[ "$(sha256sum "$NANOKVM_KVMAPP_SOURCE_DIR/server/NanoKVM-Server" | awk '{print $1}')" = "$EXPECTED_KVMAPP_SERVER_SHA256" ] \
	|| refuse "application server hash does not match the accepted artifact"
[ -z "$(git -C "$SOURCE_DIR" status --short)" ] || refuse "kernel source tree is dirty"
[ "$(git -C "$SOURCE_DIR" rev-parse HEAD)" = "$EXPECTED_SOURCE_COMMIT" ] \
	|| refuse "kernel source HEAD does not match the pinned merge commit"
MERGE="$(git -C "$SOURCE_DIR" rev-list --merges --first-parent -n1 HEAD)"
[ -n "$MERGE" ] || refuse "kernel source has no merge commit"
[ "$(git -C "$SOURCE_DIR" rev-parse "$MERGE^2")" = "$EXPECTED_STABLE_PARENT" ] \
	|| refuse "kernel stable parent does not match the signed v5.10.272 commit"
MARKER="$SOURCE/.hardened-security-backports"
[ -f "$MARKER" ] || refuse "Buildroot security source is not prepared: $SOURCE"
for pin in buildroot=2026.05.1 openssh=10.6p1 libopenssl=3.6.5 expat=2.9.0 libcurl=8.23.0 wpa_supplicant=2.12 hostapd=2.12-no-11be; do
	grep -qx "$pin" "$MARKER" || refuse "Buildroot security source lacks $pin: $SOURCE"
done

export EXPECTED_SYSTEM_VERSION
export EXPECTED_KVMAPP_VERSION
export EXPECTED_KERNEL_RELEASE=5.10.272-tag-
export EXPECTED_SECURITY_PATCH_LEVEL
export KERNEL_5_10_265_CONFIG_FRAGMENT="$FRAGMENT"
export KERNEL_5_10_265_REQUIRE_PROC_CHILDREN=1
export KERNEL_5_10_265_SOURCE_DIR="$SOURCE_DIR"
export EXPECTED_UPDATE_KEY_ID=hardened-system-prod-2026q3
export EXPECTED_UPDATE_PUBLIC_KEY_DER_SHA256=97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75
export LATEST_BUILDROOT_SOURCE_DIR="$SOURCE"
export NANOKVM_KVMAPP_SOURCE_DIR
export KERNEL_5_10_265_REPRO_ROOT="$RUN_ROOT"
exec "$ROOT_DIR/scripts/build-kernel-5.10.265-repro-run.sh"
