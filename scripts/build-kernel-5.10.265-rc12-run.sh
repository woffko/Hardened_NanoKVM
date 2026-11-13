#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
EXPECTED_SYSTEM_VERSION="${EXPECTED_SYSTEM_VERSION:-0.3.0-raw.12}"
EXPECTED_KVMAPP_VERSION="${EXPECTED_KVMAPP_VERSION:-2.0.42}"
EXPECTED_KERNEL_RELEASE="${EXPECTED_KERNEL_RELEASE:-5.10.265-tag-}"
EXPECTED_SECURITY_PATCH_LEVEL="${EXPECTED_SECURITY_PATCH_LEVEL:-Buildroot 2026.05.1 security maintenance Linux 5.10.265 SG2002 vendor port}"
KERNEL_5_10_265_CONFIG_FRAGMENT="${KERNEL_5_10_265_CONFIG_FRAGMENT:-$ROOT_DIR/support/sg2002/kernel/5.10.265/configs/phase3-04-init-on-alloc.config}"
EXPECTED_KVMAPP_SERVER_SHA256="${EXPECTED_KVMAPP_SERVER_SHA256:-fd116fc459a1961cfc16fd0c7077a8f4c5e24d8f32d8745fd3b9744217083d6d}"

[ -f "$KERNEL_5_10_265_CONFIG_FRAGMENT" ] || {
	echo "missing accepted RC12 kernel fragment: $KERNEL_5_10_265_CONFIG_FRAGMENT" >&2
	exit 1
}
[ -n "${NANOKVM_KVMAPP_SOURCE_DIR:-}" ] || {
	echo "RC12 build requires explicit NANOKVM_KVMAPP_SOURCE_DIR" >&2
	exit 1
}
[ -f "$NANOKVM_KVMAPP_SOURCE_DIR/version" ] || {
	echo "RC12 bridge stage is missing its version file" >&2
	exit 1
}
[ -f "$NANOKVM_KVMAPP_SOURCE_DIR/server/NanoKVM-Server" ] || {
	echo "RC12 bridge stage is missing NanoKVM-Server" >&2
	exit 1
}
[ "$EXPECTED_SYSTEM_VERSION" = 0.3.0-raw.12 ] || {
	echo "RC12 build requires system 0.3.0-raw.12" >&2
	exit 1
}
[ "$EXPECTED_KVMAPP_VERSION" = 2.0.42 ] || {
	echo "RC12 build requires bridge application 2.0.42" >&2
	exit 1
}
[ "$EXPECTED_KERNEL_RELEASE" = 5.10.265-tag- ] || {
	echo "RC12 build requires kernel 5.10.265-tag-" >&2
	exit 1
}
[ "$(cat "$NANOKVM_KVMAPP_SOURCE_DIR/version")" = "$EXPECTED_KVMAPP_VERSION" ] || {
	echo "RC12 bridge stage version does not match $EXPECTED_KVMAPP_VERSION" >&2
	exit 1
}
[ "$(sha256sum "$NANOKVM_KVMAPP_SOURCE_DIR/server/NanoKVM-Server" | awk '{print $1}')" = "$EXPECTED_KVMAPP_SERVER_SHA256" ] || {
	echo "RC12 bridge server hash does not match the accepted artifact" >&2
	exit 1
}

export EXPECTED_SYSTEM_VERSION
export EXPECTED_KVMAPP_VERSION
export EXPECTED_KERNEL_RELEASE
export EXPECTED_SECURITY_PATCH_LEVEL
export KERNEL_5_10_265_CONFIG_FRAGMENT
export EXPECTED_UPDATE_KEY_ID=hardened-system-prod-2026q3
# RC12 shipped the bridge trust set; later releases trust the release key alone.
export EXPECTED_UPDATE_KEY_POLICY='hardened-system-dev hardened-system-test hardened-system-prod-2026q3'
export EXPECTED_UPDATE_PUBLIC_KEY_DER_SHA256=97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75
export NANOKVM_KVMAPP_SOURCE_DIR
exec "$ROOT_DIR/scripts/build-kernel-5.10.265-repro-run.sh"
