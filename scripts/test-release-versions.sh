#!/usr/bin/env bash
# The version rules of scripts/lib/release-versions.sh and their use by the
# candidate wrappers and the raw packager. No build starts: every case stops at
# the version check, or at the first check after it for an accepted pair.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$ROOT_DIR/scripts/lib/release-versions.sh"

fail() {
	echo "release versions test: $*" >&2
	exit 1
}
accepted() {
	release_check_versions "$1" "$2" 2>/dev/null || fail "$1 with $2 was refused"
}
refused() {
	if release_check_versions "$1" "$2" 2>/dev/null; then
		fail "$1 with $2 was accepted"
	fi
}

accepted 0.3.0-raw.14 2.0.45
accepted 0.3.0-raw.99 2.0.60
accepted 0.4.0-raw.1 2.1.0
accepted 0.4.0-raw.2 2.1.1

# Published numbers and numbers burned by test builds.
for system in 0.3.0-raw.10 0.3.0-raw.11 0.3.0-raw.12 0.3.0-raw.13; do refused "$system" 2.0.45; done
for app in 2.0.40 2.0.41 2.0.42 2.0.43 2.0.44; do refused 0.3.0-raw.14 "$app"; done
# Below the debug range, or not a known family.
refused 0.3.0-raw.9 2.0.45
refused 0.3.0-raw.14 2.0.39
refused 0.5.0-raw.1 2.1.0
refused 0.4.0-raw.1 2.2.0
refused 0.4.0-raw.0 2.1.0
# A debug system never pairs with a release application, or the reverse.
refused 0.3.0-raw.14 2.1.0
refused 0.4.0-raw.1 2.0.45
# Not versions at all.
refused 0.4.0-raw.1x 2.1.0
refused 0.4.0-raw.1 2.1.0-rc1
refused "" ""

# The list is read, not a copy of it.
RELEASE_BURNED_VERSIONS="$(mktemp)"
trap 'rm -f "$RELEASE_BURNED_VERSIONS"' EXIT
printf '2.1.0\n' > "$RELEASE_BURNED_VERSIONS"
refused 0.4.0-raw.1 2.1.0
accepted 0.4.0-raw.2 2.1.1
RELEASE_BURNED_VERSIONS=/nonexistent/list
if release_check_versions 0.4.0-raw.2 2.1.1 2>/dev/null; then
	echo "a list that cannot be read must refuse every number" >&2
	exit 1
fi
unset RELEASE_BURNED_VERSIONS

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
wrapper_refuses() {
	local script=$1 system=$2 app=$3 expected=$4 output
	if output="$(EXPECTED_SYSTEM_VERSION="$system" EXPECTED_KVMAPP_VERSION="$app" \
		EXPECTED_KVMAPP_SERVER_SHA256="$(printf '0%.0s' $(seq 64))" \
		NANOKVM_KVMAPP_SOURCE_DIR="$stage" KERNEL_5_10_265_REPRO_ROOT="$stage/run" \
		KERNEL_5_10_272_REPRO_ROOT="$stage/run" bash "$ROOT_DIR/scripts/$script" 2>&1)"; then
		fail "$script accepted $system with $app"
	fi
	case "$output" in
	*"$expected"*) ;;
	*) fail "$script gave another refusal for $system with $app: $output" ;;
	esac
}
for script in build-kernel-5.10.272-candidate-run.sh build-kernel-5.10.265-candidate-run.sh; do
	wrapper_refuses "$script" 0.3.0-raw.13 2.0.44 "already used"
	wrapper_refuses "$script" 0.4.0-raw.1 2.0.45 "debug number"
done

packager_refuses() {
	local expected=$1 output
	shift
	if output="$(env "$@" bash "$ROOT_DIR/scripts/package-latest-buildroot-sg2002-raw-update.sh" 2>&1)"; then
		fail "the packager accepted: $*"
	fi
	case "$output" in
	*"$expected"*) ;;
	*) fail "the packager gave another refusal for $*: $output" ;;
	esac
}
packager_refuses "HARDENED_SG2002_SYSTEM_VERSION is required" \
	HARDENED_SG2002_SYSTEM_VERSION= EXPECTED_KVMAPP_VERSION=2.1.0 SYSTEM_UPDATE_REQUIRED_APP_VERSION=2.1.0
packager_refuses "is for 0.3.0-raw.12" HARDENED_LEGACY_RC12=1 \
	HARDENED_SG2002_SYSTEM_VERSION=0.3.0-raw.13 EXPECTED_KVMAPP_VERSION=2.0.45 SYSTEM_UPDATE_REQUIRED_APP_VERSION=2.0.45
packager_refuses "EXPECTED_KVMAPP_VERSION is required" \
	HARDENED_SG2002_SYSTEM_VERSION=0.4.0-raw.1 EXPECTED_KVMAPP_VERSION= SYSTEM_UPDATE_REQUIRED_APP_VERSION=2.1.0
packager_refuses "SYSTEM_UPDATE_REQUIRED_APP_VERSION is required" \
	HARDENED_SG2002_SYSTEM_VERSION=0.4.0-raw.1 EXPECTED_KVMAPP_VERSION=2.1.0 SYSTEM_UPDATE_REQUIRED_APP_VERSION=
packager_refuses "already used" \
	HARDENED_SG2002_SYSTEM_VERSION=0.3.0-raw.13 EXPECTED_KVMAPP_VERSION=2.0.45 SYSTEM_UPDATE_REQUIRED_APP_VERSION=2.0.45

echo "release versions test: PASS"
