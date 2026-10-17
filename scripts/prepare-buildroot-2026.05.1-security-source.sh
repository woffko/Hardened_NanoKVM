#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT/scripts/lib/build-security.sh"
VERSION=2026.05.1
ARCHIVE="${BUILDROOT_ARCHIVE:-$ROOT/build/downloads/buildroot-${VERSION}.tar.xz}"
PROBE_ROOT="${LATEST_BUILDROOT_PROBE_ROOT:-$ROOT/build/latestbuildroot}"
OUTPUT_DIR="${LATEST_BUILDROOT_SECURITY_SOURCE_DIR:-$PROBE_ROOT/buildroot-${VERSION}-raw11-security}"
PATCH_DIR="$ROOT/buildroot-external/hardened-sg2002/buildroot-patches/${VERSION}"
SHARED_DL_DIR="${BUILDROOT_SECURITY_DL_DIR:-$PROBE_ROOT/buildroot-${VERSION}/dl}"
EXPECTED_ARCHIVE_SHA256=ae7f706f087b9ae9083a10a587368dfbf53103c28bf81c2d690198dc4090cb58

verify_sha256() {
	path=$1
	expected=$2
	label=$3
	[ -f "$path" ] || {
		echo "missing $label: $path" >&2
		exit 1
	}
	actual="$(sha256sum "$path" | awk '{print $1}')"
	[ "$actual" = "$expected" ] || {
		echo "$label sha256 mismatch: expected $expected, got $actual" >&2
		exit 1
	}
}

verify_sha256 "$ARCHIVE" "$EXPECTED_ARCHIVE_SHA256" "Buildroot archive"
verify_sha256 "$PATCH_DIR/0001-openssh-10.5p1.patch" \
	a5c0253ae9ec1c6e422442aa920fd0ff876ca778d1f5e4201f93365740a98a18 \
	"OpenSSH Buildroot patch"
verify_sha256 "$PATCH_DIR/0002-hostapd-2.12-minimal.patch" \
	ca5e3458ab7a641d26354b7461e4d1a35a7bc23bb3ef61362dc75b2e7097b29b \
	"hostapd Buildroot patch"
verify_sha256 "$PATCH_DIR/0003-hostapd-disable-11be.patch" \
	52caa5ffca51d8406c2896857c519667f1a7acec587b53f332298cef57be2ade \
	"hostapd 11be removal patch"

if [ -e "$OUTPUT_DIR" ]; then
	[ -f "$OUTPUT_DIR/.hardened-security-backports" ] || {
		echo "refusing unknown existing security source: $OUTPUT_DIR" >&2
		exit 1
	}
	grep -qx 'buildroot=2026.05.1' "$OUTPUT_DIR/.hardened-security-backports"
	grep -qx 'openssh=10.5p1' "$OUTPUT_DIR/.hardened-security-backports"
	grep -qx 'hostapd=2.12-no-11be' "$OUTPUT_DIR/.hardened-security-backports"
	for patch_file in "$PATCH_DIR"/*.patch; do
		grep -Fqx "$(sha256sum "$patch_file")" "$OUTPUT_DIR/.hardened-security-backports" || {
			echo "existing security source was prepared with a different patch series" >&2
			exit 1
		}
	done
	build_verify_security_recipes "$OUTPUT_DIR" || exit 1
	printf 'Buildroot security source already prepared: %s\n' "$OUTPUT_DIR"
	exit 0
fi

mkdir -p "$PROBE_ROOT"
WORK="$(mktemp -d "$PROBE_ROOT/.buildroot-${VERSION}-security.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM
tar -C "$WORK" -xf "$ARCHIVE"
SOURCE="$WORK/buildroot-${VERSION}"

verify_sha256 "$SOURCE/package/openssh/openssh.mk" \
	a679015bfc0d90e665c6d9955552a9283d84884df21342bb31f0cf7ed5ec16d2 \
	"upstream OpenSSH recipe"
verify_sha256 "$SOURCE/package/openssh/openssh.hash" \
	0d8429fe8a6446ed5e0417e77ea09ec471a784702d4743e632460904d0013487 \
	"upstream OpenSSH hash"
verify_sha256 "$SOURCE/package/hostapd/hostapd.mk" \
	d9cef193170ca7f06f5365617511fcb39c1257d0b4643443275ff975d3c07c05 \
	"upstream hostapd recipe"
verify_sha256 "$SOURCE/package/hostapd/hostapd.hash" \
	425801c2ca3ee777162394dcb87a32336a468c44974eaca9707c335029fb4bb0 \
	"upstream hostapd hash"
verify_sha256 "$SOURCE/package/hostapd/0001-RADIUS-Drop-pending-request-only-when-accepting-the-response.patch" \
	3d27e7efacdcdb84a3ba1ce1c56d24e4c26bef49b78d17efa4b0024f9a04ec54 \
	"obsolete hostapd patch 1"
verify_sha256 "$SOURCE/package/hostapd/0002-RADIUS-Fix-pending-request-dropping.patch" \
	77c86463807cda922ed4da9762391f14fc3648454d01d358f743158e0687b1dc \
	"obsolete hostapd patch 2"

for patch_file in "$PATCH_DIR"/*.patch; do
	patch -d "$SOURCE" -p1 --forward --batch -F 0 -i "$patch_file"
done
rm -f \
	"$SOURCE/package/hostapd/0001-RADIUS-Drop-pending-request-only-when-accepting-the-response.patch" \
	"$SOURCE/package/hostapd/0002-RADIUS-Fix-pending-request-dropping.patch"

build_verify_security_recipes "$SOURCE" || exit 1

if [ -e "$SOURCE/dl" ]; then
	echo "unexpected dl entry in pristine Buildroot source" >&2
	exit 1
fi
[ -d "$SHARED_DL_DIR" ] || {
	echo "shared Buildroot download directory is missing: $SHARED_DL_DIR" >&2
	exit 1
}
ln -s "$SHARED_DL_DIR" "$SOURCE/dl"

{
	printf 'buildroot=2026.05.1\n'
	printf 'archive_sha256=%s\n' "$EXPECTED_ARCHIVE_SHA256"
	printf 'openssh=10.5p1\n'
	printf 'hostapd=2.12-no-11be\n'
	sha256sum "$PATCH_DIR"/*.patch
} > "$SOURCE/.hardened-security-backports"

mv "$SOURCE" "$OUTPUT_DIR"
printf 'Prepared Buildroot security source: %s\n' "$OUTPUT_DIR"
