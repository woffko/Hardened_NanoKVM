#!/usr/bin/env bash
# Release gate for one signed raw system update bundle, against the values of
# the accepted candidate. Every expectation is required; there is no unsigned
# mode. verify-rc12-raw-bundle.sh stays the fixed historical RC12 check.
#
# Required environment: RAW_VERSION RAW_REQUIRED_APP_VERSION
# RAW_MINIMUM_SYSTEM_VERSION RAW_KERNEL_VERSION
# RAW_SOURCE_COMMIT (short) RAW_REQUIRED_OPERATION RAW_ROOTFS_SHA256
# RAW_ROOTFS_SIZE RAW_BOOT_SHA256 RAW_BOOT_SIZE. Optional: RAW_KEY_ID
# (hardened-system-prod-2026q3), RAW_TARGET (sg2002-licheervnano-sd),
# RAW_CHANNEL (preview).
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
KEY_ID="${RAW_KEY_ID:-hardened-system-prod-2026q3}"
TARGET="${RAW_TARGET:-sg2002-licheervnano-sd}"
CHANNEL="${RAW_CHANNEL:-preview}"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

[ "$#" -eq 4 ] || {
	echo "usage: $0 <archive.tar.gz> <system-latest.json> <signature> <public-key>" >&2
	exit 2
}
ARCHIVE="$(readlink -f "$1")"
METADATA="$(readlink -f "$2")"
SIGNATURE="$3"
PUBLIC_KEY="$4"

for name in RAW_VERSION RAW_REQUIRED_APP_VERSION RAW_MINIMUM_SYSTEM_VERSION RAW_KERNEL_VERSION RAW_SOURCE_COMMIT \
	RAW_REQUIRED_OPERATION RAW_ROOTFS_SHA256 RAW_ROOTFS_SIZE RAW_BOOT_SHA256 RAW_BOOT_SIZE
do
	[ -n "${!name:-}" ] || fail "$name is required"
done
for command in cmp gzip jq openssl readlink sha256sum tar wc
do
	command -v "$command" >/dev/null 2>&1 || fail "missing command: $command"
done
for path in "$ARCHIVE" "$METADATA" "$SIGNATURE" "$PUBLIC_KEY"
do
	[ -f "$path" ] || fail "missing file: $path"
done
[ "$(basename "$ARCHIVE")" = "hardened-nanokvm-system-$RAW_VERSION.tar.gz" ] || \
	fail "unexpected archive name"

# Authenticate the exact metadata bytes before reading any payload.
[ "$(jq -r .signature_algorithm "$METADATA")" = sha256-rsa-pkcs1-v1_5 ] || fail "signature algorithm"
[ "$(jq -r .signature_key_id "$METADATA")" = "$KEY_ID" ] || fail "signature key id"
"$ROOT_DIR/scripts/verify-system-update-metadata.sh" \
	"$METADATA" "$SIGNATURE" "$PUBLIC_KEY" >/dev/null || fail "metadata signature"

archive_sha="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
archive_size="$(wc -c < "$ARCHIVE" | tr -d ' ')"
[ "$(jq -r .format "$METADATA")" = 2 ] || fail "metadata format"
[ "$(jq -r .channel "$METADATA")" = "$CHANNEL" ] || fail "metadata channel"
[ "$(jq -r .version "$METADATA")" = "$RAW_VERSION" ] || fail "metadata version"
[ "$(jq -r .target "$METADATA")" = "$TARGET" ] || fail "metadata target"
[ "$(jq -r .required_app_version "$METADATA")" = "$RAW_REQUIRED_APP_VERSION" ] || \
	fail "metadata app requirement"
[ "$(jq -r .minimum_system_version "$METADATA")" = "$RAW_MINIMUM_SYSTEM_VERSION" ] || \
	fail "metadata system requirement"
[ "$(jq -r .sha256 "$METADATA")" = "$archive_sha" ] || fail "metadata archive hash"
[ "$(jq -r .size "$METADATA")" = "$archive_size" ] || fail "metadata archive size"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-raw-verify.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM
tar -xOf "$ARCHIVE" manifest.json > "$tmp/manifest.json" || fail "manifest missing"
manifest="$tmp/manifest.json"
[ "$(jq -r .format "$manifest")" = hardened-nanokvm-system-update-v2 ] || fail "manifest format"
[ "$(jq -r .version "$manifest")" = "$RAW_VERSION" ] || fail "manifest version"
[ "$(jq -r .target "$manifest")" = "$TARGET" ] || fail "manifest target"
[ "$(jq -r .kernel_version "$manifest")" = "$RAW_KERNEL_VERSION" ] || fail "manifest kernel"
[ "$(jq -r .required_app_version "$manifest")" = "$RAW_REQUIRED_APP_VERSION" ] || \
	fail "manifest app requirement"
[ "$(jq -r .minimum_system_version "$manifest")" = "$RAW_MINIMUM_SYSTEM_VERSION" ] || \
	fail "manifest system requirement"
[ "$(jq -r .source_commit "$manifest")" = "$RAW_SOURCE_COMMIT" ] || fail "manifest source commit"
jq -e --arg operation "$RAW_REQUIRED_OPERATION" \
	'.operations | index($operation) != null' "$manifest" >/dev/null || \
	fail "manifest operation $RAW_REQUIRED_OPERATION"

# image LABEL PAYLOAD EXPECTED_SHA256 EXPECTED_SIZE
image() {
	local payload sha size
	payload="$(jq -r --arg label "$1" '.raw_images[] | select(.label == $label) | .payload' "$manifest")"
	[ "$payload" = "$2" ] || fail "$1 payload path"
	tar -xOf "$ARCHIVE" "payload/$payload" | gzip -dc > "$tmp/image" || fail "$1 payload"
	sha="$(sha256sum "$tmp/image" | awk '{print $1}')"
	size="$(wc -c < "$tmp/image" | tr -d ' ')"
	[ "$sha" = "$3" ] || fail "$1 image hash"
	[ "$size" = "$4" ] || fail "$1 image size"
	[ "$(jq -r --arg label "$1" '.raw_images[] | select(.label == $label) | .sha256' "$manifest")" = "$sha" ] || \
		fail "manifest $1 hash"
	if [ "$1" = ROOTFS ]; then
		sh "$ROOT_DIR/scripts/validate-raw-restore-rootfs.sh" "$tmp/image" || fail "raw restore prerequisites"
	fi
	rm -f "$tmp/image"
}
image ROOTFS images/rootfs.sd.gz "$RAW_ROOTFS_SHA256" "$RAW_ROOTFS_SIZE"
image BOOT images/boot.vfat.gz "$RAW_BOOT_SHA256" "$RAW_BOOT_SIZE"

printf 'ARCHIVE_SHA256=%s\nARCHIVE_SIZE=%s\n' "$archive_sha" "$archive_size"
printf 'SUCCESS: signed raw bundle %s matches the accepted candidate\n' "$RAW_VERSION"
