#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
# Historical RC12 integrity only, not the current remediation-candidate gate.
EXPECTED_SIGNATURE_MODE="${EXPECTED_SIGNATURE_MODE:-signed}"

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
	echo "usage: $0 <archive.tar.gz> <system-latest.json> [signature] [public-key]" >&2
	echo "Signed metadata is required by default; unsigned is explicit historical-fixture-only." >&2
	exit 1
fi
ARCHIVE="$(readlink -f "$1")"
METADATA="$(readlink -f "$2")"
SIGNATURE="${3:-}"
PUBLIC_KEY="${4:-$ROOT_DIR/kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem}"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

for command in cmp gzip jq readlink sha256sum tar wc
do
	command -v "$command" >/dev/null 2>&1 || fail "missing command: $command"
done
[ -f "$ARCHIVE" ] || fail "archive is missing"
[ -f "$METADATA" ] || fail "metadata is missing"
[ "$(basename "$ARCHIVE")" = hardened-nanokvm-system-0.3.0-raw.12.tar.gz ] || \
	fail "unexpected archive name"

# Authenticate exact metadata bytes before inspecting or expanding any payload.
# The key is fixed here or explicitly supplied by the reviewer, never resolved
# from an untrusted metadata path. No legacy-key fallback after verification fails.
case "$EXPECTED_SIGNATURE_MODE" in
	signed)
		[ -n "$SIGNATURE" ] || fail "signed verification requires a signature"
		[ -f "$SIGNATURE" ] || fail "signature is missing"
		[ -f "$PUBLIC_KEY" ] || fail "public key is missing"
		command -v openssl >/dev/null 2>&1 || fail "missing command: openssl"
		[ "$(jq -r .signature_algorithm "$METADATA")" = sha256-rsa-pkcs1-v1_5 ] || fail "signed algorithm"
		[ "$(jq -r .signature_key_id "$METADATA")" = hardened-system-prod-2026q3 ] || fail "signed key id"
		"$ROOT_DIR/scripts/verify-system-update-metadata.sh" \
			"$METADATA" "$SIGNATURE" "$PUBLIC_KEY" >/dev/null
		;;
	unsigned)
		[ "$(jq -r .signature_algorithm "$METADATA")" = unsigned ] || fail "unsigned algorithm"
		[ "$(jq -r .signature_key_id "$METADATA")" = unsigned ] || fail "unsigned key id"
		[ -z "$SIGNATURE" ] || fail "unsigned verification received a signature"
		echo "WARNING: unsigned historical-fixture verification; not release acceptance" >&2
		;;
	*) fail "invalid EXPECTED_SIGNATURE_MODE" ;;
esac

tmp="$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-rc12-raw-verify.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM
tar -xOf "$ARCHIVE" manifest.json > "$tmp/manifest.json"

[ "$(jq -r .format "$tmp/manifest.json")" = hardened-nanokvm-system-update-v2 ] || fail "manifest format"
[ "$(jq -r .version "$tmp/manifest.json")" = 0.3.0-raw.12 ] || fail "manifest version"
[ "$(jq -r .target "$tmp/manifest.json")" = sg2002-licheervnano-sd ] || fail "manifest target"
[ "$(jq -r .kernel_version "$tmp/manifest.json")" = 5.10.265-tag- ] || fail "manifest kernel"
[ "$(jq -r .required_app_version "$tmp/manifest.json")" = 2.0.42 ] || fail "manifest app requirement"
[ "$(jq -r .source_commit "$tmp/manifest.json")" = 9567b5f ] || fail "manifest source commit"
jq -e '.operations | index("manual-recovery-only") != null' "$tmp/manifest.json" >/dev/null || \
	fail "manual recovery marker"

rootfs_payload="$(jq -r '.raw_images[] | select(.label == "ROOTFS") | .payload' "$tmp/manifest.json")"
boot_payload="$(jq -r '.raw_images[] | select(.label == "BOOT") | .payload' "$tmp/manifest.json")"
[ "$rootfs_payload" = images/rootfs.sd.gz ] || fail "rootfs payload path"
[ "$boot_payload" = images/boot.vfat.gz ] || fail "boot payload path"
tar -xOf "$ARCHIVE" "payload/$rootfs_payload" | gzip -dc > "$tmp/rootfs.sd"
tar -xOf "$ARCHIVE" "payload/$boot_payload" | gzip -dc > "$tmp/boot.vfat"

rootfs_sha="$(sha256sum "$tmp/rootfs.sd" | awk '{print $1}')"
boot_sha="$(sha256sum "$tmp/boot.vfat" | awk '{print $1}')"
rootfs_size="$(wc -c < "$tmp/rootfs.sd" | tr -d ' ')"
boot_size="$(wc -c < "$tmp/boot.vfat" | tr -d ' ')"
[ "$rootfs_sha" = b840bd08f2c708b45b527d005719b6d5dc6a7b1ba66922b8e161b570a950c760 ] || fail "selected rootfs hash"
[ "$boot_sha" = 0d74f6acbd21499a181636afbcb3fc3d221734d3093df95cc42532c5f567864b ] || fail "selected boot hash"
[ "$rootfs_size" = 1610612736 ] || fail "rootfs size"
[ "$boot_size" = 16777216 ] || fail "boot size"
[ "$(jq -r '.raw_images[] | select(.label == "ROOTFS") | .sha256' "$tmp/manifest.json")" = "$rootfs_sha" ] || fail "manifest rootfs hash"
[ "$(jq -r '.raw_images[] | select(.label == "BOOT") | .sha256' "$tmp/manifest.json")" = "$boot_sha" ] || fail "manifest boot hash"

archive_sha="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
archive_size="$(wc -c < "$ARCHIVE" | tr -d ' ')"
[ "$(jq -r .format "$METADATA")" = 2 ] || fail "metadata format"
[ "$(jq -r .channel "$METADATA")" = preview ] || fail "metadata channel"
[ "$(jq -r .version "$METADATA")" = 0.3.0-raw.12 ] || fail "metadata version"
[ "$(jq -r .target "$METADATA")" = sg2002-licheervnano-sd ] || fail "metadata target"
[ "$(jq -r .required_app_version "$METADATA")" = 2.0.42 ] || fail "metadata app requirement"
[ "$(jq -r .sha256 "$METADATA")" = "$archive_sha" ] || fail "metadata archive hash"
[ "$(jq -r .size "$METADATA")" = "$archive_size" ] || fail "metadata archive size"

printf 'ARCHIVE_SHA256=%s\n' "$archive_sha"
printf 'ARCHIVE_SIZE=%s\n' "$archive_size"
printf 'ROOTFS_SHA256=%s\n' "$rootfs_sha"
printf 'ROOTFS_SIZE=%s\n' "$rootfs_size"
printf 'BOOT_SHA256=%s\n' "$boot_sha"
printf 'BOOT_SIZE=%s\n' "$boot_size"
printf 'METADATA_FORMAT=2\nREQUIRED_APP_VERSION=2.0.42\n'
printf 'VERIFICATION_SCOPE=historical-rc12\n'
printf 'SIGNATURE_MODE=%s\n' "$EXPECTED_SIGNATURE_MODE"
if [ "$EXPECTED_SIGNATURE_MODE" = signed ]; then
	printf 'SUCCESS: signed historical RC12 raw bundle gate passed\n'
else
	printf 'SUCCESS: unsigned historical RC12 fixture integrity passed (NOT RELEASE ACCEPTANCE)\n'
fi
