#!/usr/bin/env bash
# Prepare one combined release (app, raw system update, full SD image) from
# the accepted candidate files. Nothing is signed unless every input matches
# its pinned SHA-256 and the raw bundle passes its signed gate. The release is
# assembled in a staging directory and renamed into place only after its
# manifest checks. Publication is a separate step: scripts/publish-release.sh.
#
# Required environment:
#   RELEASE_TAG APP_VERSION SYSTEM_VERSION KERNEL_VERSION
#   APP_INPUT APP_INPUT_SHA256
#   SYSTEM_INPUT_DIR (archive, system-latest.json and .sig) SYSTEM_INPUT_SHA256
#   ROOTFS_SHA256 ROOTFS_SIZE BOOT_SHA256 BOOT_SIZE RAW_REQUIRED_OPERATION
#   SD_INPUT SD_INPUT_SHA256 SD_NAME
#   BUILD_COMMIT_FILE NOTES_INPUT SIGNING_KEY OUTPUT_DIR
# Optional: PUBLIC_KEY (the production key), SIGNATURE_KEY_ID
# (hardened-system-prod-2026q3). --draft marks the release DRAFT_ONLY and
# allows release blockers in the notes.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PUBLIC_KEY="${PUBLIC_KEY:-$ROOT_DIR/kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem}"
SIGNATURE_KEY_ID="${SIGNATURE_KEY_ID:-hardened-system-prod-2026q3}"
DRAFT=0

fail() {
	echo "prepare-release: $*" >&2
	exit 1
}

if [ "${1:-}" = --draft ]; then
	DRAFT=1
	shift
fi
[ "$#" -eq 0 ] || {
	echo "usage: $0 [--draft]" >&2
	exit 2
}

for name in RELEASE_TAG APP_VERSION SYSTEM_VERSION KERNEL_VERSION APP_INPUT APP_INPUT_SHA256 \
	SYSTEM_INPUT_DIR SYSTEM_INPUT_SHA256 ROOTFS_SHA256 ROOTFS_SIZE BOOT_SHA256 BOOT_SIZE \
	RAW_REQUIRED_OPERATION SD_INPUT SD_INPUT_SHA256 SD_NAME BUILD_COMMIT_FILE NOTES_INPUT \
	SIGNING_KEY OUTPUT_DIR
do
	[ -n "${!name:-}" ] || fail "$name is required"
done
for command in base64 git gzip jq openssl python3 sha256sum sha512sum tar xz
do
	command -v "$command" >/dev/null 2>&1 || fail "missing command: $command"
done

APP_NAME="hardened-nanokvm-kvmapp-$APP_VERSION.tar.gz"
SYSTEM_NAME="hardened-nanokvm-system-$SYSTEM_VERSION.tar.gz"
SYSTEM_ARCHIVE="$SYSTEM_INPUT_DIR/$SYSTEM_NAME"
case "$SD_NAME" in
	*/* | .* | *[!A-Za-z0-9._+-]*) fail "invalid SD image name: $SD_NAME" ;;
	*.img.xz) ;;
	*) fail "the SD image name must end in .img.xz" ;;
esac

for path in "$APP_INPUT" "$SYSTEM_ARCHIVE" "$SYSTEM_INPUT_DIR/system-latest.json" \
	"$SYSTEM_INPUT_DIR/system-latest.json.sig" "$SD_INPUT" "$BUILD_COMMIT_FILE" \
	"$NOTES_INPUT" "$SIGNING_KEY" "$PUBLIC_KEY"
do
	[ -f "$path" ] || fail "missing input: $path"
	[ -s "$path" ] || fail "empty input: $path"
done
[ -z "$(git -C "$ROOT_DIR" status --short)" ] || fail "a clean worktree is required"
SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"
BUILD_COMMIT="$(git -C "$ROOT_DIR" rev-parse --verify "$(tr -d '\r\n' < "$BUILD_COMMIT_FILE")^{commit}")" || \
	fail "the build commit is not a commit of this repository"
git -C "$ROOT_DIR" merge-base --is-ancestor "$BUILD_COMMIT" "$SOURCE_COMMIT" || \
	fail "the build commit is not an ancestor of the release commit"
[ "$RELEASE_TAG" = "hardened-system-$SYSTEM_VERSION" ] || \
	fail "the tag must be hardened-system-$SYSTEM_VERSION for the device URL validator"
if grep -Eq 'RELEASE_BLOCKED_[A-Z0-9_]+' "$NOTES_INPUT" && [ "$DRAFT" -ne 1 ]; then
	fail "the release notes still name a release blocker"
fi
[ ! -e "$OUTPUT_DIR" ] || fail "refusing to overwrite $OUTPUT_DIR"

# Only the accepted candidate bytes are ever signed or published.
pin() {
	[ "$(sha256sum "$1" | awk '{print $1}')" = "$2" ] || \
		fail "$1 does not match its pinned SHA-256"
}
pin "$APP_INPUT" "$APP_INPUT_SHA256"
pin "$SYSTEM_ARCHIVE" "$SYSTEM_INPUT_SHA256"
pin "$SD_INPUT" "$SD_INPUT_SHA256"

RAW_VERSION="$SYSTEM_VERSION" \
RAW_REQUIRED_APP_VERSION="$APP_VERSION" \
RAW_KERNEL_VERSION="$KERNEL_VERSION" \
RAW_SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse --short "$BUILD_COMMIT")" \
RAW_REQUIRED_OPERATION="$RAW_REQUIRED_OPERATION" \
RAW_ROOTFS_SHA256="$ROOTFS_SHA256" RAW_ROOTFS_SIZE="$ROOTFS_SIZE" \
RAW_BOOT_SHA256="$BOOT_SHA256" RAW_BOOT_SIZE="$BOOT_SIZE" \
RAW_KEY_ID="$SIGNATURE_KEY_ID" \
	"$ROOT_DIR/scripts/verify-raw-bundle.sh" "$SYSTEM_ARCHIVE" \
	"$SYSTEM_INPUT_DIR/system-latest.json" "$SYSTEM_INPUT_DIR/system-latest.json.sig" \
	"$PUBLIC_KEY" >/dev/null || fail "the raw bundle failed its signed gate"
[ "$(tar -xOf "$APP_INPUT" kvmapp/version | tr -d '\r\n')" = "$APP_VERSION" ] || \
	fail "the app archive is not version $APP_VERSION"

mkdir -p "$(dirname "$OUTPUT_DIR")"
STAGE="$(mktemp -d "$(dirname "$OUTPUT_DIR")/.prepare-release.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
cp "$APP_INPUT" "$STAGE/$APP_NAME"
cp "$SYSTEM_ARCHIVE" "$STAGE/$SYSTEM_NAME"
cp "$NOTES_INPUT" "$STAGE/RELEASE_NOTES.md"
pin "$STAGE/$APP_NAME" "$APP_INPUT_SHA256"
pin "$STAGE/$SYSTEM_NAME" "$SYSTEM_INPUT_SHA256"
(
	cd "$STAGE"
	sha256sum "$APP_NAME" > "$APP_NAME.sha256"
	sha256sum "$SYSTEM_NAME" > "$SYSTEM_NAME.sha256"
	sha512sum "$SYSTEM_NAME" > "$SYSTEM_NAME.sha512"
)

APP_UPDATE_SIGNING_KEY="$SIGNING_KEY" APP_UPDATE_SIGNATURE_KEY_ID="$SIGNATURE_KEY_ID" \
	"$ROOT_DIR/scripts/create-update-metadata.sh" \
	"$APP_VERSION" "$RELEASE_TAG" "$STAGE/$APP_NAME" "$STAGE/latest.json" >/dev/null
# The app metadata verifying with PUBLIC_KEY shows the signing key in hand is
# the release key. The system metadata is the system build's, already checked.
"$ROOT_DIR/scripts/verify-update-metadata.sh" \
	"$STAGE/latest.json" "$STAGE/latest.json.sig" "$PUBLIC_KEY" >/dev/null || \
	fail "the app metadata does not verify with $PUBLIC_KEY"
cp "$SYSTEM_INPUT_DIR/system-latest.json" "$SYSTEM_INPUT_DIR/system-latest.json.sig" "$STAGE/"
openssl base64 -A -in "$STAGE/system-latest.json.sig" -out "$STAGE/system-latest.json.sig.base64"
(
	cd "$STAGE"
	sha256sum latest.json > latest.json.sha256
	sha256sum system-latest.json > system-latest.json.sha256
)

xz -T0 -9 -c "$SD_INPUT" > "$STAGE/$SD_NAME"
xz -dc "$STAGE/$SD_NAME" | cmp -s - "$SD_INPUT" || fail "the compressed SD image does not round-trip"
(
	cd "$STAGE"
	sha256sum "$SD_NAME" > "$SD_NAME.sha256"
	find . -maxdepth 1 -type f ! -name RELEASE_NOTES.md ! -name SHA256SUMS -printf '%f\n' | \
		LC_ALL=C sort | xargs sha256sum > SHA256SUMS
)

python3 -I -B "$ROOT_DIR/scripts/release-manifest.py" create "$STAGE" \
	--field "tag=$RELEASE_TAG" --field "app_version=$APP_VERSION" \
	--field "system_version=$SYSTEM_VERSION" --field "kernel_version=$KERNEL_VERSION" \
	--field "signature_key_id=$SIGNATURE_KEY_ID" --field "source_commit=$SOURCE_COMMIT" \
	--field "build_commit=$BUILD_COMMIT" --field "sd_name=$SD_NAME" \
	--input "app=$APP_INPUT_SHA256" --input "system=$SYSTEM_INPUT_SHA256" \
	--input "sd=$SD_INPUT_SHA256"
if [ "$DRAFT" -eq 1 ]; then
	printf 'draft release; do not publish\n' > "$STAGE/DRAFT_ONLY"
	python3 -I -B "$ROOT_DIR/scripts/release-manifest.py" check "$STAGE" --allow-draft
else
	python3 -I -B "$ROOT_DIR/scripts/release-manifest.py" check "$STAGE"
fi
mv -T "$STAGE" "$OUTPUT_DIR"
trap - EXIT
printf 'release prepared: %s\n' "$OUTPUT_DIR"
