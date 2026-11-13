#!/usr/bin/env bash
set -euo pipefail

[ "${HARDENED_LEGACY_RC12:-}" = 1 ] || {
	echo "this is the published RC12 release helper; new releases use scripts/prepare-release.sh and scripts/publish-release.sh; set HARDENED_LEGACY_RC12=1 to run it" >&2
	exit 2
}

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
RELEASE_TAG="${RELEASE_TAG:-hardened-system-0.3.0-raw.12}"
APP_VERSION="${APP_VERSION:-2.0.42}"
SYSTEM_VERSION="${SYSTEM_VERSION:-0.3.0-raw.12}"
EXPECTED_KERNEL_VERSION="${EXPECTED_KERNEL_VERSION:-5.10.265-tag-}"
APP_INPUT="${APP_RELEASE_INPUT:-$ROOT_DIR/build/key-transition-2.0.42-bootstrap/app-a/out/hardened-nanokvm-kvmapp-2.0.42.tar.gz}"
SYSTEM_INPUT_DIR="${SYSTEM_RELEASE_INPUT_DIR:-$ROOT_DIR/build/latestbuildroot/raw-system-update-$SYSTEM_VERSION-bridge/artifacts}"
SD_INPUT="${SD_RELEASE_INPUT:-$ROOT_DIR/build/latestbuildroot/kernel-5.10.265-rc12-bridge-a/recovery/assembly/images/hardened-sg2002-port.img}"
BUILD_COMMIT_FILE="${RC12_BUILD_COMMIT_FILE:-$ROOT_DIR/build/latestbuildroot/kernel-5.10.265-rc12-bridge-a/_reports/outer-commit.txt}"
NOTES_INPUT="${RELEASE_NOTES_INPUT:-$ROOT_DIR/docs/releases/rc12-2.0.42-raw.12.md}"
OUTPUT_DIR="${COMBINED_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build/release/combined-rc12-bridge}"
SIGNING_KEY="${APP_UPDATE_SIGNING_KEY:-${SYSTEM_UPDATE_SIGNING_KEY:-}}"
PUBLIC_KEY="${UPDATE_PUBLIC_KEY:-$ROOT_DIR/kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem}"
SECURITY_PATCH_LEVEL="${SECURITY_PATCH_LEVEL:-Buildroot 2026.05.1 security maintenance Linux 5.10.265 SG2002 vendor port}"
SOURCE_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"
DRAFT=0

if [ "${1:-}" = --draft ]; then
	DRAFT=1
	shift
fi
[ "$#" -eq 0 ] || {
	echo "usage: $0 [--draft]" >&2
	exit 2
}

APP_NAME="hardened-nanokvm-kvmapp-$APP_VERSION.tar.gz"
SYSTEM_NAME="hardened-nanokvm-system-$SYSTEM_VERSION.tar.gz"
SD_NAME="Hardened_NanoKVM_2.0.42_RC12_System_0.3.0-raw.12_Buildroot-2026.05.1.img.xz"

[ -n "$SIGNING_KEY" ] || {
	echo "APP_UPDATE_SIGNING_KEY or SYSTEM_UPDATE_SIGNING_KEY is required" >&2
	exit 1
}
[ -z "$(git -C "$ROOT_DIR" status --short)" ] || {
	echo "combined release preparation requires a clean worktree" >&2
	exit 1
}

for command in base64 gzip openssl sha256sum sha512sum tar xz
do
	command -v "$command" >/dev/null 2>&1 || {
		echo "required release command is missing: $command" >&2
		exit 1
	}
done

for path in \
	"$APP_INPUT" \
	"$SYSTEM_INPUT_DIR/$SYSTEM_NAME" \
	"$SYSTEM_INPUT_DIR/system-latest.json" \
	"$SYSTEM_INPUT_DIR/system-latest.json.sig" \
	"$SD_INPUT" \
	"$BUILD_COMMIT_FILE" \
	"$NOTES_INPUT" \
	"$SIGNING_KEY" \
	"$PUBLIC_KEY"
do
	[ -f "$path" ] || {
		echo "required combined release input is missing: $path" >&2
		exit 1
	}
done

"$ROOT_DIR/scripts/verify-system-update-metadata.sh" \
	"$SYSTEM_INPUT_DIR/system-latest.json" \
	"$SYSTEM_INPUT_DIR/system-latest.json.sig" \
	"$PUBLIC_KEY"

BUILD_COMMIT="$(cat "$BUILD_COMMIT_FILE")"
git -C "$ROOT_DIR" cat-file -e "$BUILD_COMMIT^{commit}"
git -C "$ROOT_DIR" merge-base --is-ancestor "$BUILD_COMMIT" "$SOURCE_COMMIT" || {
	echo "RC12 artifact build commit is not an ancestor of the release commit" >&2
	exit 1
}
BUILD_COMMIT_SHORT="$(git -C "$ROOT_DIR" rev-parse --short "$BUILD_COMMIT^{commit}")"

[ "$RELEASE_TAG" = "hardened-system-$SYSTEM_VERSION" ] || {
	echo "combined tag must satisfy the deployed system URL validator" >&2
	exit 1
}
if grep -Eq 'RELEASE_BLOCKED_[A-Z0-9_]+' "$NOTES_INPUT"; then
	[ "$DRAFT" -eq 1 ] || {
		echo "release notes still contain a fail-closed release blocker" >&2
		exit 1
	}
fi

if [ -e "$OUTPUT_DIR" ]; then
	echo "refusing to overwrite combined release output: $OUTPUT_DIR" >&2
	exit 1
fi

mkdir -p "$OUTPUT_DIR"
cp "$APP_INPUT" "$OUTPUT_DIR/$APP_NAME"
cp "$SYSTEM_INPUT_DIR/$SYSTEM_NAME" "$OUTPUT_DIR/$SYSTEM_NAME"
cp "$NOTES_INPUT" "$OUTPUT_DIR/RELEASE_NOTES.md"

test "$(tar -xOf "$OUTPUT_DIR/$APP_NAME" kvmapp/version | tr -d '\r\n')" = "$APP_VERSION"
manifest="$(tar -xOf "$OUTPUT_DIR/$SYSTEM_NAME" manifest.json)"
test "$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$manifest" | head -n 1)" = "$SYSTEM_VERSION"
test "$(sed -n 's/.*"kernel_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$manifest" | head -n 1)" = "$EXPECTED_KERNEL_VERSION"
test "$(sed -n 's/.*"required_app_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$manifest" | head -n 1)" = "$APP_VERSION"
test "$(sed -n 's/.*"source_commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$manifest" | head -n 1)" = "$BUILD_COMMIT_SHORT"
grep -Fq '"format": "hardened-nanokvm-system-update-v2"' <<<"$manifest"
grep -Fq '"manual-recovery-only"' <<<"$manifest"
unset manifest

(
	cd "$OUTPUT_DIR"
	sha256sum "$APP_NAME" > "$APP_NAME.sha256"
	sha256sum "$SYSTEM_NAME" > "$SYSTEM_NAME.sha256"
	sha512sum "$SYSTEM_NAME" > "$SYSTEM_NAME.sha512"
)

APP_UPDATE_SIGNING_KEY="$SIGNING_KEY" \
APP_UPDATE_SIGNATURE_KEY_ID=hardened-system-prod-2026q3 \
	"$ROOT_DIR/scripts/create-update-metadata.sh" \
	"$APP_VERSION" "$RELEASE_TAG" "$OUTPUT_DIR/$APP_NAME" "$OUTPUT_DIR/latest.json"

CHANNEL=preview \
TARGET=sg2002-licheervnano-sd \
SECURITY_PATCH_LEVEL="$SECURITY_PATCH_LEVEL" \
SYSTEM_UPDATE_FORMAT=2 \
SYSTEM_UPDATE_REQUIRED_APP_VERSION="$APP_VERSION" \
SYSTEM_UPDATE_SIGNING_KEY="$SIGNING_KEY" \
SYSTEM_UPDATE_SIGNATURE_KEY_ID=hardened-system-prod-2026q3 \
	"$ROOT_DIR/scripts/create-system-update-metadata.sh" \
	"$SYSTEM_VERSION" "$RELEASE_TAG" "$OUTPUT_DIR/$SYSTEM_NAME" "$OUTPUT_DIR/system-latest.json"

"$ROOT_DIR/scripts/verify-update-metadata.sh" \
	"$OUTPUT_DIR/latest.json" "$OUTPUT_DIR/latest.json.sig" "$PUBLIC_KEY"
"$ROOT_DIR/scripts/verify-system-update-metadata.sh" \
	"$OUTPUT_DIR/system-latest.json" "$OUTPUT_DIR/system-latest.json.sig" "$PUBLIC_KEY"
cmp -s "$OUTPUT_DIR/system-latest.json" "$SYSTEM_INPUT_DIR/system-latest.json"
cmp -s "$OUTPUT_DIR/system-latest.json.sig" "$SYSTEM_INPUT_DIR/system-latest.json.sig"
grep -Fq '"format": 2' "$OUTPUT_DIR/system-latest.json"
grep -Fq "\"required_app_version\": \"$APP_VERSION\"" "$OUTPUT_DIR/system-latest.json"

(
	cd "$OUTPUT_DIR"
	sha256sum latest.json > latest.json.sha256
	sha256sum system-latest.json > system-latest.json.sha256
)

xz -T0 -9 -c "$SD_INPUT" > "$OUTPUT_DIR/$SD_NAME"
(
	cd "$OUTPUT_DIR"
	sha256sum "$SD_NAME" > "$SD_NAME.sha256"
)

assets=(
	"$APP_NAME"
	"$APP_NAME.sha256"
	latest.json
	latest.json.sha256
	latest.json.sig
	latest.json.sig.base64
	"$SYSTEM_NAME"
	"$SYSTEM_NAME.sha256"
	"$SYSTEM_NAME.sha512"
	system-latest.json
	system-latest.json.sha256
	system-latest.json.sig
	system-latest.json.sig.base64
	"$SD_NAME"
	"$SD_NAME.sha256"
)

(
	cd "$OUTPUT_DIR"
	sha256sum "${assets[@]}" > SHA256SUMS
)

printf 'asset\tbytes\tsha256\n' > "$OUTPUT_DIR/ASSETS.tsv"
for asset in "${assets[@]}" SHA256SUMS RELEASE_NOTES.md
do
	printf '%s\t%s\t%s\n' "$asset" \
		"$(wc -c < "$OUTPUT_DIR/$asset" | tr -d ' ')" \
		"$(sha256sum "$OUTPUT_DIR/$asset" | awk '{print $1}')" \
		>> "$OUTPUT_DIR/ASSETS.tsv"
done

printf 'source\tsha256\n' > "$OUTPUT_DIR/INPUTS.tsv"
for source in "$APP_INPUT" "$SYSTEM_INPUT_DIR/$SYSTEM_NAME" "$SD_INPUT" "$NOTES_INPUT" "$PUBLIC_KEY"
do
	printf '%s\t%s\n' "$source" "$(sha256sum "$source" | awk '{print $1}')" >> "$OUTPUT_DIR/INPUTS.tsv"
done
printf '%s\n' "$SOURCE_COMMIT" > "$OUTPUT_DIR/SOURCE_COMMIT"
printf '%s\n' "$BUILD_COMMIT" > "$OUTPUT_DIR/BUILD_COMMIT"
if [ "$DRAFT" -eq 1 ]; then
	printf 'blocked combined RC12 draft; do not publish\n' > "$OUTPUT_DIR/DRAFT_ONLY"
fi

printf 'combined RC12 release ready: %s\n' "$OUTPUT_DIR"
