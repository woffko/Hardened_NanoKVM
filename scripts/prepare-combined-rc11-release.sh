#!/usr/bin/env bash
set -euo pipefail

# Superseded by the RC12 release scripts. Kept so that RC11 assets can still
# be rebuilt or republished for recovery, which must be asked for explicitly.
[ "${HARDENED_LEGACY_RC11:-}" = 1 ] || {
	echo "this is the superseded RC11 release helper; set HARDENED_LEGACY_RC11=1 to run it" >&2
	exit 2
}

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
RELEASE_TAG="${RELEASE_TAG:-hardened-system-0.3.0-raw.10}"
APP_VERSION="${APP_VERSION:-2.0.40}"
SYSTEM_VERSION="${SYSTEM_VERSION:-0.3.0-raw.10}"
APP_INPUT="${APP_RELEASE_INPUT:-$ROOT_DIR/build/artifacts/nanokvm-kvmapp-rust.tar.gz}"
SYSTEM_INPUT_DIR="${SYSTEM_RELEASE_INPUT_DIR:-$ROOT_DIR/build/latestbuildroot/raw-system-update-$SYSTEM_VERSION/artifacts}"
SD_INPUT="${SD_RELEASE_INPUT:-$ROOT_DIR/build/latestbuildroot/recoverable-kernel-baseline-sd-v2/assembly/images/hardened-sg2002-port.img}"
NOTES_INPUT="${RELEASE_NOTES_INPUT:-$ROOT_DIR/docs/releases/rc11-2.0.40-raw.10.md}"
OUTPUT_DIR="${COMBINED_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build/release/combined-rc11}"
SIGNING_KEY="${APP_UPDATE_SIGNING_KEY:-${SYSTEM_UPDATE_SIGNING_KEY:-}}"
PUBLIC_KEY="${UPDATE_PUBLIC_KEY:-$ROOT_DIR/kvmapp/system/keys/system-update-signing.pub.pem}"

APP_NAME="hardened-nanokvm-kvmapp-$APP_VERSION.tar.gz"
SYSTEM_NAME="hardened-nanokvm-system-$SYSTEM_VERSION.tar.gz"
SD_NAME="Hardened_NanoKVM_2.0.40_RC11_System_0.3.0-raw.10_Buildroot-2026.05.1.img.xz"

[ -n "$SIGNING_KEY" ] || {
	echo "APP_UPDATE_SIGNING_KEY or SYSTEM_UPDATE_SIGNING_KEY is required" >&2
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
	"$SD_INPUT" \
	"$NOTES_INPUT" \
	"$SIGNING_KEY" \
	"$PUBLIC_KEY"
do
	[ -f "$path" ] || {
		echo "required combined release input is missing: $path" >&2
		exit 1
	}
done

[ "$RELEASE_TAG" = "hardened-system-$SYSTEM_VERSION" ] || {
	echo "combined tag must satisfy the deployed system URL validator" >&2
	exit 1
}

if [ -e "$OUTPUT_DIR" ]; then
	echo "refusing to overwrite combined release output: $OUTPUT_DIR" >&2
	exit 1
fi

mkdir -p "$OUTPUT_DIR"
cp "$APP_INPUT" "$OUTPUT_DIR/$APP_NAME"
cp "$SYSTEM_INPUT_DIR/$SYSTEM_NAME" "$OUTPUT_DIR/$SYSTEM_NAME"
cp "$NOTES_INPUT" "$OUTPUT_DIR/RELEASE_NOTES.md"

test "$(tar -xOf "$OUTPUT_DIR/$APP_NAME" kvmapp/version | tr -d '\r\n')" = "$APP_VERSION"
test "$(tar -xOf "$OUTPUT_DIR/$SYSTEM_NAME" manifest.json | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)" = "$SYSTEM_VERSION"

(
	cd "$OUTPUT_DIR"
	sha256sum "$APP_NAME" > "$APP_NAME.sha256"
	sha256sum "$SYSTEM_NAME" > "$SYSTEM_NAME.sha256"
	sha512sum "$SYSTEM_NAME" > "$SYSTEM_NAME.sha512"
)

APP_UPDATE_SIGNING_KEY="$SIGNING_KEY" \
APP_UPDATE_SIGNATURE_KEY_ID=hardened-system-dev \
	"$ROOT_DIR/scripts/create-update-metadata.sh" \
	"$APP_VERSION" "$RELEASE_TAG" "$OUTPUT_DIR/$APP_NAME" "$OUTPUT_DIR/latest.json"

CHANNEL=preview \
TARGET=sg2002-licheervnano-sd \
SECURITY_PATCH_LEVEL='Buildroot 2026.05.1 userspace vendor-kernel-5.10.4' \
SYSTEM_UPDATE_SIGNING_KEY="$SIGNING_KEY" \
SYSTEM_UPDATE_SIGNATURE_KEY_ID=hardened-system-dev \
	"$ROOT_DIR/scripts/create-system-update-metadata.sh" \
	"$SYSTEM_VERSION" "$RELEASE_TAG" "$OUTPUT_DIR/$SYSTEM_NAME" "$OUTPUT_DIR/system-latest.json"

"$ROOT_DIR/scripts/verify-update-metadata.sh" \
	"$OUTPUT_DIR/latest.json" "$OUTPUT_DIR/latest.json.sig" "$PUBLIC_KEY"
"$ROOT_DIR/scripts/verify-system-update-metadata.sh" \
	"$OUTPUT_DIR/system-latest.json" "$OUTPUT_DIR/system-latest.json.sig" "$PUBLIC_KEY"

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

printf 'combined release ready: %s\n' "$OUTPUT_DIR"
