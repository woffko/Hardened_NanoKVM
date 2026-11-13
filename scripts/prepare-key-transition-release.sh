#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
APP_VERSION="${APP_VERSION:-2.0.42}"
RELEASE_TAG="${RELEASE_TAG:-hardened-rust-2.0.42-key-transition}"
APP_INPUT="${APP_RELEASE_INPUT:-$ROOT_DIR/build/key-transition-2.0.42-bootstrap/app-a/out/hardened-nanokvm-kvmapp-2.0.42.tar.gz}"
NOTES_INPUT="${RELEASE_NOTES_INPUT:-$ROOT_DIR/docs/releases/2.0.42-key-transition.md}"
OUTPUT_DIR="${KEY_TRANSITION_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build/release/key-transition-2.0.42}"
APP_NAME="hardened-nanokvm-kvmapp-$APP_VERSION.tar.gz"
EXPECTED_ARCHIVE_SHA256=aa0cd78c1b2e9951f216826c44b4b7ff2fb211fc1980540366f8f5b1f7e0dd20
EXPECTED_ARCHIVE_SIZE=22495269
EXPECTED_SERVER_SHA256=fd116fc459a1961cfc16fd0c7077a8f4c5e24d8f32d8745fd3b9744217083d6d
EXPECTED_LEGACY_DER_SHA256=2167216b8ccca472124a0f5bfc7889a3ab55772c221d8540e577243a1aa90926
EXPECTED_PRODUCTION_DER_SHA256=97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75
DRAFT=0

if [ "${1:-}" = --draft ]; then
	DRAFT=1
	shift
fi
[ "$#" -eq 0 ] || {
	echo "usage: $0 [--draft]" >&2
	exit 2
}

for command in awk grep openssl sha256sum tar wc
do
	command -v "$command" >/dev/null 2>&1 || {
		echo "required transition command is missing: $command" >&2
		exit 1
	}
done
[ -z "$(git -C "$ROOT_DIR" status --short)" ] || {
	echo "transition preparation requires a clean worktree" >&2
	exit 1
}
for path in "$APP_INPUT" "$NOTES_INPUT"
do
	[ -f "$path" ] || {
		echo "required transition input is missing: $path" >&2
		exit 1
	}
done
[ ! -e "$OUTPUT_DIR" ] || {
	echo "refusing to overwrite transition output: $OUTPUT_DIR" >&2
	exit 1
}

if grep -Eq 'TRANSITION_RELEASE_BLOCKED_[A-Z0-9_]+' "$NOTES_INPUT"; then
	[ "$DRAFT" -eq 1 ] || {
		echo "transition notes still contain a fail-closed blocker" >&2
		exit 1
	}
fi

[ "$(sha256sum "$APP_INPUT" | awk '{print $1}')" = "$EXPECTED_ARCHIVE_SHA256" ]
[ "$(wc -c < "$APP_INPUT" | tr -d ' ')" = "$EXPECTED_ARCHIVE_SIZE" ]
[ "$(tar -xOf "$APP_INPUT" kvmapp/version | tr -d '\r\n')" = "$APP_VERSION" ]
[ "$(tar -xOf "$APP_INPUT" kvmapp/server/NanoKVM-Server | sha256sum | awk '{print $1}')" = "$EXPECTED_SERVER_SHA256" ]

tmp="$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-key-transition.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM
tar -xOf "$APP_INPUT" kvmapp/system/keys/system-update-signing.pub.pem > "$tmp/legacy.pem"
tar -xOf "$APP_INPUT" kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem > "$tmp/production.pem"
tar -xOf "$APP_INPUT" kvmapp/system/keys/update-key-policy > "$tmp/policy"
[ "$(openssl pkey -pubin -in "$tmp/legacy.pem" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" = "$EXPECTED_LEGACY_DER_SHA256" ]
[ "$(openssl pkey -pubin -in "$tmp/production.pem" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" = "$EXPECTED_PRODUCTION_DER_SHA256" ]
for key_id in hardened-system-dev hardened-system-test hardened-system-prod-2026q3
do
	grep -qx "$key_id" "$tmp/policy"
done
if tar -tzf "$APP_INPUT" | \
	grep -Ei '(^|/)(id_rsa|id_ed25519|.*private.*|.*\.key|.*\.p12|.*\.pfx|.*\.jks|.*\.keystore|.*\.pem)$' | \
	grep -Ev '\.pub\.pem$' | grep -q .
then
	echo "transition archive may contain private-key material" >&2
	exit 1
fi

mkdir -p "$OUTPUT_DIR"
cp "$APP_INPUT" "$OUTPUT_DIR/$APP_NAME"
cp "$NOTES_INPUT" "$OUTPUT_DIR/RELEASE_NOTES.md"
(
	cd "$OUTPUT_DIR"
	sha256sum "$APP_NAME" > "$APP_NAME.sha256"
	sha256sum "$APP_NAME" "$APP_NAME.sha256" > SHA256SUMS
)
assets=("$APP_NAME" "$APP_NAME.sha256" SHA256SUMS)
printf 'asset\tbytes\tsha256\n' > "$OUTPUT_DIR/ASSETS.tsv"
for asset in "${assets[@]}" RELEASE_NOTES.md
do
	printf '%s\t%s\t%s\n' "$asset" \
		"$(wc -c < "$OUTPUT_DIR/$asset" | tr -d ' ')" \
		"$(sha256sum "$OUTPUT_DIR/$asset" | awk '{print $1}')" \
		>> "$OUTPUT_DIR/ASSETS.tsv"
done
git -C "$ROOT_DIR" rev-parse HEAD > "$OUTPUT_DIR/SOURCE_COMMIT"
printf '%s\n' "$RELEASE_TAG" > "$OUTPUT_DIR/RELEASE_TAG"
if [ "$DRAFT" -eq 1 ]; then
	printf 'blocked transition draft; do not publish\n' > "$OUTPUT_DIR/DRAFT_ONLY"
fi
printf 'manual key-transition release prepared: %s\n' "$OUTPUT_DIR"
