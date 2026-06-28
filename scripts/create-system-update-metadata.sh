#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <version> <tag> <archive> <output-json>" >&2
  exit 1
fi

VERSION="$1"
TAG="$2"
ARCHIVE="$3"
OUTPUT="$4"
NAME=$(basename "$ARCHIVE")
TARGET="${TARGET:-sg2002-licheervnano-sd}"
CHANNEL="${CHANNEL:-stable}"
SIZE=$(wc -c < "$ARCHIVE" | tr -d ' ')
SHA256=$(sha256sum "$ARCHIVE" | awk '{print $1}')
SHA512=$(openssl dgst -sha512 -binary "$ARCHIVE" | base64 | tr -d '\n')
URL="https://github.com/woffko/Hardened_NanoKVM/releases/download/$TAG/$NAME"
RELEASE_NOTES_URL="https://github.com/woffko/Hardened_NanoKVM/releases/tag/$TAG"
SIGNATURE_ALGORITHM="${SYSTEM_UPDATE_SIGNATURE_ALGORITHM:-sha256-rsa-pkcs1-v1_5}"
SIGNATURE_KEY_ID="${SYSTEM_UPDATE_SIGNATURE_KEY_ID:-unsigned}"
SIGNING_KEY="${SYSTEM_UPDATE_SIGNING_KEY:-}"

case "$VERSION" in
  "" | *[!A-Za-z0-9._+-]* | .* | *..* | *.)
    echo "invalid system update version: $VERSION" >&2
    exit 1
    ;;
esac

case "$TAG" in
  "" | *[!A-Za-z0-9._/-]* | /* | *..*)
    echo "invalid release tag: $TAG" >&2
    exit 1
    ;;
esac

case "$TARGET" in
  "" | *[!A-Za-z0-9._+-]*)
    echo "invalid target: $TARGET" >&2
    exit 1
    ;;
esac

case "$CHANNEL" in
  stable | preview | dev) ;;
  *)
    echo "invalid channel: $CHANNEL" >&2
    exit 1
    ;;
esac

case "$NAME" in
  hardened-nanokvm-system-*.tar.gz) ;;
  *)
    echo "invalid system update archive name: $NAME" >&2
    exit 1
    ;;
esac

cat > "$OUTPUT" <<EOF
{
  "kind": "hardened-nanokvm-system-update",
  "format": 1,
  "channel": "$CHANNEL",
  "version": "$VERSION",
  "target": "$TARGET",
  "name": "$NAME",
  "sha256": "$SHA256",
  "sha512": "$SHA512",
  "size": $SIZE,
  "url": "$URL",
  "release_notes_url": "$RELEASE_NOTES_URL",
  "signature_algorithm": "$SIGNATURE_ALGORITHM",
  "signature_key_id": "$SIGNATURE_KEY_ID"
}
EOF

sha256sum "$OUTPUT" > "$OUTPUT.sha256"

if [ -n "$SIGNING_KEY" ]; then
  [ -f "$SIGNING_KEY" ] || {
    echo "signing key does not exist: $SIGNING_KEY" >&2
    exit 1
  }
  openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$OUTPUT.sig" "$OUTPUT"
  base64 "$OUTPUT.sig" | tr -d '\n' > "$OUTPUT.sig.base64"
fi

echo "$OUTPUT"
