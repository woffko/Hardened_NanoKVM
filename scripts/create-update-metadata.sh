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
SIZE=$(wc -c < "$ARCHIVE" | tr -d ' ')
SHA512=$(openssl dgst -sha512 -binary "$ARCHIVE" | base64 | tr -d '\n')
URL="https://github.com/woffko/Hardened_NanoKVM/releases/download/$TAG/$NAME"
SIGNING_KEY="${APP_UPDATE_SIGNING_KEY:-${SYSTEM_UPDATE_SIGNING_KEY:-}}"

if [ -n "$SIGNING_KEY" ]; then
  SIGNATURE_ALGORITHM="${APP_UPDATE_SIGNATURE_ALGORITHM:-sha256-rsa-pkcs1-v1_5}"
  SIGNATURE_KEY_ID="${APP_UPDATE_SIGNATURE_KEY_ID:-hardened-system-dev}"
else
  SIGNATURE_ALGORITHM="${APP_UPDATE_SIGNATURE_ALGORITHM:-unsigned}"
  SIGNATURE_KEY_ID="${APP_UPDATE_SIGNATURE_KEY_ID:-unsigned}"
fi

case "$VERSION" in
  *[!0-9.]* | .* | *..* | *.)
    echo "invalid semver version: $VERSION" >&2
    exit 1
    ;;
esac

case "$NAME" in
  hardened-nanokvm-kvmapp-*.tar.gz | nanokvm_*.tar.gz) ;;
  *)
    echo "invalid update archive name: $NAME" >&2
    exit 1
    ;;
esac

case "$SIGNATURE_ALGORITHM" in
  sha256-rsa-pkcs1-v1_5 | unsigned) ;;
  *)
    echo "invalid signature algorithm: $SIGNATURE_ALGORITHM" >&2
    exit 1
    ;;
esac

case "$SIGNATURE_KEY_ID" in
  "" | *[!A-Za-z0-9._+-]* | .* | *..* | *.)
    echo "invalid signature key id: $SIGNATURE_KEY_ID" >&2
    exit 1
    ;;
esac

if [ -z "$SIGNING_KEY" ]; then
  if [ "$SIGNATURE_ALGORITHM" != "unsigned" ] || [ "$SIGNATURE_KEY_ID" != "unsigned" ]; then
    echo "unsigned metadata must use signature_algorithm=unsigned and signature_key_id=unsigned" >&2
    exit 1
  fi
else
  [ -f "$SIGNING_KEY" ] || {
    echo "signing key does not exist: $SIGNING_KEY" >&2
    exit 1
  }
  if [ "$SIGNATURE_ALGORITHM" = "unsigned" ] || [ "$SIGNATURE_KEY_ID" = "unsigned" ]; then
    echo "signed metadata cannot use unsigned signature markers" >&2
    exit 1
  fi
fi

cat > "$OUTPUT" <<EOF
{
  "version": "$VERSION",
  "name": "$NAME",
  "sha512": "$SHA512",
  "size": $SIZE,
  "url": "$URL",
  "signature_algorithm": "$SIGNATURE_ALGORITHM",
  "signature_key_id": "$SIGNATURE_KEY_ID"
}
EOF

sha256sum "$OUTPUT" > "$OUTPUT.sha256"

if [ -n "$SIGNING_KEY" ]; then
  openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$OUTPUT.sig" "$OUTPUT"
  base64 "$OUTPUT.sig" | tr -d '\n' > "$OUTPUT.sig.base64"
fi

echo "$OUTPUT"
