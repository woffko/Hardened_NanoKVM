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

cat > "$OUTPUT" <<EOF
{
  "version": "$VERSION",
  "name": "$NAME",
  "sha512": "$SHA512",
  "size": $SIZE,
  "url": "$URL"
}
EOF

echo "$OUTPUT"
