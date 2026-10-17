#!/bin/sh
set -eu

SCRIPT_ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
. "$SCRIPT_ROOT/scripts/lib/build-security.sh"

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
[ -s "$ARCHIVE" ] || { echo "system update archive is missing or empty" >&2; exit 1; }
SIZE=$(wc -c < "$ARCHIVE")
SHA256=$(build_file_sha256 "$ARCHIVE")
SHA512=$(build_file_sha512_base64 "$ARCHIVE")
URL="https://github.com/woffko/Hardened_NanoKVM/releases/download/$TAG/$NAME"
RELEASE_NOTES_URL="https://github.com/woffko/Hardened_NanoKVM/releases/tag/$TAG"
SIGNING_KEY="${SYSTEM_UPDATE_SIGNING_KEY:-}"
SECURITY_PATCH_LEVEL="${SECURITY_PATCH_LEVEL:-}"
SYSTEM_UPDATE_FORMAT="${SYSTEM_UPDATE_FORMAT:-1}"
REQUIRED_APP_VERSION="${SYSTEM_UPDATE_REQUIRED_APP_VERSION:-}"

if [ -n "$SIGNING_KEY" ]; then
  SIGNATURE_ALGORITHM="${SYSTEM_UPDATE_SIGNATURE_ALGORITHM:-sha256-rsa-pkcs1-v1_5}"
  SIGNATURE_KEY_ID="${SYSTEM_UPDATE_SIGNATURE_KEY_ID:-hardened-system-dev}"
else
  SIGNATURE_ALGORITHM="${SYSTEM_UPDATE_SIGNATURE_ALGORITHM:-unsigned}"
  SIGNATURE_KEY_ID="${SYSTEM_UPDATE_SIGNATURE_KEY_ID:-unsigned}"
fi

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

case "$SYSTEM_UPDATE_FORMAT" in
  1)
    [ -z "$REQUIRED_APP_VERSION" ] || {
      echo "system metadata v1 cannot require an application version" >&2
      exit 1
    }
    ;;
  2)
    if ! printf '%s' "$REQUIRED_APP_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
      echo "system metadata v2 requires SYSTEM_UPDATE_REQUIRED_APP_VERSION=x.y.z" >&2
      exit 1
    fi
    ;;
  *)
    echo "invalid system update metadata format: $SYSTEM_UPDATE_FORMAT" >&2
    exit 1
    ;;
esac

if [ -n "$SECURITY_PATCH_LEVEL" ]; then
  case "$SECURITY_PATCH_LEVEL" in
    .* | *..* | *.)
      echo "invalid security patch level: $SECURITY_PATCH_LEVEL" >&2
      exit 1
      ;;
  esac
  if ! printf '%s' "$SECURITY_PATCH_LEVEL" | grep -Eq '^[A-Za-z0-9._+:/ -]+$'; then
    echo "invalid security patch level: $SECURITY_PATCH_LEVEL" >&2
    exit 1
  fi
fi

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
  [ -f "$SIGNING_KEY" ] || { echo "signing key does not exist: $SIGNING_KEY" >&2; exit 1; }
  if [ "$SIGNATURE_ALGORITHM" = "unsigned" ] || [ "$SIGNATURE_KEY_ID" = "unsigned" ]; then
    echo "signed metadata cannot use unsigned signature markers" >&2
    exit 1
  fi
fi

case "$NAME" in
  *[!A-Za-z0-9._+-]*) echo "invalid system update archive name: $NAME" >&2; exit 1 ;;
esac
case "$NAME" in
  hardened-nanokvm-system-*.tar.gz) ;;
  *)
    echo "invalid system update archive name: $NAME" >&2
    exit 1
    ;;
esac

build_begin_metadata_output "$OUTPUT" || exit 1
cat > "$metadata_work/metadata.json" <<EOF
{
  "kind": "hardened-nanokvm-system-update",
  "format": $SYSTEM_UPDATE_FORMAT,
  "channel": "$CHANNEL",
  "version": "$VERSION",
  "target": "$TARGET",
  "name": "$NAME",
  "sha256": "$SHA256",
  "sha512": "$SHA512",
  "size": $SIZE,
  "url": "$URL",
  "release_notes_url": "$RELEASE_NOTES_URL",
$(if [ -n "$SECURITY_PATCH_LEVEL" ]; then printf '  "security_patch_level": "%s",\n' "$SECURITY_PATCH_LEVEL"; fi)
$(if [ -n "$REQUIRED_APP_VERSION" ]; then printf '  "required_app_version": "%s",\n' "$REQUIRED_APP_VERSION"; fi)
  "signature_algorithm": "$SIGNATURE_ALGORITHM",
  "signature_key_id": "$SIGNATURE_KEY_ID"
}
EOF

build_publish_metadata_output || exit 1

echo "$OUTPUT"
