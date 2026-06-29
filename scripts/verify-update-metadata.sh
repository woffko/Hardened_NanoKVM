#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <latest.json> <latest.json.sig> <public-key.pem>" >&2
  exit 1
fi

METADATA="$1"
SIGNATURE="$2"
PUBLIC_KEY="$3"

[ -f "$METADATA" ] || {
  echo "metadata file does not exist: $METADATA" >&2
  exit 1
}
[ -f "$SIGNATURE" ] || {
  echo "signature file does not exist: $SIGNATURE" >&2
  exit 1
}
[ -f "$PUBLIC_KEY" ] || {
  echo "public key file does not exist: $PUBLIC_KEY" >&2
  exit 1
}

openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SIGNATURE" "$METADATA"
