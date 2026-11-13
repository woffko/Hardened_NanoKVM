#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-system-v2-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM

mkdir -p "$WORK/payload/rootfs/etc" "$WORK/out" "$WORK/meta"
printf 'raw11-v2\n' > "$WORK/payload/rootfs/etc/security-maintenance-test"

SYSTEM_UPDATE_FORMAT=2 \
SYSTEM_UPDATE_REQUIRED_APP_VERSION=2.0.41 \
BASE_VERSION=Buildroot-2026.05.1-security \
KERNEL_VERSION=5.10.4-tag- \
  "$ROOT/scripts/create-system-update-bundle.sh" \
  0.3.0-raw.11 sg2002-licheervnano-sd "$WORK/payload" "$WORK/out" >/dev/null

ARCHIVE="$WORK/out/hardened-nanokvm-system-0.3.0-raw.11.tar.gz"
tar -xOf "$ARCHIVE" manifest.json > "$WORK/manifest.json"
grep -Fq '"format": "hardened-nanokvm-system-update-v2"' "$WORK/manifest.json"
grep -Fq '"required_app_version": "2.0.41"' "$WORK/manifest.json"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$WORK/signing.pem" >/dev/null 2>&1
openssl pkey -in "$WORK/signing.pem" -pubout -out "$WORK/signing.pub.pem" >/dev/null 2>&1

SYSTEM_UPDATE_FORMAT=2 \
SYSTEM_UPDATE_REQUIRED_APP_VERSION=2.0.41 \
CHANNEL=preview \
SYSTEM_UPDATE_SIGNING_KEY="$WORK/signing.pem" \
SYSTEM_UPDATE_SIGNATURE_KEY_ID=hardened-system-test-v2 \
  "$ROOT/scripts/create-system-update-metadata.sh" \
  0.3.0-raw.11 hardened-system-0.3.0-raw.11 "$ARCHIVE" \
  "$WORK/meta/system-latest.json" >/dev/null

grep -Fq '"format": 2' "$WORK/meta/system-latest.json"
grep -Fq '"required_app_version": "2.0.41"' "$WORK/meta/system-latest.json"
"$ROOT/scripts/verify-system-update-metadata.sh" \
  "$WORK/meta/system-latest.json" "$WORK/meta/system-latest.json.sig" \
  "$WORK/signing.pub.pem" >/dev/null

if SYSTEM_UPDATE_FORMAT=1 \
  SYSTEM_UPDATE_REQUIRED_APP_VERSION=2.0.41 \
  "$ROOT/scripts/create-system-update-metadata.sh" \
  0.3.0-raw.11 hardened-system-0.3.0-raw.11 "$ARCHIVE" \
  "$WORK/meta/rejected-v1.json" >/dev/null 2>&1; then
  echo "metadata v1 unexpectedly accepted required_app_version" >&2
  exit 1
fi

if SYSTEM_UPDATE_FORMAT=2 \
  "$ROOT/scripts/create-system-update-metadata.sh" \
  0.3.0-raw.11 hardened-system-0.3.0-raw.11 "$ARCHIVE" \
  "$WORK/meta/rejected-v2.json" >/dev/null 2>&1; then
  echo "metadata v2 unexpectedly accepted a missing required_app_version" >&2
  exit 1
fi

printf 'system update v2 metadata/manifest/signature tests passed\n'
