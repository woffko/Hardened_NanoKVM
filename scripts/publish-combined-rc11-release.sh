#!/usr/bin/env bash
set -euo pipefail

# Superseded by the RC12 release scripts. Kept so that RC11 assets can still
# be rebuilt or republished for recovery, which must be asked for explicitly.
[ "${HARDENED_LEGACY_RC11:-}" = 1 ] || {
	echo "this is the superseded RC11 release helper; set HARDENED_LEGACY_RC11=1 to run it" >&2
	exit 2
}

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REPO="${GITHUB_REPOSITORY:-woffko/Hardened_NanoKVM}"
RELEASE_TAG="${RELEASE_TAG:-hardened-system-0.3.0-raw.10}"
RELEASE_TITLE="${RELEASE_TITLE:-Hardened NanoKVM 2.0.40 RC11 + System 0.3.0 Raw 10}"
RELEASE_COMMIT="${RELEASE_COMMIT:-}"
RELEASE_DIR="${COMBINED_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build/release/combined-rc11}"
PUBLIC_KEY="${UPDATE_PUBLIC_KEY:-$ROOT_DIR/kvmapp/system/keys/system-update-signing.pub.pem}"

[ -n "$RELEASE_COMMIT" ] || {
	echo "RELEASE_COMMIT is required" >&2
	exit 1
}
git -C "$ROOT_DIR" cat-file -e "$RELEASE_COMMIT^{commit}"
command -v gh >/dev/null 2>&1
command -v curl >/dev/null 2>&1
gh auth status >/dev/null
[ -f "$PUBLIC_KEY" ]

gh release view "$RELEASE_TAG" --repo "$REPO" >/dev/null 2>&1 && {
	echo "release already exists: $RELEASE_TAG" >&2
	exit 1
}

mapfile -t assets < <(
	awk -F '\t' 'NR > 1 && $1 != "RELEASE_NOTES.md" {print $1}' "$RELEASE_DIR/ASSETS.tsv"
)
asset_paths=()
for asset in "${assets[@]}"
do
	asset_paths+=("$RELEASE_DIR/$asset")
done

gh release create "$RELEASE_TAG" \
	--repo "$REPO" \
	--target "$RELEASE_COMMIT" \
	--title "$RELEASE_TITLE" \
	--notes-file "$RELEASE_DIR/RELEASE_NOTES.md" \
	--latest \
	"${asset_paths[@]}"

gh release upload hardened-rust-preview --repo "$REPO" --clobber \
	"$RELEASE_DIR/latest.json" \
	"$RELEASE_DIR/latest.json.sha256" \
	"$RELEASE_DIR/latest.json.sig" \
	"$RELEASE_DIR/latest.json.sig.base64"

VERIFY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-rc11-publish.XXXXXX")"
trap 'rm -rf "$VERIFY_DIR"' EXIT INT TERM
curl -fsSL --retry 3 \
	"https://github.com/$REPO/releases/latest/download/latest.json" \
	-o "$VERIFY_DIR/latest.json"
curl -fsSL --retry 3 \
	"https://github.com/$REPO/releases/latest/download/latest.json.sig" \
	-o "$VERIFY_DIR/latest.json.sig"
cmp -s "$VERIFY_DIR/latest.json" "$RELEASE_DIR/latest.json"
"$ROOT_DIR/scripts/verify-update-metadata.sh" \
	"$VERIFY_DIR/latest.json" "$VERIFY_DIR/latest.json.sig" "$PUBLIC_KEY"

gh release upload hardened-system-preview --repo "$REPO" --clobber \
	"$RELEASE_DIR/system-latest.json" \
	"$RELEASE_DIR/system-latest.json.sha256" \
	"$RELEASE_DIR/system-latest.json.sig" \
	"$RELEASE_DIR/system-latest.json.sig.base64"

gh release view "$RELEASE_TAG" --repo "$REPO" \
	--json url,tagName,name,isDraft,isPrerelease,publishedAt,targetCommitish
