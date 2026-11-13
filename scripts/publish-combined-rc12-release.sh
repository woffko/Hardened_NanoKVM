#!/usr/bin/env bash
set -euo pipefail

[ "${HARDENED_LEGACY_RC12:-}" = 1 ] || {
	echo "this is the published RC12 release helper; new releases use scripts/prepare-release.sh and scripts/publish-release.sh; set HARDENED_LEGACY_RC12=1 to run it" >&2
	exit 2
}

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REPO="${GITHUB_REPOSITORY:-woffko/Hardened_NanoKVM}"
RELEASE_TAG="${RELEASE_TAG:-hardened-system-0.3.0-raw.12}"
RELEASE_TITLE="${RELEASE_TITLE:-Hardened NanoKVM 2.0.42 RC12 + System 0.3.0 Raw 12}"
RELEASE_COMMIT="${RELEASE_COMMIT:-}"
RELEASE_DIR="${COMBINED_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build/release/combined-rc12-bridge}"
PUBLIC_KEY="${UPDATE_PUBLIC_KEY:-$ROOT_DIR/kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem}"

[ "${PUBLISH_COMBINED_RC12_RELEASE:-0}" = 1 ] || {
	echo "set PUBLISH_COMBINED_RC12_RELEASE=1 for explicit publication" >&2
	exit 1
}

[ -n "$RELEASE_COMMIT" ] || {
	echo "RELEASE_COMMIT is required" >&2
	exit 1
}
git -C "$ROOT_DIR" cat-file -e "$RELEASE_COMMIT^{commit}"
[ "$(git -C "$ROOT_DIR" rev-parse HEAD)" = "$(git -C "$ROOT_DIR" rev-parse "$RELEASE_COMMIT^{commit}")" ] || {
	echo "RELEASE_COMMIT must be the checked-out HEAD" >&2
	exit 1
}
[ -z "$(git -C "$ROOT_DIR" status --short)" ] || {
	echo "release publication requires a clean worktree" >&2
	exit 1
}
[ ! -e "$RELEASE_DIR/DRAFT_ONLY" ] || {
	echo "combined RC12 assets are marked draft-only" >&2
	exit 1
}

for command in cmp curl gh sha256sum
do
	command -v "$command" >/dev/null 2>&1 || {
		echo "required publication command is missing: $command" >&2
		exit 1
	}
done
gh auth status >/dev/null

for path in "$PUBLIC_KEY" "$RELEASE_DIR/ASSETS.tsv" "$RELEASE_DIR/SHA256SUMS" "$RELEASE_DIR/RELEASE_NOTES.md" "$RELEASE_DIR/SOURCE_COMMIT" "$RELEASE_DIR/BUILD_COMMIT"
do
	[ -f "$path" ] || {
		echo "required release file is missing: $path" >&2
		exit 1
	}
done
[ "$(cat "$RELEASE_DIR/SOURCE_COMMIT")" = "$(git -C "$ROOT_DIR" rev-parse "$RELEASE_COMMIT^{commit}")" ] || {
	echo "release assets were prepared from a different commit" >&2
	exit 1
}
git -C "$ROOT_DIR" merge-base --is-ancestor \
	"$(cat "$RELEASE_DIR/BUILD_COMMIT")" \
	"$(cat "$RELEASE_DIR/SOURCE_COMMIT")" || {
	echo "release build commit is not an ancestor of the release commit" >&2
	exit 1
}
grep -Eq 'RELEASE_BLOCKED_[A-Z0-9_]+' "$RELEASE_DIR/RELEASE_NOTES.md" && {
	echo "release notes still contain a fail-closed release blocker" >&2
	exit 1
}

(
	cd "$RELEASE_DIR"
	sha256sum -c SHA256SUMS
)
while IFS=$'\t' read -r asset bytes expected
do
	[ "$asset" != "asset" ] || continue
	[ "$(wc -c < "$RELEASE_DIR/$asset" | tr -d ' ')" = "$bytes" ]
	[ "$(sha256sum "$RELEASE_DIR/$asset" | awk '{print $1}')" = "$expected" ]
done < "$RELEASE_DIR/ASSETS.tsv"

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

VERIFY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-rc12-publish.XXXXXX")"
trap 'rm -rf "$VERIFY_DIR"' EXIT INT TERM
mkdir -p "$VERIFY_DIR/release"
gh release download "$RELEASE_TAG" --repo "$REPO" --dir "$VERIFY_DIR/release"
(
	cd "$VERIFY_DIR/release"
	sha256sum -c SHA256SUMS
)
for asset in "${assets[@]}"
do
	cmp -s "$VERIFY_DIR/release/$asset" "$RELEASE_DIR/$asset"
done

gh release upload hardened-rust-preview --repo "$REPO" --clobber \
	"$RELEASE_DIR/latest.json" \
	"$RELEASE_DIR/latest.json.sha256" \
	"$RELEASE_DIR/latest.json.sig" \
	"$RELEASE_DIR/latest.json.sig.base64"
mkdir -p "$VERIFY_DIR/app-channel"
gh release download hardened-rust-preview --repo "$REPO" --dir "$VERIFY_DIR/app-channel" \
	--pattern latest.json \
	--pattern latest.json.sig
cmp -s "$VERIFY_DIR/app-channel/latest.json" "$RELEASE_DIR/latest.json"
cmp -s "$VERIFY_DIR/app-channel/latest.json.sig" "$RELEASE_DIR/latest.json.sig"
"$ROOT_DIR/scripts/verify-update-metadata.sh" \
	"$VERIFY_DIR/app-channel/latest.json" "$VERIFY_DIR/app-channel/latest.json.sig" "$PUBLIC_KEY"

gh release upload hardened-system-preview --repo "$REPO" --clobber \
	"$RELEASE_DIR/system-latest.json" \
	"$RELEASE_DIR/system-latest.json.sha256" \
	"$RELEASE_DIR/system-latest.json.sig" \
	"$RELEASE_DIR/system-latest.json.sig.base64"
mkdir -p "$VERIFY_DIR/system-channel"
gh release download hardened-system-preview --repo "$REPO" --dir "$VERIFY_DIR/system-channel" \
	--pattern system-latest.json \
	--pattern system-latest.json.sig
cmp -s "$VERIFY_DIR/system-channel/system-latest.json" "$RELEASE_DIR/system-latest.json"
cmp -s "$VERIFY_DIR/system-channel/system-latest.json.sig" "$RELEASE_DIR/system-latest.json.sig"
"$ROOT_DIR/scripts/verify-system-update-metadata.sh" \
	"$VERIFY_DIR/system-channel/system-latest.json" \
	"$VERIFY_DIR/system-channel/system-latest.json.sig" \
	"$PUBLIC_KEY"

curl -fsSL --retry 3 \
	"https://github.com/$REPO/releases/latest/download/latest.json" \
	-o "$VERIFY_DIR/latest.json"
curl -fsSL --retry 3 \
	"https://github.com/$REPO/releases/latest/download/latest.json.sig" \
	-o "$VERIFY_DIR/latest.json.sig"
cmp -s "$VERIFY_DIR/latest.json" "$RELEASE_DIR/latest.json"
cmp -s "$VERIFY_DIR/latest.json.sig" "$RELEASE_DIR/latest.json.sig"
"$ROOT_DIR/scripts/verify-update-metadata.sh" \
	"$VERIFY_DIR/latest.json" "$VERIFY_DIR/latest.json.sig" "$PUBLIC_KEY"

gh release view "$RELEASE_TAG" --repo "$REPO" \
	--json url,tagName,name,isDraft,isPrerelease,publishedAt,targetCommitish
