#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REPO="${GITHUB_REPOSITORY:-woffko/Hardened_NanoKVM}"
RELEASE_TAG="${RELEASE_TAG:-hardened-rust-2.0.42-key-transition}"
RELEASE_TITLE="${RELEASE_TITLE:-Hardened NanoKVM 2.0.42 Manual Key Transition}"
RELEASE_COMMIT="${RELEASE_COMMIT:-}"
RELEASE_DIR="${KEY_TRANSITION_RELEASE_OUTPUT_DIR:-$ROOT_DIR/build/release/key-transition-2.0.42}"

[ "${PUBLISH_KEY_TRANSITION_RELEASE:-0}" = 1 ] || {
	echo "set PUBLISH_KEY_TRANSITION_RELEASE=1 for explicit publication" >&2
	exit 1
}
[ -n "$RELEASE_COMMIT" ] || {
	echo "RELEASE_COMMIT is required" >&2
	exit 1
}
[ "$(git -C "$ROOT_DIR" rev-parse HEAD)" = "$(git -C "$ROOT_DIR" rev-parse "$RELEASE_COMMIT^{commit}")" ] || {
	echo "RELEASE_COMMIT must be checked-out HEAD" >&2
	exit 1
}
[ -z "$(git -C "$ROOT_DIR" status --short)" ] || {
	echo "transition publication requires a clean worktree" >&2
	exit 1
}
[ ! -e "$RELEASE_DIR/DRAFT_ONLY" ] || {
	echo "transition assets are marked draft-only" >&2
	exit 1
}
for command in cmp gh sha256sum
do
	command -v "$command" >/dev/null 2>&1 || {
		echo "required publication command is missing: $command" >&2
		exit 1
	}
done
for path in "$RELEASE_DIR/ASSETS.tsv" "$RELEASE_DIR/SHA256SUMS" "$RELEASE_DIR/RELEASE_NOTES.md" "$RELEASE_DIR/SOURCE_COMMIT" "$RELEASE_DIR/RELEASE_TAG"
do
	[ -f "$path" ] || {
		echo "required transition release file is missing: $path" >&2
		exit 1
	}
done
[ "$(cat "$RELEASE_DIR/SOURCE_COMMIT")" = "$(git -C "$ROOT_DIR" rev-parse "$RELEASE_COMMIT^{commit}")" ]
[ "$(cat "$RELEASE_DIR/RELEASE_TAG")" = "$RELEASE_TAG" ]
grep -Eq 'TRANSITION_RELEASE_BLOCKED_[A-Z0-9_]+' "$RELEASE_DIR/RELEASE_NOTES.md" && {
	echo "transition notes still contain a fail-closed blocker" >&2
	exit 1
}
(
	cd "$RELEASE_DIR"
	sha256sum -c SHA256SUMS
)
gh auth status >/dev/null
gh release view "$RELEASE_TAG" --repo "$REPO" >/dev/null 2>&1 && {
	echo "transition release already exists: $RELEASE_TAG" >&2
	exit 1
}
mapfile -t assets < <(awk -F '\t' 'NR > 1 && $1 != "RELEASE_NOTES.md" {print $1}' "$RELEASE_DIR/ASSETS.tsv")
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
	--prerelease \
	"${asset_paths[@]}"

verify_dir="$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-transition-publish.XXXXXX")"
trap 'rm -rf "$verify_dir"' EXIT INT TERM
gh release download "$RELEASE_TAG" --repo "$REPO" --dir "$verify_dir"
(
	cd "$verify_dir"
	sha256sum -c SHA256SUMS
)
for asset in "${assets[@]}"
do
	cmp -s "$verify_dir/$asset" "$RELEASE_DIR/$asset"
done
gh release view "$RELEASE_TAG" --repo "$REPO" \
	--json url,tagName,name,isDraft,isPrerelease,publishedAt,targetCommitish
