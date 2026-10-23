#!/usr/bin/env bash
# Publish one release prepared by scripts/prepare-release.sh, in this order:
#   1. save the current app and system channel metadata and signatures;
#   2. create the release as a draft holding exactly the manifest's assets;
#   3. download the draft again and compare every asset byte for byte;
#   4. publish it, not yet marked latest;
#   5. switch the app channel, then the system channel, checking each;
#   6. mark the release latest and check the latest download URL.
# Each step is written to a receipt before and after it runs. A rerun reads
# the receipt and the remote state first: a step whose outcome is unknown is
# checked, and repeated only when its check shows it did not happen. Only the
# two channel metadata sets are ever replaced, and their previous files stay
# under the receipt directory. A device that fetches a metadata file and a
# signature of different generations fails closed on the signature.
#
# Required: PUBLISH_RELEASE=1, RELEASE_DIR, RELEASE_TITLE. Optional:
# GITHUB_REPOSITORY (woffko/Hardened_NanoKVM), PUBLIC_KEY (the production
# key), APP_CHANNEL (hardened-rust-preview), SYSTEM_CHANNEL
# (hardened-system-preview).
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REPO="${GITHUB_REPOSITORY:-woffko/Hardened_NanoKVM}"
PUBLIC_KEY="${PUBLIC_KEY:-$ROOT_DIR/kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem}"
APP_CHANNEL="${APP_CHANNEL:-hardened-rust-preview}"
SYSTEM_CHANNEL="${SYSTEM_CHANNEL:-hardened-system-preview}"
APP_FILES=(latest.json latest.json.sha256 latest.json.sig latest.json.sig.base64)
SYSTEM_FILES=(system-latest.json system-latest.json.sha256 system-latest.json.sig system-latest.json.sig.base64)

fail() {
	echo "publish-release: $*" >&2
	exit 1
}

[ "${PUBLISH_RELEASE:-0}" = 1 ] || fail "set PUBLISH_RELEASE=1 to publish"
for name in RELEASE_DIR RELEASE_TITLE
do
	[ -n "${!name:-}" ] || fail "$name is required"
done
for command in cmp curl gh git openssl python3 sha256sum
do
	command -v "$command" >/dev/null 2>&1 || fail "missing command: $command"
done

manifest() {
	python3 -I -B "$ROOT_DIR/scripts/release-manifest.py" "$@"
}
manifest check "$RELEASE_DIR" || fail "$RELEASE_DIR does not match its manifest"
TAG="$(manifest field "$RELEASE_DIR" tag)"
SOURCE_COMMIT="$(manifest field "$RELEASE_DIR" source_commit)"
BUILD_COMMIT="$(manifest field "$RELEASE_DIR" build_commit)"
MANIFEST_SHA="$(sha256sum "$RELEASE_DIR/RELEASE_MANIFEST.json" | awk '{print $1}')"
mapfile -t UPLOAD < <(
	python3 -I -c 'import json, sys
for asset in json.load(open(sys.argv[1]))["assets"]:
    print(asset["name"])' "$RELEASE_DIR/RELEASE_MANIFEST.json"
)
UPLOAD+=(RELEASE_MANIFEST.json)

[ -z "$(git -C "$ROOT_DIR" status --short)" ] || fail "a clean worktree is required"
[ "$(git -C "$ROOT_DIR" rev-parse HEAD)" = "$SOURCE_COMMIT" ] || \
	fail "the release was prepared from $SOURCE_COMMIT, not the checked-out HEAD"
git -C "$ROOT_DIR" merge-base --is-ancestor "$BUILD_COMMIT" "$SOURCE_COMMIT" || \
	fail "the build commit is not an ancestor of the release commit"
if grep -Eq 'RELEASE_BLOCKED_[A-Z0-9_]+' "$RELEASE_DIR/RELEASE_NOTES.md"; then
	fail "the release notes still name a release blocker"
fi
"$ROOT_DIR/scripts/verify-update-metadata.sh" "$RELEASE_DIR/latest.json" \
	"$RELEASE_DIR/latest.json.sig" "$PUBLIC_KEY" >/dev/null || fail "the app metadata signature"
"$ROOT_DIR/scripts/verify-system-update-metadata.sh" "$RELEASE_DIR/system-latest.json" \
	"$RELEASE_DIR/system-latest.json.sig" "$PUBLIC_KEY" >/dev/null || fail "the system metadata signature"
gh auth status >/dev/null 2>&1 || fail "gh is not authenticated"

RECEIPT_DIR="$RELEASE_DIR.publish"
RECEIPT="$RECEIPT_DIR/receipt"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-publish.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

note() {
	printf '%s\t%s\t%s\n' "$1" "$2" "$(date -u +%FT%TZ)" >> "$RECEIPT"
	sync
}

state() {
	awk -F '\t' -v step="$1" '$2 == step { last = $1 } END { print last ? last : "none" }' "$RECEIPT"
}

# Prints true or false, or absent when gh cannot show the release.
release_draft() {
	local json
	json="$(gh release view "$TAG" --repo "$REPO" --json isDraft 2>/dev/null)" || {
		echo absent
		return
	}
	python3 -I -c 'import json, sys; print(str(json.load(sys.stdin)["isDraft"]).lower())' <<<"$json"
}

# download TAG DIR [FILE...]: the named files, or every asset.
download() {
	local tag=$1 dir=$2 pattern=()
	shift 2
	for file in "$@"
	do
		pattern+=(--pattern "$file")
	done
	rm -rf "$dir"
	mkdir -p "$dir"
	gh release download "$tag" --repo "$REPO" --dir "$dir" "${pattern[@]}" >/dev/null 2>&1
}

# same DIR FILE...: DIR holds exactly these files, equal to the release's.
same() {
	local dir=$1
	shift
	[ "$(find "$dir" -mindepth 1 -printf '%f\n' | LC_ALL=C sort)" = \
		"$(printf '%s\n' "$@" | LC_ALL=C sort)" ] || return 1
	for file in "$@"
	do
		cmp -s "$dir/$file" "$RELEASE_DIR/$file" || return 1
	done
}

draft_matches() {
	[ "$(release_draft)" != absent ] && download "$TAG" "$WORK/release" && same "$WORK/release" "${UPLOAD[@]}"
}
create_draft() {
	[ "$(release_draft)" = absent ] || return 1
	local paths=()
	for asset in "${UPLOAD[@]}"
	do
		paths+=("$RELEASE_DIR/$asset")
	done
	gh release create "$TAG" --repo "$REPO" --draft --target "$SOURCE_COMMIT" \
		--title "$RELEASE_TITLE" --notes-file "$RELEASE_DIR/RELEASE_NOTES.md" "${paths[@]}"
}
published() {
	[ "$(release_draft)" = false ]
}
publish() {
	gh release edit "$TAG" --repo "$REPO" --draft=false --latest=false
}
app_switched() {
	download "$APP_CHANNEL" "$WORK/app" "${APP_FILES[@]}" && same "$WORK/app" "${APP_FILES[@]}" &&
		"$ROOT_DIR/scripts/verify-update-metadata.sh" "$WORK/app/latest.json" \
			"$WORK/app/latest.json.sig" "$PUBLIC_KEY" >/dev/null
}
switch_app() {
	gh release upload "$APP_CHANNEL" --repo "$REPO" --clobber "${APP_FILES[@]/#/$RELEASE_DIR/}"
}
system_switched() {
	download "$SYSTEM_CHANNEL" "$WORK/system" "${SYSTEM_FILES[@]}" && same "$WORK/system" "${SYSTEM_FILES[@]}" &&
		"$ROOT_DIR/scripts/verify-system-update-metadata.sh" "$WORK/system/system-latest.json" \
			"$WORK/system/system-latest.json.sig" "$PUBLIC_KEY" >/dev/null
}
switch_system() {
	gh release upload "$SYSTEM_CHANNEL" --repo "$REPO" --clobber "${SYSTEM_FILES[@]/#/$RELEASE_DIR/}"
}
is_latest() {
	local json
	json="$(gh release list --repo "$REPO" --json tagName,isLatest 2>/dev/null)" || return 1
	python3 -I -c 'import json, sys
latest = [r["tagName"] for r in json.load(sys.stdin) if r["isLatest"]]
sys.exit(0 if latest == [sys.argv[1]] else 1)' "$TAG" <<<"$json" || return 1
	curl -fsSL --retry 3 "https://github.com/$REPO/releases/latest/download/latest.json" \
		-o "$WORK/latest.json" && cmp -s "$WORK/latest.json" "$RELEASE_DIR/latest.json"
}
mark_latest() {
	gh release edit "$TAG" --repo "$REPO" --latest
}
backed_up() {
	[ -s "$RECEIPT_DIR/backup/app/latest.json.sig" ] &&
		[ -s "$RECEIPT_DIR/backup/system/system-latest.json.sig" ]
}
back_up() {
	# Never replace an earlier backup: it holds the state before this release.
	[ ! -e "$RECEIPT_DIR/backup" ] || return 1
	download "$APP_CHANNEL" "$WORK/backup/app" "${APP_FILES[@]}" &&
		download "$SYSTEM_CHANNEL" "$WORK/backup/system" "${SYSTEM_FILES[@]}" &&
		mv "$WORK/backup" "$RECEIPT_DIR/backup"
}

# step NAME CHECK ACTION: a done step is skipped; a begun step is checked and
# repeated only when its check says it did not happen. HINT follows a failure.
HINT=
step() {
	local name=$1 check=$2 action=$3
	case "$(state "$name")" in
		done) return 0 ;;
		begin)
			if "$check"; then
				note done "$name"
				return 0
			fi
			;;
	esac
	note begin "$name"
	"$action" || fail "step $name failed; rerun to inspect the remote state and continue$HINT"
	"$check" || fail "step $name did not take effect; rerun to inspect the remote state$HINT"
	note done "$name"
}

if [ -e "$RECEIPT" ]; then
	[ "$(head -n 1 "$RECEIPT")" = "$(printf 'release\t%s\t%s' "$TAG" "$MANIFEST_SHA")" ] || \
		fail "$RECEIPT belongs to another release"
else
	[ "$(release_draft)" = absent ] || fail "$TAG already exists and no receipt here created it"
	mkdir -p "$RECEIPT_DIR"
	printf 'release\t%s\t%s\n' "$TAG" "$MANIFEST_SHA" > "$RECEIPT"
fi

step backup backed_up back_up
step draft draft_matches create_draft
step publish published publish
HINT="; the previous channel files are in $RECEIPT_DIR/backup"
step app-channel app_switched switch_app
step system-channel system_switched switch_system
HINT=
step latest is_latest mark_latest
printf 'release published: %s (receipt %s)\n' "$TAG" "$RECEIPT"
