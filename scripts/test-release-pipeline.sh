#!/usr/bin/env bash
# Host test for the release pipeline (M14): prepare-release.sh and
# publish-release.sh in a scratch copy of this repository, with a throwaway
# signing key, synthetic candidate files and scripts/fixtures/fake-gh.py in
# place of gh and curl. No network and no real key are used. Every refused
# case must leave the release and both channels untouched.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export TMPDIR="$T/tmp"
mkdir -p "$TMPDIR"

fail() {
	echo "release pipeline test: $*" >&2
	exit 1
}
ok() {
	echo "ok $*"
}

# A scratch repository holding the scripts, so its worktree can be dirtied.
REPO="$T/repo"
mkdir -p "$REPO"
cp -r "$ROOT/scripts" "$REPO/scripts"
git -C "$REPO" init -q
git -C "$REPO" -c user.name=test -c user.email=test@invalid add -A
git -C "$REPO" -c user.name=test -c user.email=test@invalid commit -qm fixture
BUILD_COMMIT="$(git -C "$REPO" rev-parse HEAD)"

mkdir -p "$T/bin"
for program in gh curl
do
	ln -s "$ROOT/scripts/fixtures/fake-gh.py" "$T/bin/$program"
done
export PATH="$T/bin:$PATH"

openssl genrsa -out "$T/key.pem" 2048 2>/dev/null
openssl rsa -in "$T/key.pem" -pubout -out "$T/key.pub.pem" 2>/dev/null
openssl genrsa -out "$T/other.pem" 2048 2>/dev/null

APP=2.0.43
SYSTEM=0.3.0-raw.13
mkdir -p "$T/app/kvmapp"
echo "$APP" > "$T/app/kvmapp/version"
tar -czf "$T/hardened-nanokvm-kvmapp-$APP.tar.gz" -C "$T/app" kvmapp

mkdir -p "$T/system/payload/images" "$T/system-out"
head -c 65536 /dev/urandom > "$T/rootfs.sd"
head -c 4096 /dev/urandom > "$T/boot.vfat"
gzip -c "$T/rootfs.sd" > "$T/system/payload/images/rootfs.sd.gz"
gzip -c "$T/boot.vfat" > "$T/system/payload/images/boot.vfat.gz"
sha() { sha256sum "$1" | awk '{print $1}'; }
size() { wc -c < "$1" | tr -d ' '; }
cat > "$T/system/manifest.json" <<EOF
{
  "format": "hardened-nanokvm-system-update-v2",
  "version": "$SYSTEM",
  "target": "sg2002-licheervnano-sd",
  "kernel_version": "5.10.265-tag-",
  "required_app_version": "$APP",
  "source_commit": "$(git -C "$REPO" rev-parse --short "$BUILD_COMMIT")",
  "operations": ["restore-required"],
  "raw_images": [
    {"label": "ROOTFS", "payload": "images/rootfs.sd.gz", "sha256": "$(sha "$T/rootfs.sd")"},
    {"label": "BOOT", "payload": "images/boot.vfat.gz", "sha256": "$(sha "$T/boot.vfat")"}
  ]
}
EOF
SYSTEM_ARCHIVE="$T/system-out/hardened-nanokvm-system-$SYSTEM.tar.gz"
tar -czf "$SYSTEM_ARCHIVE" -C "$T/system" manifest.json payload
CHANNEL=preview TARGET=sg2002-licheervnano-sd SYSTEM_UPDATE_FORMAT=2 \
SYSTEM_UPDATE_REQUIRED_APP_VERSION="$APP" SYSTEM_UPDATE_SIGNING_KEY="$T/key.pem" \
SYSTEM_UPDATE_SIGNATURE_KEY_ID=hardened-system-prod-2026q3 \
	"$REPO/scripts/create-system-update-metadata.sh" "$SYSTEM" "hardened-system-$SYSTEM" \
	"$SYSTEM_ARCHIVE" "$T/system-out/system-latest.json" >/dev/null
head -c 131072 /dev/urandom > "$T/sd.img"
printf 'Release notes\n' > "$T/notes.md"
printf '%s\n' "$BUILD_COMMIT" > "$T/build-commit"

good_env() {
	export RELEASE_TAG="hardened-system-$SYSTEM" APP_VERSION="$APP" SYSTEM_VERSION="$SYSTEM"
	export KERNEL_VERSION=5.10.265-tag- RAW_REQUIRED_OPERATION=restore-required
	export APP_INPUT="$T/hardened-nanokvm-kvmapp-$APP.tar.gz" APP_INPUT_SHA256
	APP_INPUT_SHA256="$(sha "$APP_INPUT")"
	export SYSTEM_INPUT_DIR="$T/system-out" SYSTEM_INPUT_SHA256
	SYSTEM_INPUT_SHA256="$(sha "$SYSTEM_ARCHIVE")"
	export ROOTFS_SHA256 ROOTFS_SIZE BOOT_SHA256 BOOT_SIZE
	ROOTFS_SHA256="$(sha "$T/rootfs.sd")" ROOTFS_SIZE="$(size "$T/rootfs.sd")"
	BOOT_SHA256="$(sha "$T/boot.vfat")" BOOT_SIZE="$(size "$T/boot.vfat")"
	export SD_INPUT="$T/sd.img" SD_INPUT_SHA256 SD_NAME="Hardened_NanoKVM_test.img.xz"
	SD_INPUT_SHA256="$(sha "$SD_INPUT")"
	export BUILD_COMMIT_FILE="$T/build-commit" NOTES_INPUT="$T/notes.md"
	export SIGNING_KEY="$T/key.pem" PUBLIC_KEY="$T/key.pub.pem"
	export OUTPUT_DIR="$T/out/release"
}

# refused_prepare NAME: prepare must fail and leave no release or stage.
refused_prepare() {
	if "$REPO/scripts/prepare-release.sh" > "$T/prepare.log" 2>&1; then
		fail "$1: prepare succeeded"
	fi
	[ ! -e "$OUTPUT_DIR" ] || fail "$1: a release directory was left"
	[ -z "$(find "$T/out" -maxdepth 1 -name '.prepare-release.*' 2>/dev/null)" ] || \
		fail "$1: a staging directory was left"
	ok "prepare refuses $1 ($(tail -n 1 "$T/prepare.log"))"
}

# flip FILE: invert one byte in place.
flip() {
	python3 -I -c 'import sys
with open(sys.argv[1], "r+b") as file:
    file.seek(40)
    byte = file.read(1)
    file.seek(40)
    file.write(bytes([byte[0] ^ 0xff]))' "$1"
}
tampered() {
	cp "$1" "$T/tampered-$(basename "$1")"
	flip "$T/tampered-$(basename "$1")"
	echo "$T/tampered-$(basename "$1")"
}

good_env
APP_INPUT="$(tampered "$APP_INPUT")" refused_prepare "a tampered app archive"
SD_INPUT="$(tampered "$SD_INPUT")" refused_prepare "a tampered SD image"
mkdir -p "$T/system-tampered"
cp "$T/system-out"/* "$T/system-tampered/"
flip "$T/system-tampered/hardened-nanokvm-system-$SYSTEM.tar.gz"
SYSTEM_INPUT_DIR="$T/system-tampered" refused_prepare "a tampered system archive"
SYSTEM_INPUT_SHA256="$(sha "$T/system-tampered/hardened-nanokvm-system-$SYSTEM.tar.gz")" \
	SYSTEM_INPUT_DIR="$T/system-tampered" refused_prepare "a system archive its metadata does not sign"
mkdir -p "$T/system-unsigned"
cp "$T/system-out"/* "$T/system-unsigned/"
rm "$T/system-unsigned/system-latest.json.sig"
SYSTEM_INPUT_DIR="$T/system-unsigned" refused_prepare "missing system signature"
SIGNING_KEY="$T/other.pem" refused_prepare "a signing key that is not the release key"
ROOTFS_SHA256="$BOOT_SHA256" refused_prepare "a raw image other than the accepted one"
: > "$T/empty.img"
SD_INPUT="$T/empty.img" SD_INPUT_SHA256="$(sha "$T/empty.img")" refused_prepare "an empty SD image"
printf 'RELEASE_BLOCKED_DEVICE_GATE\n' > "$T/blocked.md"
NOTES_INPUT="$T/blocked.md" refused_prepare "notes with a release blocker"
touch "$REPO/untracked"
refused_prepare "a dirty worktree"
rm "$REPO/untracked"

"$REPO/scripts/prepare-release.sh" > "$T/prepare.log" 2>&1 || {
	cat "$T/prepare.log" >&2
	fail "prepare failed on the accepted inputs"
}
python3 -I -B "$REPO/scripts/release-manifest.py" check "$OUTPUT_DIR" || fail "manifest check"
ok "prepare builds and checks the release"
cp -a "$OUTPUT_DIR" "$T/prepared"

# Remote state: an older latest release and both channels with old metadata.
OLD_TAG=hardened-system-0.3.0-raw.12
reset_remote() {
	export FAKE_GH_STATE="$T/remote"
	rm -rf "$FAKE_GH_STATE"
	for tag in "$OLD_TAG" hardened-rust-preview hardened-system-preview
	do
		mkdir -p "$FAKE_GH_STATE/releases/$tag/assets"
		printf '{"draft": false, "latest": %s, "target": null}' \
			"$([ "$tag" = "$OLD_TAG" ] && echo true || echo false)" \
			> "$FAKE_GH_STATE/releases/$tag/meta.json"
	done
	for file in latest.json latest.json.sha256 latest.json.sig latest.json.sig.base64
	do
		echo "old $file" > "$FAKE_GH_STATE/releases/hardened-rust-preview/assets/$file"
		echo "old $file" > "$FAKE_GH_STATE/releases/$OLD_TAG/assets/$file"
	done
	for file in system-latest.json system-latest.json.sha256 system-latest.json.sig system-latest.json.sig.base64
	do
		echo "old $file" > "$FAKE_GH_STATE/releases/hardened-system-preview/assets/$file"
	done
	: > "$FAKE_GH_STATE/log"
	rm -rf "$T/out"
	mkdir -p "$T/out"
	cp -a "$T/prepared" "$OUTPUT_DIR"
}
export PUBLISH_RELEASE=1 RELEASE_DIR="$OUTPUT_DIR" RELEASE_TITLE="Test release"
publish() {
	"$REPO/scripts/publish-release.sh" > "$T/publish.log" 2>&1
}
writes() {
	grep -cE '^gh release (create|edit|upload)' "$FAKE_GH_STATE/log" || true
}
channels_old() {
	grep -q '^old ' "$FAKE_GH_STATE/releases/hardened-rust-preview/assets/latest.json" &&
		grep -q '^old ' "$FAKE_GH_STATE/releases/hardened-system-preview/assets/system-latest.json"
}
refused_publish() {
	if publish; then
		fail "$1: publish succeeded"
	fi
	[ "$(writes)" = 0 ] || fail "$1: publish wrote to the remote"
	channels_old || fail "$1: a channel changed"
	ok "publish refuses $1 before any remote write ($(tail -n 1 "$T/publish.log"))"
}

reset_remote
echo extra > "$OUTPUT_DIR/extra.bin"
refused_publish "an extra file"
reset_remote
rm "$OUTPUT_DIR/$SD_NAME.sha256"
refused_publish "a missing asset"
reset_remote
flip "$OUTPUT_DIR/$SD_NAME"
refused_publish "a changed asset"
reset_remote
printf 'draft\n' > "$OUTPUT_DIR/DRAFT_ONLY"
refused_publish "a draft-only release"
reset_remote
git -C "$REPO" -c user.name=test -c user.email=test@invalid commit -q --allow-empty -m later
refused_publish "a release prepared from another commit"
git -C "$REPO" reset -q --hard "$BUILD_COMMIT"

# order: the remote writes and reads in the log, with the edit flags.
order() {
	awk '$1 == "curl" { print "curl"; next }
		$1 == "gh" && $2 == "release" && $3 ~ /^(create|edit|upload|download)$/ {
			line = $3 " " $4
			for (i = 5; i <= NF; i++) if ($i == "--draft" || $i == "--draft=false" || $i == "--latest") line = line " " $i
			print line
		}' "$FAKE_GH_STATE/log" | uniq
}
reset_remote
publish || {
	cat "$T/publish.log" >&2
	fail "publish failed"
}
expected="download hardened-rust-preview
download hardened-system-preview
create $RELEASE_TAG --draft
download $RELEASE_TAG
edit $RELEASE_TAG --draft=false
upload hardened-rust-preview
download hardened-rust-preview
upload hardened-system-preview
download hardened-system-preview
edit $RELEASE_TAG --latest
curl"
[ "$(order)" = "$expected" ] || {
	order >&2
	fail "unexpected publication order"
}
cmp -s "$FAKE_GH_STATE/releases/hardened-rust-preview/assets/latest.json" "$OUTPUT_DIR/latest.json" ||
	fail "the app channel was not switched"
cmp -s "$FAKE_GH_STATE/releases/hardened-system-preview/assets/system-latest.json" \
	"$OUTPUT_DIR/system-latest.json" || fail "the system channel was not switched"
grep -q '^old ' "$OUTPUT_DIR.publish/backup/app/latest.json" || fail "the app backup"
grep -q '^old ' "$OUTPUT_DIR.publish/backup/system/system-latest.json.sig" || fail "the system backup"
ok "publish drafts, verifies, publishes, switches both channels and marks latest, in order"
: > "$FAKE_GH_STATE/log"
publish || fail "a rerun after completion failed"
[ "$(writes)" = 0 ] || fail "a rerun after completion wrote again"
ok "a rerun after completion writes nothing"

reset_remote
if FAKE_GH_FAIL=create publish; then fail "a partial upload succeeded"; fi
channels_old || fail "a partial upload switched a channel"
if publish; then fail "the rerun continued from a partial draft"; fi
channels_old || fail "the rerun after a partial upload switched a channel"
[ "$(grep -c '^gh release create' "$FAKE_GH_STATE/log")" = 1 ] || fail "the partial draft was recreated"
ok "a partial draft stops before the channels, also on a rerun"

reset_remote
if FAKE_GH_CORRUPT="$SD_NAME" publish; then fail "a corrupted upload succeeded"; fi
channels_old || fail "a corrupted upload switched a channel"
ok "an asset that differs after upload stops before the channels"

reset_remote
if FAKE_GH_FAIL=edit-after publish; then fail "a lost reply succeeded"; fi
channels_old || fail "a lost reply switched a channel"
publish || {
	cat "$T/publish.log" >&2
	fail "the rerun after a lost reply failed"
}
[ "$(grep -c -- '--draft=false' "$FAKE_GH_STATE/log")" = 1 ] || fail "the publish edit was repeated"
ok "a lost reply is read back from the remote, not repeated"

reset_remote
if FAKE_GH_FAIL=upload:hardened-system-preview publish; then fail "a failed channel upload succeeded"; fi
grep -q 'previous channel files are in' "$T/publish.log" || fail "no restore hint"
cmp -s "$FAKE_GH_STATE/releases/hardened-rust-preview/assets/latest.json" "$OUTPUT_DIR/latest.json" ||
	fail "the app channel step"
publish || {
	cat "$T/publish.log" >&2
	fail "the rerun after a failed channel upload failed"
}
cmp -s "$FAKE_GH_STATE/releases/hardened-system-preview/assets/system-latest.json.sig" \
	"$OUTPUT_DIR/system-latest.json.sig" || fail "the system channel after the rerun"
[ "$(grep -c '^gh release upload hardened-rust-preview' "$FAKE_GH_STATE/log")" = 1 ] ||
	fail "the app channel was switched twice"
ok "a failed channel switch names the backup and a rerun finishes it"
echo "release pipeline test: PASS"
