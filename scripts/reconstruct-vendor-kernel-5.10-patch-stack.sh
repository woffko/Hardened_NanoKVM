#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
HISTORY_REPO="${KERNEL_HISTORY_REPO:-$ROOT_DIR/build/latestbuildroot/kernel-history/milkv-duo-buildroot-sdk}"
SIPEED_METADATA_REPO="${SIPEED_KERNEL_HISTORY_REPO:-$ROOT_DIR/build/latestbuildroot/kernel-history/sipeed-licheerv-nano-build}"
OUTPUT_DIR="${KERNEL_PATCH_STACK_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-patch-stack-5.10.4-v1}"
PATCH_DIR="$OUTPUT_DIR/patches"
REPORT_DIR="$OUTPUT_DIR/report"
WORKTREE="$OUTPUT_DIR/reconstructed"

OFFICIAL_REF="refs/remotes/official/v5.10.4-tar"
MILKV_IMPORT="5c7dd7acc3624737c37e5db9390f5d24db6e9457"
MILKV_NEAREST="303ec5da3ba7e806720f255be57ce210f1a5188f"
SIPEED_INITIAL="bd39c05f39ab6d850d7c2c29a6b5ac617efc698a"
SIPEED_PINNED="d88d58feca49ef15f4cc7bd1f27dbf17dc25f85e"

require_command() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "required command is missing: $1" >&2
		exit 1
	}
}

require_repo() {
	git -C "$1" rev-parse --git-dir >/dev/null 2>&1 || {
		echo "required Git repository is missing: $1" >&2
		exit 1
	}
}

require_command git
require_command sha256sum
require_repo "$HISTORY_REPO"
require_repo "$SIPEED_METADATA_REPO"

if [ -e "$OUTPUT_DIR" ]; then
	echo "refusing to overwrite kernel patch-stack output: $OUTPUT_DIR" >&2
	exit 1
fi

for object in \
	"$OFFICIAL_REF^{commit}" \
	"$MILKV_IMPORT^{commit}" \
	"$MILKV_NEAREST^{commit}" \
	"$SIPEED_INITIAL^{commit}" \
	"$SIPEED_PINNED^{commit}"
do
	git -C "$HISTORY_REPO" cat-file -e "$object"
done

mkdir -p "$PATCH_DIR" "$REPORT_DIR"
git -C "$HISTORY_REPO" worktree add --detach "$WORKTREE" "$OFFICIAL_REF"
git -C "$WORKTREE" config user.name "Hardened NanoKVM kernel reconstruction"
git -C "$WORKTREE" config user.email "noreply@local"

MANIFEST="$REPORT_DIR/manifest.tsv"
printf 'index\tkind\tsource_commit\tfrom_tree\tto_tree\tchanged_paths\tpatch_sha256\tpatch\tsubject\n' > "$MANIFEST"

layer_index=0

subject_for() {
	repo="$1"
	commit="$2"
	git -C "$repo" show -s --format=%s "$commit" 2>/dev/null || printf 'source snapshot %s' "$commit"
}

apply_layer() {
	kind="$1"
	source_commit="$2"
	from_tree="$3"
	to_tree="$4"
	metadata_repo="$5"

	layer_index=$((layer_index + 1))
	short_commit="$(printf '%s' "$source_commit" | cut -c1-12)"
	patch_name="$(printf '%03d-%s-%s.patch' "$layer_index" "$kind" "$short_commit")"
	patch_path="$PATCH_DIR/$patch_name"
	subject="$(subject_for "$metadata_repo" "$source_commit")"

	git -C "$HISTORY_REPO" diff --binary --full-index --no-renames \
		"$from_tree" "$to_tree" > "$patch_path"
	[ -s "$patch_path" ] || {
		echo "empty layer patch: $kind $source_commit" >&2
		exit 1
	}

	changed_paths="$(git -C "$HISTORY_REPO" diff --name-only --no-renames \
		"$from_tree" "$to_tree" | wc -l | tr -d ' ')"
	patch_sha256="$(sha256sum "$patch_path" | awk '{print $1}')"

	git -C "$WORKTREE" apply --index --binary --whitespace=nowarn "$patch_path"
	actual_tree="$(git -C "$WORKTREE" write-tree)"
	[ "$actual_tree" = "$to_tree" ] || {
		echo "tree mismatch after layer $layer_index: $kind $source_commit" >&2
		echo "expected: $to_tree" >&2
		echo "actual:   $actual_tree" >&2
		exit 1
	}

	git -C "$WORKTREE" commit -q -m "$kind $source_commit" -m "$subject"
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$layer_index" "$kind" "$source_commit" "$from_tree" "$to_tree" \
		"$changed_paths" "$patch_sha256" "$patch_name" "$subject" >> "$MANIFEST"
}

official_tree="$(git -C "$HISTORY_REPO" rev-parse "$OFFICIAL_REF^{tree}")"
milkv_import_tree="$(git -C "$HISTORY_REPO" rev-parse "$MILKV_IMPORT:linux_5.10")"
apply_layer "milkv-import" "$MILKV_IMPORT" "$official_tree" "$milkv_import_tree" "$HISTORY_REPO"

previous_commit="$MILKV_IMPORT"
previous_tree="$milkv_import_tree"
mapfile -t milkv_commits < <(
	git -C "$HISTORY_REPO" rev-list --reverse --first-parent \
		"$MILKV_IMPORT^..$MILKV_NEAREST" -- linux_5.10
)
for commit in "${milkv_commits[@]}"
do
	[ "$commit" = "$MILKV_IMPORT" ] && continue
	tree="$(git -C "$HISTORY_REPO" rev-parse "$commit:linux_5.10")"
	apply_layer "milkv" "$commit" "$previous_tree" "$tree" "$HISTORY_REPO"
	previous_commit="$commit"
	previous_tree="$tree"
done
[ "$previous_commit" = "$MILKV_NEAREST" ]

sipeed_initial_tree="$(git -C "$HISTORY_REPO" rev-parse "$SIPEED_INITIAL:linux_5.10")"
expected_tree="$(git -C "$HISTORY_REPO" rev-parse "$SIPEED_PINNED:linux_5.10")"
apply_layer "sipeed-import-gap" "$SIPEED_INITIAL" "$previous_tree" \
	"$sipeed_initial_tree" "$SIPEED_METADATA_REPO"

previous_commit="$SIPEED_INITIAL"
previous_tree="$sipeed_initial_tree"
mapfile -t sipeed_commits < <(
	git -C "$HISTORY_REPO" rev-list --reverse --first-parent \
		"$SIPEED_INITIAL^..$SIPEED_PINNED" -- linux_5.10
)
for commit in "${sipeed_commits[@]}"
do
	[ "$commit" = "$SIPEED_INITIAL" ] && continue
	tree="$(git -C "$HISTORY_REPO" rev-parse "$commit:linux_5.10")"
	apply_layer "sipeed" "$commit" "$previous_tree" "$tree" "$SIPEED_METADATA_REPO"
	previous_commit="$commit"
	previous_tree="$tree"
done
[ "$previous_tree" = "$expected_tree" ] || {
	echo "last Sipeed kernel-changing commit does not reproduce the pinned SDK tree" >&2
	exit 1
}

actual_tree="$(git -C "$WORKTREE" write-tree)"
[ "$actual_tree" = "$expected_tree" ] || {
	echo "final reconstructed tree mismatch" >&2
	exit 1
}

git -C "$WORKTREE" log --reverse --format='%H%x09%s' > "$REPORT_DIR/reconstructed-history.tsv"
sha256sum "$PATCH_DIR"/*.patch > "$REPORT_DIR/patches-sha256.txt"

milkv_layers="$(awk -F '\t' 'NR > 1 && ($2 == "milkv-import" || $2 == "milkv") {n++} END {print n+0}' "$MANIFEST")"
sipeed_layers="$(awk -F '\t' 'NR > 1 && ($2 == "sipeed-import-gap" || $2 == "sipeed") {n++} END {print n+0}' "$MANIFEST")"
total_changed_paths="$(awk -F '\t' 'NR > 1 {n += $6} END {print n+0}' "$MANIFEST")"

cat > "$REPORT_DIR/summary.md" <<EOF
# Vendor kernel 5.10.4 patch-stack reconstruction

- official archive tree: \`$official_tree\`
- Milk-V import commit: \`$MILKV_IMPORT\`
- nearest Milk-V snapshot: \`$MILKV_NEAREST\`
- first Sipeed snapshot: \`$SIPEED_INITIAL\`
- pinned Sipeed SDK commit: \`$SIPEED_PINNED\`
- reconstructed final tree: \`$actual_tree\`
- expected pinned tree: \`$expected_tree\`
- Milk-V layers including import normalization: **$milkv_layers**
- Sipeed layers including the import gap: **$sipeed_layers**
- total patch layers: **$layer_index**
- sum of per-layer changed paths: **$total_changed_paths**

Every patch was applied to the preceding exact tree and checked with
\`git write-tree\`. The final reconstructed tree is byte-and-mode identical to
the pinned \`linux_5.10\` subtree. This proves source reconstruction only; it
does not prove that an upstream stable merge is conflict-free or hardware-safe.
EOF

cat "$REPORT_DIR/summary.md"
printf 'kernel patch-stack report: %s\n' "$REPORT_DIR/summary.md"
