#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
STABLE_REPO="${KERNEL_5_10_STABLE_REPO:-$ROOT_DIR/build/latestbuildroot/kernel-stable-5.10-rehydrate}"
VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-$ROOT_DIR/build/vendor/LicheeRV-Nano-Build}"
OUTPUT_DIR="${KERNEL_5_10_265_REHYDRATE_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-5.10.265-v1}"
REPO="$OUTPUT_DIR/repo"
REPORT_DIR="$OUTPUT_DIR/rehydrate-report"
PATCH_DIR="$ROOT_DIR/support/sg2002/kernel/5.10.265/patches"

VENDOR_SDK_COMMIT="d88d58feca49ef15f4cc7bd1f27dbf17dc25f85e"
VENDOR_KERNEL_TREE="a5854bd362b88c59d34bd4db9ff9ea876c6aebd4"
STABLE_5_10_4_COMMIT="b1313fe517ca3703119dcc99ef3bbf75ab42bcfb"
STABLE_5_10_265_COMMIT="2a3da1f4966798b0b48ce302944ad356b2c98b5d"
FINAL_SOURCE_TREE="d53dfbde34f1de6b4565e686009b688c04b8913d"

runtime_conflicts=(
	arch/riscv/Kconfig
	arch/riscv/Makefile
	arch/riscv/configs/defconfig
	arch/riscv/include/asm/pgtable-64.h
	arch/riscv/include/asm/thread_info.h
	arch/riscv/kernel/entry.S
	arch/riscv/kernel/patch.c
	arch/riscv/kernel/stacktrace.c
	arch/riscv/kernel/vdso/Makefile
	arch/riscv/mm/fault.c
	arch/riscv/mm/init.c
	drivers/i2c/i2c-dev.c
	drivers/net/ethernet/stmicro/stmmac/stmmac_platform.c
	drivers/staging/fbtft/fbtft-core.c
	drivers/usb/dwc2/core_intr.c
	drivers/usb/dwc2/gadget.c
	drivers/usb/dwc2/hcd.c
	drivers/usb/dwc2/hcd_queue.c
	drivers/usb/dwc2/platform.c
	drivers/usb/gadget/function/f_hid.c
	drivers/usb/gadget/function/u_hid.h
	drivers/usb/gadget/udc/core.c
	drivers/usb/host/xhci.c
	include/linux/mmc/card.h
	include/linux/netdevice.h
	kernel/module.c
	net/core/dev_ioctl.c
	net/ethtool/ioctl.c
	net/socket.c
)

selftest_conflicts=(
	tools/testing/selftests/bpf/test_progs.c
	tools/testing/selftests/bpf/test_progs.h
)

die() {
	echo "$*" >&2
	exit 1
}

for command in git mkdir sort cmp wc tar find sha256sum awk
do
	command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"
done

git -C "$STABLE_REPO" rev-parse --git-dir >/dev/null 2>&1 || \
	die "stable Git repository is missing: $STABLE_REPO"
git -C "$VENDOR_SDK_DIR" rev-parse --git-dir >/dev/null 2>&1 || \
	die "vendor SDK Git repository is missing: $VENDOR_SDK_DIR"
[ -d "$PATCH_DIR" ] || die "kernel resolution patch directory is missing: $PATCH_DIR"
[ ! -e "$OUTPUT_DIR" ] || die "refusing to reuse rehydration output: $OUTPUT_DIR"

mapfile -t resolution_patches < <(
	find "$PATCH_DIR" -maxdepth 1 -type f -name '*.patch' -print | LC_ALL=C sort
)
[ "${#resolution_patches[@]}" -eq 9 ] || \
	die "expected exactly nine tracked kernel resolution patches"

[ "$(git -C "$VENDOR_SDK_DIR" rev-parse HEAD)" = "$VENDOR_SDK_COMMIT" ] || \
	die "vendor SDK commit does not match the pin"
[ "$(git -C "$VENDOR_SDK_DIR" rev-parse HEAD:linux_5.10)" = "$VENDOR_KERNEL_TREE" ] || \
	die "vendor kernel snapshot tree does not match the pin"
[ "$(git -C "$STABLE_REPO" rev-parse 'v5.10.4^{}')" = "$STABLE_5_10_4_COMMIT" ] || \
	die "v5.10.4 commit does not match the pin"
[ "$(git -C "$STABLE_REPO" rev-parse 'v5.10.265^{}')" = "$STABLE_5_10_265_COMMIT" ] || \
	die "v5.10.265 commit does not match the pin"

mkdir -p "$OUTPUT_DIR" "$REPORT_DIR"
git -C "$STABLE_REPO" worktree prune
git -C "$STABLE_REPO" worktree add --detach "$REPO" 'v5.10.4^{}'
git -C "$REPO" config user.name "Hardened NanoKVM kernel port"
git -C "$REPO" config user.email "noreply@local"
git -C "$REPO" rm -r -q -- .
git -C "$VENDOR_SDK_DIR" archive "$VENDOR_SDK_COMMIT:linux_5.10" | \
	tar -xf - -C "$REPO"
git -C "$REPO" add -A
[ "$(git -C "$REPO" write-tree)" = "$VENDOR_KERNEL_TREE" ] || \
	die "vendor worktree does not match the pinned tree"
git -C "$REPO" commit -m "Import exact SG2002 vendor kernel on Linux v5.10.4"
vendor_commit="$(git -C "$REPO" rev-parse HEAD)"

expected_conflicts="$REPORT_DIR/expected-conflicts.txt"
actual_conflicts="$REPORT_DIR/actual-conflicts.txt"
printf '%s\n' "${runtime_conflicts[@]}" "${selftest_conflicts[@]}" | \
	LC_ALL=C sort > "$expected_conflicts"

start_expected_conflict_merge() {
	worktree="$1"
	if git -C "$worktree" merge --no-commit --no-ff v5.10.265; then
		die "stable merge unexpectedly completed without the reviewed conflicts"
	fi
	git -C "$worktree" diff --name-only --diff-filter=U | LC_ALL=C sort > "$actual_conflicts"
	cmp "$expected_conflicts" "$actual_conflicts" || \
		die "stable merge conflict inventory changed"
}

start_expected_conflict_merge "$REPO"
git -C "$REPO" checkout --ours -- "${runtime_conflicts[@]}"
git -C "$REPO" checkout --theirs -- "${selftest_conflicts[@]}"
git -C "$REPO" add -- "${runtime_conflicts[@]}" "${selftest_conflicts[@]}"
[ -z "$(git -C "$REPO" diff --name-only --diff-filter=U)" ] || \
	die "initial merge still contains unresolved paths"
git -C "$REPO" commit \
	-m "Merge Linux v5.10.265 with bounded vendor conflict review" \
	-m "Create the signed-stable merge parent while retaining the vendor side only for the 29 runtime conflicts and the stable side for two BPF selftest conflicts. Reviewed subsystem resolutions are applied as follow-up commits."
initial_merge_commit="$(git -C "$REPO" rev-parse HEAD)"

git -C "$REPO" am --committer-date-is-author-date "${resolution_patches[@]}"
final_source_commit="$(git -C "$REPO" rev-parse HEAD)"
final_source_tree="$(git -C "$REPO" rev-parse HEAD^{tree})"
[ "$final_source_tree" = "$FINAL_SOURCE_TREE" ] || \
	die "rehydrated final source tree does not match the accepted tree"
[ -z "$(git -C "$REPO" status --short)" ] || \
	die "rehydrated final source worktree is not clean"

printf '%s\n' "$VENDOR_SDK_COMMIT" > "$REPORT_DIR/vendor-sdk-commit.txt"
printf '%s\n' "$VENDOR_KERNEL_TREE" > "$REPORT_DIR/vendor-kernel-tree.txt"
printf '%s\n' "$vendor_commit" > "$REPORT_DIR/vendor-import-commit.txt"
printf '%s\n' "$STABLE_5_10_4_COMMIT" > "$REPORT_DIR/stable-5.10.4-commit.txt"
printf '%s\n' "$STABLE_5_10_265_COMMIT" > "$REPORT_DIR/stable-5.10.265-commit.txt"
printf '%s\n' "$initial_merge_commit" > "$REPORT_DIR/initial-merge-commit.txt"
printf '%s\n' "$final_source_commit" > "$REPORT_DIR/final-source-commit.txt"
printf '%s\n' "$final_source_tree" > "$REPORT_DIR/final-source-tree.txt"
sha256sum "${resolution_patches[@]}" > "$REPORT_DIR/resolution-patches-sha256.txt"

cat <<EOF
vendor tree rehydrated: $VENDOR_KERNEL_TREE
initial stable merge: $initial_merge_commit
reviewed conflict inventory: $(wc -l < "$actual_conflicts")
tracked resolution patches: ${#resolution_patches[@]}
final source commit: $final_source_commit
final source tree: $final_source_tree
EOF
