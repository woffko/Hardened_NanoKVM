#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: $0 <left-root> <right-root> <report-dir>" >&2
	echo "Each root must contain kernel, external, media, runtime, buildroot, boot and recovery subdirectories." >&2
	exit 1
}

[ "$#" -eq 3 ] || usage
LEFT_ROOT="$(readlink -f "$1")"
RIGHT_ROOT="$(readlink -f "$2")"
REPORT_DIR="$(readlink -m "$3")"

for command in cmp diff find sha256sum sort readlink xargs
do
	command -v "$command" >/dev/null 2>&1 || {
		echo "required command is missing: $command" >&2
		exit 1
	}
done

[ -d "$LEFT_ROOT" ] || { echo "left reproducibility root is missing" >&2; exit 1; }
[ -d "$RIGHT_ROOT" ] || { echo "right reproducibility root is missing" >&2; exit 1; }
if [ -e "$REPORT_DIR" ]; then
	echo "refusing to reuse reproducibility report: $REPORT_DIR" >&2
	exit 1
fi
mkdir -p "$REPORT_DIR"

inventory_paths() {
	root="$1"
	shift
	(
		cd "$root"
		for relative in "$@"
		do
			[ -s "$relative" ] || {
				echo "missing or empty artifact: $root/$relative" >&2
				exit 1
			}
			sha256sum "$relative"
		done
	)
}

inventory_tree() {
	root="$1"
	(
		list="$(mktemp "$REPORT_DIR/.inventory-paths.XXXXXX")"
		trap 'rm -f "$list"' EXIT
		cd "$root"
		find . -type f -print0 | LC_ALL=C sort -z > "$list"
		[ -s "$list" ] || {
			echo "empty artifact tree: $root" >&2
			exit 1
		}
		xargs -0 -r sha256sum < "$list"
		find . -type l -printf 'SYMLINK %p -> %l\n' | LC_ALL=C sort
	)
}

require_module_set() {
	module_root="$1"
	expected_count="$2"
	module_count="$(find "$module_root" -type f -name '*.ko' -printf '.\n' | wc -l)"
	[ "$module_count" -eq "$expected_count" ] || {
		echo "incomplete module inventory: $module_root (expected $expected_count, got $module_count)" >&2
		exit 1
	}
	empty_module="$(find "$module_root" -type f -name '*.ko' -empty -print -quit)"
	[ -z "$empty_module" ] || {
		echo "empty module in inventory: $module_root" >&2
		exit 1
	}
}

compare_inventory() {
	name="$1"
	left_file="$2"
	right_file="$3"
	cmp -s "$left_file" "$right_file" || {
		diff -u "$left_file" "$right_file" > "$REPORT_DIR/$name.diff" || true
		echo "reproducibility mismatch: $name" >&2
		exit 1
	}
}

kernel_inventory() {
	root="$1"
	output="$2"
	(
		cd "$root/kernel"
		inventory_paths . \
			.config \
			Module.symvers \
			System.map \
			vmlinux \
			arch/riscv/boot/Image \
			arch/riscv/boot/dts/cvitek/sg2000_duo_sd.dtb \
			arch/riscv/boot/dts/cvitek/sg2002_duo_sd.dtb \
			arch/riscv/boot/dts/cvitek/sg2002_licheervnano_sd.dtb
		find . -type f -name '*.ko' -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
	) > "$output"
}

for candidate in "$LEFT_ROOT" "$RIGHT_ROOT"
do
	require_module_set "$candidate/kernel" 24
	require_module_set "$candidate/external/artifacts" 30
	require_module_set "$candidate/media/artifacts" 3
	require_module_set "$candidate/runtime/system/ko" 57
done

kernel_inventory "$LEFT_ROOT" "$REPORT_DIR/kernel-left.tsv"
kernel_inventory "$RIGHT_ROOT" "$REPORT_DIR/kernel-right.tsv"
compare_inventory kernel "$REPORT_DIR/kernel-left.tsv" "$REPORT_DIR/kernel-right.tsv"

inventory_tree "$LEFT_ROOT/external/artifacts" > "$REPORT_DIR/external-left.tsv"
inventory_tree "$RIGHT_ROOT/external/artifacts" > "$REPORT_DIR/external-right.tsv"
compare_inventory external "$REPORT_DIR/external-left.tsv" "$REPORT_DIR/external-right.tsv"

inventory_tree "$LEFT_ROOT/media/artifacts" > "$REPORT_DIR/media-left.tsv"
inventory_tree "$RIGHT_ROOT/media/artifacts" > "$REPORT_DIR/media-right.tsv"
compare_inventory media "$REPORT_DIR/media-left.tsv" "$REPORT_DIR/media-right.tsv"

for subtree in system kvmapp-dl-lib loaders
do
	inventory_tree "$LEFT_ROOT/runtime/$subtree" > "$REPORT_DIR/runtime-$subtree-left.tsv"
	inventory_tree "$RIGHT_ROOT/runtime/$subtree" > "$REPORT_DIR/runtime-$subtree-right.tsv"
	compare_inventory "runtime-$subtree" \
		"$REPORT_DIR/runtime-$subtree-left.tsv" \
		"$REPORT_DIR/runtime-$subtree-right.tsv"
done

inventory_paths "$LEFT_ROOT/buildroot" images/rootfs.ext2 images/rootfs.tar \
	> "$REPORT_DIR/buildroot-left.tsv"
inventory_paths "$RIGHT_ROOT/buildroot" images/rootfs.ext2 images/rootfs.tar \
	> "$REPORT_DIR/buildroot-right.tsv"
compare_inventory buildroot "$REPORT_DIR/buildroot-left.tsv" "$REPORT_DIR/buildroot-right.tsv"

inventory_paths "$LEFT_ROOT/boot" workspace/boot.itb \
	> "$REPORT_DIR/boot-left.tsv"
inventory_paths "$RIGHT_ROOT/boot" workspace/boot.itb \
	> "$REPORT_DIR/boot-right.tsv"
compare_inventory boot "$REPORT_DIR/boot-left.tsv" "$REPORT_DIR/boot-right.tsv"

inventory_paths "$LEFT_ROOT/recovery" \
	assembly/images/hardened-sg2002-port.img \
	assembly/images/hardened-sg2002-port.img.xz \
	extracted/boot.vfat \
	extracted/rootfs.sd \
	extracted-boot-files/fip.bin \
	extracted-boot-files/boot.sd \
	> "$REPORT_DIR/recovery-left.tsv"
inventory_paths "$RIGHT_ROOT/recovery" \
	assembly/images/hardened-sg2002-port.img \
	assembly/images/hardened-sg2002-port.img.xz \
	extracted/boot.vfat \
	extracted/rootfs.sd \
	extracted-boot-files/fip.bin \
	extracted-boot-files/boot.sd \
	> "$REPORT_DIR/recovery-right.tsv"
compare_inventory recovery "$REPORT_DIR/recovery-left.tsv" "$REPORT_DIR/recovery-right.tsv"

cat > "$REPORT_DIR/summary.md" <<EOF
# Linux 5.10.265 candidate reproducibility

- kernel Image, vmlinux, config, symbols, 3 DTBs and 24 modules: **exact**
- 30 external modules: **exact**
- 3 media modules: **exact**
- staged runtime payload: **exact**
- Buildroot ext4 and tar rootfs: **exact**
- boot FIT: **exact**
- full SD image, compressed image and extracted payloads: **exact**

Left: \`$LEFT_ROOT\`

Right: \`$RIGHT_ROOT\`
EOF

cat "$REPORT_DIR/summary.md"
printf 'kernel candidate reproducibility report: %s\n' "$REPORT_DIR/summary.md"
