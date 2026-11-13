#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build}"
KERNEL_SOURCE="${KERNEL_5_10_265_SOURCE_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-5.10.265-v1/repo}"
OUTPUT_DIR="${KERNEL_5_10_265_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-5.10.265-v1/output}"
EXPECTED_MODULE_MANIFEST="${KERNEL_5_10_265_MODULE_MANIFEST:-$ROOT_DIR/support/sg2002/kernel/5.10.265/manifests/in-tree-modules.txt}"
EXPECTED_DTB_MANIFEST="${KERNEL_5_10_265_DTB_MANIFEST:-$ROOT_DIR/support/sg2002/kernel/5.10.265/manifests/cvitek-dtbs.txt}"
BOARD_DEFCONFIG="$VENDOR_SDK_DIR/build/boards/sg200x/sg2002_licheervnano_sd/linux/sg2002_licheervnano_sd_defconfig"
TOOLCHAIN_BIN="$VENDOR_SDK_DIR/host-tools/gcc/riscv64-linux-musl-x86_64/bin"
TOOLCHAIN_PREFIX="$TOOLCHAIN_BIN/riscv64-unknown-linux-musl-"
HOST_CPP="${HOST_CPP:-/usr/bin/gcc}"
REPORT_DIR="$OUTPUT_DIR/report"
JOBS="${KERNEL_BUILD_JOBS:-16}"
EXPECTED_KERNEL_RELEASE="${EXPECTED_KERNEL_RELEASE:-5.10.265-tag-}"
CONFIG_FRAGMENT="${KERNEL_5_10_265_CONFIG_FRAGMENT:-}"
# Merged after the first fragment, so that one can stay the accepted file.
EXTRA_FRAGMENT="${KERNEL_EXTRA_CONFIG_FRAGMENT:-}"

require_file() {
	[ -f "$1" ] || {
		echo "required file is missing: $1" >&2
		exit 1
	}
}

require_dir() {
	[ -d "$1" ] || {
		echo "required directory is missing: $1" >&2
		exit 1
	}
}

for command in git make sha256sum sort cmp sed find xargs diff wc tail awk readlink cp
do
	command -v "$command" >/dev/null 2>&1 || {
		echo "required command is missing: $command" >&2
		exit 1
	}
done

case "$JOBS" in
	''|*[!0-9]*|0)
		echo "KERNEL_BUILD_JOBS must be a positive integer" >&2
		exit 1
		;;
esac

require_dir "$KERNEL_SOURCE"
require_file "$BOARD_DEFCONFIG"
require_file "$EXPECTED_MODULE_MANIFEST"
require_file "$EXPECTED_DTB_MANIFEST"
require_file "${TOOLCHAIN_PREFIX}gcc"
require_file "${TOOLCHAIN_PREFIX}ld"
require_file "$KERNEL_SOURCE/scripts/config"
require_file "$HOST_CPP"

if [ -n "$CONFIG_FRAGMENT" ]; then
	case "$CONFIG_FRAGMENT" in
	/*) ;;
	*) CONFIG_FRAGMENT="$ROOT_DIR/$CONFIG_FRAGMENT" ;;
	esac
	require_file "$CONFIG_FRAGMENT"
	CONFIG_FRAGMENT="$(readlink -f "$CONFIG_FRAGMENT")"
	config_fragment_sha256="$(sha256sum "$CONFIG_FRAGMENT" | awk '{print $1}')"
else
	config_fragment_sha256="none"
fi
if [ -n "$EXTRA_FRAGMENT" ]; then
	require_file "$EXTRA_FRAGMENT"
	EXTRA_FRAGMENT="$(readlink -f "$EXTRA_FRAGMENT")"
	config_fragment_sha256="$config_fragment_sha256+$(sha256sum "$EXTRA_FRAGMENT" | awk '{print $1}')"
fi

RISCV_TIME_SOURCE="$KERNEL_SOURCE/arch/riscv/kernel/time.c"
require_file "$RISCV_TIME_SOURCE"
of_clk_include_count="$(awk '$0 == "#include <linux/of_clk.h>" { count++ } END { print count + 0 }' \
	"$RISCV_TIME_SOURCE")"
of_clk_init_count="$(awk 'index($0, "of_clk_init(NULL);") { count++ } END { print count + 0 }' \
	"$RISCV_TIME_SOURCE")"
if [ "$of_clk_include_count" -ne 1 ] || [ "$of_clk_init_count" -ne 1 ]; then
	echo "RISC-V time_init must initialize device-tree clocks exactly once" >&2
	echo "of_clk include count: $of_clk_include_count" >&2
	echo "of_clk_init count: $of_clk_init_count" >&2
	exit 1
fi

if [ -n "$(git -C "$KERNEL_SOURCE" status --short)" ]; then
	echo "kernel candidate source is not clean" >&2
	exit 1
fi

source_commit="$(git -C "$KERNEL_SOURCE" rev-parse HEAD)"
source_tree="$(git -C "$KERNEL_SOURCE" rev-parse HEAD^{tree})"
source_timestamp="$(git -C "$KERNEL_SOURCE" show -s --format=%cI HEAD)"
merge_commit="$(git -C "$KERNEL_SOURCE" rev-list --merges --first-parent -n1 HEAD)"
stable_parent="$(git -C "$KERNEL_SOURCE" rev-parse "$merge_commit^2")"

mkdir -p "$OUTPUT_DIR" "$REPORT_DIR"
printf 'of_clk_include_count=%s\nof_clk_init_count=%s\n' \
	"$of_clk_include_count" "$of_clk_init_count" \
	> "$REPORT_DIR/riscv-time-init-audit.txt"
new_output=false
if [ -f "$REPORT_DIR/source-commit.txt" ]; then
	read -r recorded_commit < "$REPORT_DIR/source-commit.txt"
	if [ "$recorded_commit" != "$source_commit" ]; then
		echo "refusing to reuse output from kernel commit $recorded_commit" >&2
		echo "current kernel commit: $source_commit" >&2
		exit 1
	fi
else
	new_output=true
	if [ -e "$OUTPUT_DIR/.config" ]; then
		echo "unattributed kernel output already contains .config: $OUTPUT_DIR" >&2
		exit 1
	fi
	printf '%s\n' "$source_commit" > "$REPORT_DIR/source-commit.txt"
	printf '%s\n' "$source_tree" > "$REPORT_DIR/source-tree.txt"
	cp "$BOARD_DEFCONFIG" "$OUTPUT_DIR/.config"
fi

if [ -f "$REPORT_DIR/config-fragment-sha256.txt" ]; then
	read -r recorded_fragment_sha256 < "$REPORT_DIR/config-fragment-sha256.txt"
	[ "$recorded_fragment_sha256" = "$config_fragment_sha256" ] || {
		echo "refusing to reuse output with a different config fragment" >&2
		exit 1
	}
else
	[ "$new_output" = true ] || {
		echo "refusing to attribute an existing output to an unrecorded config fragment" >&2
		exit 1
	}
	printf '%s\n' "$config_fragment_sha256" > "$REPORT_DIR/config-fragment-sha256.txt"
fi

# The accepted vendor build ran from a source snapshot without Git metadata.
# Disable automatic SCM suffixes in the candidate output config and retain the
# explicit LOCALVERSION=-tag- contract without mutating the reviewed source.
if [ -n "$(tail -c 1 "$OUTPUT_DIR/.config")" ]; then
	printf '\n' >> "$OUTPUT_DIR/.config"
fi
"$KERNEL_SOURCE/scripts/config" --file "$OUTPUT_DIR/.config" \
	--disable LOCALVERSION_AUTO

export PATH="$TOOLCHAIN_BIN:/usr/bin:/bin"
export ARCH=riscv
export CROSS_COMPILE="$TOOLCHAIN_PREFIX"
export LOCALVERSION=-tag-
export KBUILD_BUILD_USER=hardened
export KBUILD_BUILD_HOST=nanokvm-builder
export KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP="$source_timestamp"
export SOURCE_DATE_EPOCH="$(git -C "$KERNEL_SOURCE" show -s --format=%ct HEAD)"

"${TOOLCHAIN_PREFIX}gcc" --version > "$REPORT_DIR/compiler-version.txt"
"${TOOLCHAIN_PREFIX}ld" --version > "$REPORT_DIR/linker-version.txt"
sha256sum "${TOOLCHAIN_PREFIX}gcc" "${TOOLCHAIN_PREFIX}ld" \
	> "$REPORT_DIR/toolchain-sha256.txt"

make -C "$KERNEL_SOURCE" O="$OUTPUT_DIR" olddefconfig

if [ "$new_output" = true ]; then
	cp "$OUTPUT_DIR/.config" "$REPORT_DIR/config-before-fragment.config"
	if [ -n "$CONFIG_FRAGMENT" ]; then
		KCONFIG_CONFIG="$OUTPUT_DIR/.config" \
			"$KERNEL_SOURCE/scripts/kconfig/merge_config.sh" \
			-m -O "$OUTPUT_DIR" "$OUTPUT_DIR/.config" "$CONFIG_FRAGMENT" ${EXTRA_FRAGMENT:+"$EXTRA_FRAGMENT"}
		make -C "$KERNEL_SOURCE" O="$OUTPUT_DIR" olddefconfig
	fi
fi

if [ -n "$CONFIG_FRAGMENT" ]; then
	while IFS= read -r requested || [ -n "$requested" ]
	do
		case "$requested" in
		''|'#'*)
			case "$requested" in
			'# CONFIG_'*' is not set') ;;
			*) continue ;;
			esac
			;;
		CONFIG_[A-Za-z0-9_]*=*) ;;
		*)
			echo "invalid kernel config fragment line: $requested" >&2
			exit 1
			;;
		esac
		grep -Fqx "$requested" "$OUTPUT_DIR/.config" || {
			echo "kernel config fragment request was not retained: $requested" >&2
			exit 1
		}
	done < <(cat "$CONFIG_FRAGMENT" ${EXTRA_FRAGMENT:+"$EXTRA_FRAGMENT"})
fi
if [ "${KERNEL_5_10_265_REQUIRE_PROC_CHILDREN:-0}" = 1 ]; then
	grep -Fqx 'CONFIG_PROC_CHILDREN=y' "$OUTPUT_DIR/.config" || {
		echo "kernel config does not enable CONFIG_PROC_CHILDREN" >&2
		exit 1
	}
	if grep -Fqx 'CONFIG_CHECKPOINT_RESTORE=y' "$OUTPUT_DIR/.config"; then
		echo "kernel config unexpectedly enables CONFIG_CHECKPOINT_RESTORE" >&2
		exit 1
	fi
fi
for required in CONFIG_IP_NF_IPTABLES=y CONFIG_IP_NF_FILTER=y CONFIG_IP_NF_MANGLE=y; do
	grep -Fqx "$required" "$OUTPUT_DIR/.config" || {
		echo "kernel lacks required firewall/AP ingress support: $required" >&2
		exit 1
	}
done
make -j"$JOBS" -C "$KERNEL_SOURCE" O="$OUTPUT_DIR" Image modules dtbs

CVITEK_DTB_DIR="$OUTPUT_DIR/arch/riscv/boot/dts/cvitek"
CVITEK_DTS_DIR="$KERNEL_SOURCE/arch/riscv/boot/dts/cvitek"
DEFAULT_DTS_DIR="$VENDOR_SDK_DIR/build/boards/default/dts/sg200x"
DTC_INCLUDE_DIR="$KERNEL_SOURCE/scripts/dtc/include-prefixes"
DTC="$OUTPUT_DIR/scripts/dtc/dtc"
BOARD_INPUT_DIR="$OUTPUT_DIR/board-inputs"
MEMMAP_SOURCE="$VENDOR_SDK_DIR/build/boards/sg200x/sg2002_licheervnano_sd/memmap.py"
MEMMAP_CONVERTER="$VENDOR_SDK_DIR/build/scripts/mmap_conv.py"
MEMMAP_HEADER="$BOARD_INPUT_DIR/cvi_board_memmap.h"
REFERENCE_MEMMAP_HEADER="${KERNEL_5_10_265_MEMMAP_REFERENCE:-$ROOT_DIR/support/sg2002/kernel/5.10.265/reference/cvi_board_memmap.h}"
NORMALIZED_REFERENCE_MEMMAP="$BOARD_INPUT_DIR/reference-cvi_board_memmap.h"
require_file "$DTC"
require_dir "$DEFAULT_DTS_DIR"
require_file "$MEMMAP_SOURCE"
require_file "$MEMMAP_CONVERTER"
require_file "$REFERENCE_MEMMAP_HEADER"
mkdir -p "$CVITEK_DTB_DIR" "$BOARD_INPUT_DIR"
"$MEMMAP_CONVERTER" --type h "$MEMMAP_SOURCE" "$MEMMAP_HEADER"
cp "$REFERENCE_MEMMAP_HEADER" "$NORMALIZED_REFERENCE_MEMMAP"
sed -i -E \
	's/__BOARD_MMAP__[0-9a-f]+__/__BOARD_MMAP__HARDENED_SG2002__/g' \
	"$MEMMAP_HEADER" "$NORMALIZED_REFERENCE_MEMMAP"
cmp -s "$MEMMAP_HEADER" "$NORMALIZED_REFERENCE_MEMMAP" || {
	echo "generated SG2002 memory-map header differs from pinned SDK output" >&2
	exit 1
}
sha256sum "$MEMMAP_SOURCE" "$MEMMAP_CONVERTER" "$MEMMAP_HEADER" \
	> "$REPORT_DIR/board-memmap-sha256.txt"
: > "$REPORT_DIR/board-dts-sha256.txt"
find "$DEFAULT_DTS_DIR" -maxdepth 1 -type f -name '*.dtsi' -print0 | \
	LC_ALL=C sort -z | xargs -0 sha256sum \
	> "$REPORT_DIR/default-board-dtsi-sha256.txt"

for board in sg2000_duo_sd sg2002_duo_sd sg2002_licheervnano_sd
do
	board_dts="$VENDOR_SDK_DIR/build/boards/sg200x/$board/dts_riscv/$board.dts"
	preprocessed="$CVITEK_DTB_DIR/.$board.dtb.dts.tmp"
	board_dtb="$CVITEK_DTB_DIR/$board.dtb"
	require_file "$board_dts"
	sha256sum "$board_dts" >> "$REPORT_DIR/board-dts-sha256.txt"
	"$HOST_CPP" -E -nostdinc \
		-I"$BOARD_INPUT_DIR" -I"$DEFAULT_DTS_DIR" \
		-I"$CVITEK_DTS_DIR" -I"$DTC_INCLUDE_DIR" \
		-undef -D__DTS__ -x assembler-with-cpp \
		-o "$preprocessed" "$board_dts"
	"$DTC" -O dtb -o "$board_dtb" -b 0 \
		-i"$DEFAULT_DTS_DIR" -i"$CVITEK_DTS_DIR" -i"$DTC_INCLUDE_DIR" \
		-Wno-interrupt_provider -Wno-unit_address_vs_reg \
		-Wno-unit_address_format -Wno-avoid_unnecessary_addr_size \
		-Wno-alias_paths -Wno-graph_child_address \
		-Wno-simple_bus_reg -Wno-unique_unit_address \
		-Wno-pci_device_reg "$preprocessed"
done

kernel_release="$(make -s -C "$KERNEL_SOURCE" O="$OUTPUT_DIR" kernelrelease)"
if [ "$kernel_release" != "$EXPECTED_KERNEL_RELEASE" ]; then
	echo "unexpected kernel release: $kernel_release" >&2
	exit 1
fi
printf '%s\n' "$kernel_release" > "$REPORT_DIR/kernel-release.txt"

for path in \
	"$OUTPUT_DIR/arch/riscv/boot/Image" \
	"$OUTPUT_DIR/vmlinux" \
	"$OUTPUT_DIR/Module.symvers" \
	"$OUTPUT_DIR/arch/riscv/boot/dts/cvitek/sg2002_licheervnano_sd.dtb"
do
	require_file "$path"
done

cp "$EXPECTED_MODULE_MANIFEST" "$REPORT_DIR/expected-in-tree-modules.txt"
find "$OUTPUT_DIR" -type f -name '*.ko' -printf '%P\n' | LC_ALL=C sort \
	> "$REPORT_DIR/built-in-tree-modules.txt"
cmp -s "$REPORT_DIR/expected-in-tree-modules.txt" \
	"$REPORT_DIR/built-in-tree-modules.txt" || {
	echo "kernel in-tree module inventory differs from the accepted baseline" >&2
	diff -u "$REPORT_DIR/expected-in-tree-modules.txt" \
		"$REPORT_DIR/built-in-tree-modules.txt" >&2 || true
	exit 1
}

cp "$EXPECTED_DTB_MANIFEST" "$REPORT_DIR/expected-dtbs.txt"
find "$OUTPUT_DIR/arch/riscv/boot/dts/cvitek" -maxdepth 1 -type f \
	-name '*.dtb' -printf '%f\n' | LC_ALL=C sort > "$REPORT_DIR/built-dtbs.txt"
cmp -s "$REPORT_DIR/expected-dtbs.txt" "$REPORT_DIR/built-dtbs.txt" || {
	echo "CVITEK DTB inventory differs from the accepted baseline" >&2
	diff -u "$REPORT_DIR/expected-dtbs.txt" "$REPORT_DIR/built-dtbs.txt" >&2 || true
	exit 1
}

sha256sum \
	"$OUTPUT_DIR/.config" \
	"$OUTPUT_DIR/arch/riscv/boot/Image" \
	"$OUTPUT_DIR/vmlinux" \
	"$OUTPUT_DIR/Module.symvers" \
	"$OUTPUT_DIR"/arch/riscv/boot/dts/cvitek/*.dtb \
	> "$REPORT_DIR/core-sha256.txt"
find "$OUTPUT_DIR" -type f -name '*.ko' -print0 | LC_ALL=C sort -z | \
	xargs -0 sha256sum > "$REPORT_DIR/in-tree-module-sha256.txt"
require_file "$REPORT_DIR/config-before-fragment.config"
diff -u "$REPORT_DIR/config-before-fragment.config" "$OUTPUT_DIR/.config" \
	> "$REPORT_DIR/config-hardening.diff" || true

if [ -n "$(git -C "$KERNEL_SOURCE" status --short)" ]; then
	echo "kernel build modified the clean source worktree" >&2
	exit 1
fi

cat > "$REPORT_DIR/summary.md" <<EOF
# SG2002 Linux $kernel_release recovery candidate build

- source commit: \`$source_commit\`
- source tree: \`$source_tree\`
- config fragment SHA-256: \`$config_fragment_sha256\`
- kernel release: \`$kernel_release\`
- signed stable parent: \`$stable_parent\`
- in-tree module inventory: **$(wc -l < "$REPORT_DIR/built-in-tree-modules.txt")/$(wc -l < "$REPORT_DIR/expected-in-tree-modules.txt") match**
- CVITEK DTB inventory: **$(wc -l < "$REPORT_DIR/built-dtbs.txt")/$(wc -l < "$REPORT_DIR/expected-dtbs.txt") match**
- source worktree mutation: **none**

This is a local recovery-media candidate. It has not been installed on a
device and must not be deployed first through a raw partition update.
EOF

cat "$REPORT_DIR/summary.md"
printf 'kernel candidate report: %s\n' "$REPORT_DIR/summary.md"
