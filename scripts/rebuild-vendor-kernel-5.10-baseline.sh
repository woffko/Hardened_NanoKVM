#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build}"
KERNEL_SOURCE="$VENDOR_SDK_DIR/linux_5.10"
REFERENCE_OUTPUT="$KERNEL_SOURCE/build/sg2002_licheervnano_sd"
BOARD_DEFCONFIG="$VENDOR_SDK_DIR/build/boards/sg200x/sg2002_licheervnano_sd/linux/sg2002_licheervnano_sd_defconfig"
TOOLCHAIN_BIN="$VENDOR_SDK_DIR/host-tools/gcc/riscv64-linux-musl-x86_64/bin"
TOOLCHAIN_PREFIX="$TOOLCHAIN_BIN/riscv64-unknown-linux-musl-"
OUTPUT_DIR="${KERNEL_BASELINE_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-baseline-5.10.4-v2}"
REPORT_DIR="$OUTPUT_DIR/report"
REFERENCE_INITRAMFS_TIMESTAMP="Sun Jun 28 18:15:32 EEST 2026"
REFERENCE_COMPILE_TIMESTAMP="Mon Jun 29 11:59:04 EEST 2026"

require_file() {
    if [ ! -f "$1" ]; then
        echo "required file is missing: $1" >&2
        exit 1
    fi
}

require_dir() {
    if [ ! -d "$1" ]; then
        echo "required directory is missing: $1" >&2
        exit 1
    fi
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required command is missing: $1" >&2
        exit 1
    fi
}

require_command make
require_command python3
require_command sha256sum
require_dir "$KERNEL_SOURCE"
require_dir "$REFERENCE_OUTPUT"
require_file "$BOARD_DEFCONFIG"
require_file "${TOOLCHAIN_PREFIX}gcc"
require_file "${TOOLCHAIN_PREFIX}ld"
require_file "$REFERENCE_OUTPUT/.config"
require_file "$REFERENCE_OUTPUT/arch/riscv/boot/Image"
require_file "$REFERENCE_OUTPUT/vmlinux"

if [ -e "$OUTPUT_DIR" ]; then
    echo "refusing to reuse baseline output: $OUTPUT_DIR" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR" "$REPORT_DIR"
cp "$BOARD_DEFCONFIG" "$OUTPUT_DIR/.config"

export PATH="$TOOLCHAIN_BIN:/usr/bin:/bin"
export ARCH=riscv
export CROSS_COMPILE="$TOOLCHAIN_PREFIX"
export LOCALVERSION=-tag-
export KBUILD_BUILD_USER=w0w
export KBUILD_BUILD_HOST=w0w-PC

"${TOOLCHAIN_PREFIX}gcc" --version >"$REPORT_DIR/compiler-version.txt"
"${TOOLCHAIN_PREFIX}ld" --version >"$REPORT_DIR/linker-version.txt"
sha256sum "${TOOLCHAIN_PREFIX}gcc" "${TOOLCHAIN_PREFIX}ld" \
    >"$REPORT_DIR/toolchain-sha256.txt"

# The retained reference was built incrementally: its minimal embedded cpio
# kept the first-build timestamp while compile.h was refreshed on build 8.
# Reproduce both stages explicitly so byte comparison remains meaningful.
export KBUILD_BUILD_TIMESTAMP="$REFERENCE_INITRAMFS_TIMESTAMP"
export KBUILD_BUILD_VERSION=1
make -C "$KERNEL_SOURCE" O="$OUTPUT_DIR" olddefconfig
make -j"${KERNEL_BUILD_JOBS:-16}" -C "$KERNEL_SOURCE" O="$OUTPUT_DIR" \
    Image modules dtbs

export KBUILD_BUILD_TIMESTAMP="$REFERENCE_COMPILE_TIMESTAMP"
export KBUILD_BUILD_VERSION=8
make -j"${KERNEL_BUILD_JOBS:-16}" -C "$KERNEL_SOURCE" O="$OUTPUT_DIR" \
    Image modules dtbs

python3 - "$REFERENCE_OUTPUT" "$OUTPUT_DIR" "$REPORT_DIR" <<'PY'
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

reference = Path(sys.argv[1])
candidate = Path(sys.argv[2])
report_dir = Path(sys.argv[3])


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def inventory(root: Path, pattern: str, ignored_parts: set[str] | None = None):
    ignored_parts = ignored_parts or set()
    result: dict[str, str] = {}
    for path in sorted(root.glob(pattern)):
        relative = path.relative_to(root)
        if any(part in ignored_parts for part in relative.parts):
            continue
        result[relative.as_posix()] = digest(path)
    return result


def compare_inventory(name: str, left: dict[str, str], right: dict[str, str]):
    rows: list[str] = []
    mismatches: list[str] = []
    for path in sorted(left.keys() | right.keys()):
        left_hash = left.get(path, "missing")
        right_hash = right.get(path, "missing")
        status = "match" if left_hash == right_hash else "mismatch"
        rows.append(f"{status}\t{path}\t{left_hash}\t{right_hash}\n")
        if status != "match":
            mismatches.append(path)
    (report_dir / f"{name}.tsv").write_text("".join(rows), encoding="utf-8")
    return len(left), len(right), mismatches


single_files = (
    ".config",
    "arch/riscv/boot/Image",
    "vmlinux",
)
single_rows: list[str] = []
single_mismatches: list[str] = []
for relative in single_files:
    left = reference / relative
    right = candidate / relative
    left_hash = digest(left) if left.is_file() else "missing"
    right_hash = digest(right) if right.is_file() else "missing"
    status = "match" if left_hash == right_hash else "mismatch"
    single_rows.append(f"{status}\t{relative}\t{left_hash}\t{right_hash}\n")
    if status != "match":
        single_mismatches.append(relative)
(report_dir / "core-artifacts.tsv").write_text("".join(single_rows), encoding="utf-8")

reference_modules = inventory(reference, "**/*.ko", {"modules"})
candidate_modules = inventory(candidate, "**/*.ko", {"modules"})
ref_module_count, candidate_module_count, module_mismatches = compare_inventory(
    "in-tree-modules", reference_modules, candidate_modules
)

reference_dtbs = inventory(reference, "arch/riscv/boot/dts/cvitek/*.dtb")
candidate_dtbs = inventory(candidate, "arch/riscv/boot/dts/cvitek/*.dtb")
ref_dtb_count, candidate_dtb_count, dtb_mismatches = compare_inventory(
    "cvitek-dtbs", reference_dtbs, candidate_dtbs
)

all_mismatches = single_mismatches + module_mismatches + dtb_mismatches
summary = f"""# Vendor kernel 5.10.4 clean baseline rebuild

- reference output: `{reference}`
- isolated output: `{candidate}`
- core artifact mismatches: **{len(single_mismatches)}**
- reference/candidate in-tree modules: **{ref_module_count}/{candidate_module_count}**
- in-tree module mismatches: **{len(module_mismatches)}**
- reference/candidate CVITEK DTBs: **{ref_dtb_count}/{candidate_dtb_count}**
- CVITEK DTB mismatches: **{len(dtb_mismatches)}**
- total mismatches: **{len(all_mismatches)}**

The comparison reproduces the reference's historical two-stage metadata: its
minimal embedded cpio retained the first-build timestamp, while compile metadata
was refreshed on build 8. It also uses the original build user, host, toolchain,
and `LOCALVERSION=-tag-`. A zero mismatch result proves byte-exact reproduction
only for the listed kernel, in-tree module, and DTB artifacts; it does not cover
external `osdrv` modules or final `boot.sd` packaging. Future release builds
must use one pinned reproducible timestamp instead of this historical sequence.
"""
(report_dir / "summary.md").write_text(summary, encoding="utf-8")
print(summary)

if all_mismatches:
    print("mismatched paths:")
    for path in all_mismatches:
        print(path)
    raise SystemExit(2)
PY

echo "kernel baseline report: $REPORT_DIR/summary.md"
