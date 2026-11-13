#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-$ROOT_DIR/build/vendor/LicheeRV-Nano-Build}"
OSDRV_COMMIT="aa542c41df94f7bc656cb740f6622a5dca7dc403"
SOURCE_REPO="${SOPHGO_OSDRV_SOURCE_DIR:-$ROOT_DIR/build/latestbuildroot/sophgo-osdrv-$OSDRV_COMMIT}"
KERNEL_DIR="${SOPHGO_MEDIA_KERNEL_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-baseline-5.10.4-v2}"
OUTPUT_DIR="${SOPHGO_MEDIA_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/sophgo-media-modules-5.10.4-v2}"
WORKTREE_DIR="$OUTPUT_DIR/osdrv"
ARTIFACT_DIR="$OUTPUT_DIR/artifacts"
REPORT_DIR="$OUTPUT_DIR/report"
PATCH_FILE="$ROOT_DIR/buildroot-external/hardened-sg2002/board/sg2002/kernel/patches/sophgo-osdrv-legacy-module-names.patch"
KERNEL_COMPAT_PATCH="${SOPHGO_MEDIA_KERNEL_COMPAT_PATCH:-}"
EXPECTED_JPEG_SRCVERSION="${SOPHGO_MEDIA_EXPECTED_JPEG_SRCVERSION:-625882D05A26BB4B2FD9A6E}"
EXTRA_KCFLAGS="${SOPHGO_MEDIA_KCFLAGS:-}"
TOOLCHAIN_BIN="$VENDOR_SDK_DIR/host-tools/gcc/riscv64-linux-musl-x86_64/bin"
BASE_SYMVERS="${SOPHGO_MEDIA_BASE_SYMVERS:-$VENDOR_SDK_DIR/osdrv/interdrv/v2/base/Module.symvers}"
SYS_SYMVERS="${SOPHGO_MEDIA_SYS_SYMVERS:-$VENDOR_SDK_DIR/osdrv/interdrv/v2/sys/Module.symvers}"

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

for command_name in git make modinfo sha256sum; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "required command is missing: $command_name" >&2
        exit 1
    fi
done

require_dir "$SOURCE_REPO"
require_dir "$KERNEL_DIR"
require_file "$PATCH_FILE"
if [ -n "$KERNEL_COMPAT_PATCH" ]; then
    require_file "$KERNEL_COMPAT_PATCH"
fi
require_file "$KERNEL_DIR/include/generated/utsrelease.h"
require_file "$BASE_SYMVERS"
require_file "$SYS_SYMVERS"
require_file "$TOOLCHAIN_BIN/riscv64-unknown-linux-musl-gcc"

if [ -e "$OUTPUT_DIR" ]; then
    echo "refusing to reuse media-module output: $OUTPUT_DIR" >&2
    exit 1
fi

actual_source_commit="$(git -C "$SOURCE_REPO" rev-parse HEAD)"
if [ "$actual_source_commit" != "$OSDRV_COMMIT" ]; then
    echo "unexpected SOPHGO osdrv source commit: $actual_source_commit" >&2
    exit 1
fi
if [ -n "$(git -C "$SOURCE_REPO" status --short)" ]; then
    echo "SOPHGO osdrv source checkout is not clean" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR" "$ARTIFACT_DIR" "$REPORT_DIR"
git -C "$SOURCE_REPO" worktree prune --expire now
git -C "$SOURCE_REPO" worktree add --detach "$WORKTREE_DIR" "$OSDRV_COMMIT"
git -C "$WORKTREE_DIR" apply --check "$PATCH_FILE"
git -C "$WORKTREE_DIR" apply "$PATCH_FILE"
if [ -n "$KERNEL_COMPAT_PATCH" ]; then
    git -C "$WORKTREE_DIR" apply --check "$KERNEL_COMPAT_PATCH"
    git -C "$WORKTREE_DIR" apply "$KERNEL_COMPAT_PATCH"
fi

cp "$BASE_SYMVERS" "$WORKTREE_DIR/interdrv/base/Module.symvers"
cp "$SYS_SYMVERS" "$WORKTREE_DIR/interdrv/sys/Module.symvers"

export PATH="$TOOLCHAIN_BIN:/usr/sbin:/usr/bin:/sbin:/bin"
export ARCH=riscv
export CROSS_COMPILE=riscv64-unknown-linux-musl-
export CVIARCH=CV181X
export CVIARCH_L=cv181x
export SDK_VER=musl_riscv64

build_module() {
    module_dir="$WORKTREE_DIR/interdrv/$1"
    make -C "$module_dir" \
        PWD="$module_dir" \
        KERNEL_DIR="$KERNEL_DIR" \
        ARCH="$ARCH" \
        CROSS_COMPILE="$CROSS_COMPILE" \
        KCFLAGS="$EXTRA_KCFLAGS" \
        CVIARCH="$CVIARCH" \
        CVIARCH_L="$CVIARCH_L" \
        SDK_VER="$SDK_VER" \
        all
}

build_module vcodec
build_module jpeg
build_module cvi_vc_drv

for artifact in \
    "$WORKTREE_DIR/interdrv/vcodec/soph_vcodec.ko" \
    "$WORKTREE_DIR/interdrv/jpeg/soph_jpeg.ko" \
    "$WORKTREE_DIR/interdrv/cvi_vc_drv/soph_vc_driver.ko"; do
    require_file "$artifact"
    cp "$artifact" "$ARTIFACT_DIR/"
done

kernel_release="$(sed -n 's/^#define UTS_RELEASE "\(.*\)"$/\1/p' "$KERNEL_DIR/include/generated/utsrelease.h")"
if [ -z "$kernel_release" ]; then
    echo "cannot read kernel release" >&2
    exit 1
fi

assert_modinfo() {
    field="$1"
    module="$2"
    expected="$3"
    actual="$(modinfo -F "$field" "$ARTIFACT_DIR/$module")"
    if [ "$actual" != "$expected" ]; then
        echo "unexpected $field for $module: $actual" >&2
        exit 1
    fi
}

assert_modinfo name soph_vcodec.ko soph_vcodec
assert_modinfo name soph_jpeg.ko soph_jpeg
assert_modinfo name soph_vc_driver.ko soph_vc_driver
assert_modinfo depends soph_jpeg.ko soph_vcodec
assert_modinfo depends soph_vc_driver.ko soph_jpeg,soph_vcodec,soph_base,soph_sys
assert_modinfo srcversion soph_jpeg.ko "$EXPECTED_JPEG_SRCVERSION"

for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko; do
    vermagic="$(modinfo -F vermagic "$ARTIFACT_DIR/$module")"
    case "$vermagic" in
        "$kernel_release "*) ;;
        *)
            echo "unexpected vermagic for $module: $vermagic" >&2
            exit 1
            ;;
    esac
done

sha256sum "$PATCH_FILE" >"$REPORT_DIR/patch-sha256.txt"
if [ -n "$KERNEL_COMPAT_PATCH" ]; then
    sha256sum "$KERNEL_COMPAT_PATCH" >>"$REPORT_DIR/patch-sha256.txt"
fi
sha256sum "$ARTIFACT_DIR"/*.ko >"$REPORT_DIR/module-sha256.txt"
"$TOOLCHAIN_BIN/riscv64-unknown-linux-musl-gcc" --version \
    >"$REPORT_DIR/compiler-version.txt"

for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko; do
    {
        echo "[$module]"
        modinfo "$ARTIFACT_DIR/$module"
    } >>"$REPORT_DIR/modinfo.txt"
done

cat >"$REPORT_DIR/summary.md" <<EOF
# SOPHGO source-built media module replacements

- SOPHGO osdrv commit: \`$OSDRV_COMMIT\`
- target kernel release: \`$kernel_release\`
- compatibility patch: \`$PATCH_FILE\`
- source-built modules: \`soph_vcodec.ko\`, \`soph_jpeg.ko\`,
  \`soph_vc_driver.ko\`
- JPEG source version: \`$EXPECTED_JPEG_SRCVERSION\`
- modpost completed with the retained \`soph_base\` and \`soph_sys\` symbol
  contracts and no unresolved symbols.

This proves a technical source rebuild path for the three media modules against
the selected kernel. It does not grant redistribution rights and does not prove
runtime compatibility until a reboot-based device test passes.
EOF

cat "$REPORT_DIR/summary.md"
echo "SOPHGO media module report: $REPORT_DIR/summary.md"
