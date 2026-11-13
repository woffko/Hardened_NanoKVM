#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
RUN_ROOT="${KERNEL_5_10_265_REPRO_ROOT:-}"
EXPECTED_KERNEL_RELEASE="${EXPECTED_KERNEL_RELEASE:-5.10.265-tag-}"
EXPECTED_SYSTEM_VERSION="${EXPECTED_SYSTEM_VERSION:-0.3.0-raw.11}"
EXPECTED_KVMAPP_VERSION="${EXPECTED_KVMAPP_VERSION:-2.0.41}"
EXPECTED_SECURITY_PATCH_LEVEL="${EXPECTED_SECURITY_PATCH_LEVEL:-Buildroot 2026.05.1 security maintenance; Linux 5.10.265 stable with SG2002 vendor port}"
export HARDENED_SG2002_VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-$ROOT_DIR/build/vendor/LicheeRV-Nano-Build}"
export HARDENED_SG2002_TOOLCHAIN_BIN="${HARDENED_SG2002_TOOLCHAIN_BIN:-$HARDENED_SG2002_VENDOR_SDK_DIR/host-tools/gcc/riscv64-linux-musl-x86_64/bin}"
export REFERENCE_BOOT_SD="${REFERENCE_BOOT_SD:-$ROOT_DIR/build/latestbuildroot/recoverable-kernel-baseline-sd-v2/assembly/input/rawimages/boot.sd}"
export VENDOR_RAMDISK_WORKSPACE="${VENDOR_RAMDISK_WORKSPACE:-$ROOT_DIR/build/latestbuildroot/kernel-5.10.265-fixed-repro-a/boot/workspace}"
export KERNEL_5_10_265_FIP_IMAGE="${KERNEL_5_10_265_FIP_IMAGE:-$ROOT_DIR/build/latestbuildroot/recoverable-kernel-baseline-sd-v2/assembly/input/fip.bin}"

[ -n "$RUN_ROOT" ] || {
	echo "KERNEL_5_10_265_REPRO_ROOT is required" >&2
	exit 1
}
case "$RUN_ROOT" in
	/*) ;;
	*)
	echo "KERNEL_5_10_265_REPRO_ROOT must be absolute" >&2
	exit 1
	;;
esac
if [ -e "$RUN_ROOT" ]; then
	echo "refusing to reuse reproducibility run root: $RUN_ROOT" >&2
	exit 1
fi
if [ -n "$(git -C "$ROOT_DIR" status --short)" ]; then
	echo "outer project worktree is not clean" >&2
	exit 1
fi

mkdir -p "$RUN_ROOT" "$RUN_ROOT/_reports"
outer_commit="$(git -C "$ROOT_DIR" rev-parse HEAD)"
printf '%s\n' "$outer_commit" > "$RUN_ROOT/_reports/outer-commit.txt"

KERNEL_5_10_265_OUTPUT_DIR="$RUN_ROOT/kernel" \
	"$ROOT_DIR/scripts/build-vendor-kernel-5.10.265-candidate.sh"

KERNEL_BASELINE_OUTPUT_DIR="$RUN_ROOT/kernel" \
EXTERNAL_MODULE_BASELINE_OUTPUT_DIR="$RUN_ROOT/external" \
EXPECTED_KERNEL_RELEASE="$EXPECTED_KERNEL_RELEASE" \
	"$ROOT_DIR/scripts/rebuild-vendor-external-modules-5.10-baseline.sh"

KERNEL_5_10_265_OUTPUT_DIR="$RUN_ROOT/kernel" \
MEDIA_MODULE_5_10_265_OUTPUT_DIR="$RUN_ROOT/media" \
MEDIA_MODULE_5_10_265_EXTERNAL_BUILD_DIR="$RUN_ROOT/external" \
EXPECTED_KERNEL_RELEASE="$EXPECTED_KERNEL_RELEASE" \
	"$ROOT_DIR/scripts/build-sg2002-media-modules-5.10.265-candidate.sh"

KERNEL_5_10_265_OUTPUT_DIR="$RUN_ROOT/kernel" \
EXTERNAL_MODULE_5_10_265_DIR="$RUN_ROOT/external/artifacts" \
MEDIA_MODULE_5_10_265_DIR="$RUN_ROOT/media/artifacts" \
KERNEL_5_10_265_VENDOR_RUNTIME_DIR="$RUN_ROOT/runtime" \
KERNEL_5_10_265_VENDOR_RUNTIME_REPORT_DIR="$RUN_ROOT/_reports/runtime" \
EXPECTED_KERNEL_RELEASE="$EXPECTED_KERNEL_RELEASE" \
	"$ROOT_DIR/scripts/prepare-kernel-5.10.265-vendor-runtime.sh"

KERNEL_5_10_265_VENDOR_RUNTIME_DIR="$RUN_ROOT/runtime" \
KERNEL_5_10_265_BUILDROOT_OUTPUT_DIR="$RUN_ROOT/buildroot" \
KERNEL_5_10_265_ROOTFS_REPORT_DIR="$RUN_ROOT/_reports/rootfs" \
EXPECTED_KERNEL_RELEASE="$EXPECTED_KERNEL_RELEASE" \
EXPECTED_SYSTEM_VERSION="$EXPECTED_SYSTEM_VERSION" \
EXPECTED_KVMAPP_VERSION="$EXPECTED_KVMAPP_VERSION" \
EXPECTED_SECURITY_PATCH_LEVEL="$EXPECTED_SECURITY_PATCH_LEVEL" \
	"$ROOT_DIR/scripts/build-latest-buildroot-kernel-5.10.265-rootfs.sh"

KERNEL_BASELINE_OUTPUT_DIR="$RUN_ROOT/kernel" \
BOOT_SD_BASELINE_OUTPUT_DIR="$RUN_ROOT/boot" \
BOOT_SD_BUILD_MODE=candidate \
EXPECTED_KERNEL_RELEASE="$EXPECTED_KERNEL_RELEASE" \
	"$ROOT_DIR/scripts/rebuild-vendor-boot-sd-5.10-baseline.sh"

KERNEL_5_10_265_BUILDROOT_OUTPUT_DIR="$RUN_ROOT/buildroot" \
KERNEL_5_10_265_VENDOR_RUNTIME_DIR="$RUN_ROOT/runtime" \
KERNEL_5_10_265_BOOT_SD="$RUN_ROOT/boot/workspace/boot.itb" \
KERNEL_5_10_265_RECOVERY_SD_DIR="$RUN_ROOT/recovery" \
EXPECTED_KERNEL_RELEASE="$EXPECTED_KERNEL_RELEASE" \
EXPECTED_SYSTEM_VERSION="$EXPECTED_SYSTEM_VERSION" \
EXPECTED_KVMAPP_VERSION="$EXPECTED_KVMAPP_VERSION" \
EXPECTED_SECURITY_PATCH_LEVEL="$EXPECTED_SECURITY_PATCH_LEVEL" \
	"$ROOT_DIR/scripts/assemble-kernel-5.10.265-recovery-sd-image.sh"

cat > "$RUN_ROOT/_reports/summary.md" <<EOF
# Complete Linux $EXPECTED_KERNEL_RELEASE clean candidate run

- outer project commit: \`$outer_commit\`
- kernel release: **$EXPECTED_KERNEL_RELEASE**
- userspace system: **$EXPECTED_SYSTEM_VERSION**
- application: **$EXPECTED_KVMAPP_VERSION**
- kernel, external modules, media modules, runtime staging, Buildroot rootfs,
  FIT and recovery SD: **complete**
- device acceptance: **pending-recovery-sd**
EOF

cat "$RUN_ROOT/_reports/summary.md"
printf 'complete kernel candidate run: %s\n' "$RUN_ROOT"
