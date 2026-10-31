#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDROOT_VERSION="${BUILDROOT_VERSION:-2026.05.1}"
PROBE_ROOT="${LATEST_BUILDROOT_PROBE_ROOT:-$ROOT/build/latestbuildroot}"
CONFIG_OUTPUT_DIR="${HARDENED_SG2002_BUILDROOT_OUTPUT_DIR:-$PROBE_ROOT/sg2002-config-${BUILDROOT_VERSION}-raw11}"
VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-$ROOT/build/vendor/LicheeRV-Nano-Build}"
VENDOR_OUTPUT_DIR="${HARDENED_SG2002_VENDOR_OUTPUT_DIR:-$VENDOR_SDK_DIR/install/soc_sg2002_licheervnano_sd}"
EXTERNAL_DIR="${HARDENED_SG2002_EXTERNAL_DIR:-$ROOT/buildroot-external/hardened-sg2002}"
OUTPUT_DIR="${HARDENED_SG2002_SD_OUTPUT_DIR:-$PROBE_ROOT/sg2002-sd-image-${BUILDROOT_VERSION}-raw11}"
ROOTFS_IMAGE="${HARDENED_SG2002_ROOTFS_IMAGE:-$CONFIG_OUTPUT_DIR/images/rootfs.ext2}"
FIP_IMAGE="${HARDENED_SG2002_FIP_IMAGE:-$VENDOR_OUTPUT_DIR/fip.bin}"
BOOT_IMAGE="${HARDENED_SG2002_BOOT_IMAGE:-$VENDOR_OUTPUT_DIR/rawimages/boot.sd}"
LOGO_IMAGE="${HARDENED_SG2002_LOGO_IMAGE:-$VENDOR_SDK_DIR/build/tools/common/sd_tools/logo.jpeg}"
GENIMAGE="$CONFIG_OUTPUT_DIR/host/bin/genimage"
HOST_DEPS_ROOT="${BUILDROOT_PORT_HOST_DEPS:-$ROOT/build/host-deps}"
USER_HOME="${HOME:-/home/w0w}"
HOST_DEPS_PATH="$HOST_DEPS_ROOT/usr/sbin:$HOST_DEPS_ROOT/usr/bin"
CLEAN_PATH="${BUILDROOT_PORT_CLEAN_PATH:-$HOST_DEPS_PATH:$USER_HOME/.local/bin:$USER_HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
ASSEMBLY_EPOCH="${HARDENED_SG2002_ASSEMBLY_EPOCH:-1782723554}"
EXPECTED_SYSTEM_VERSION="${EXPECTED_SYSTEM_VERSION:-0.3.0-raw.11}"
EXPECTED_SYSTEM_KERNEL_VERSION="${EXPECTED_SYSTEM_KERNEL_VERSION:-}"
EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL="${EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL:-}"

require_file() {
	[ -f "$1" ] || {
		echo "missing required file: $1" >&2
		exit 1
	}
}

require_file "$ROOTFS_IMAGE"
require_file "$GENIMAGE"
require_file "$FIP_IMAGE"
require_file "$BOOT_IMAGE"
require_file "$LOGO_IMAGE"
require_file "$EXTERNAL_DIR/board/sg2002/genimage.cfg"
require_file "$ROOT/scripts/mcopy-preserve-time.sh"

for tool in mkdosfs mcopy debugfs; do
	PATH="$CLEAN_PATH" command -v "$tool" >/dev/null 2>&1 || {
		echo "missing required host tool in BUILDROOT_PORT_CLEAN_PATH: $tool" >&2
		exit 1
	}
done
MCOPY_REAL="$(PATH="$CLEAN_PATH" command -v mcopy)"

# Buildroot's package/busybox/busybox.mk device table hardcodes /bin/busybox
# to 4755 even though the staged target tree is 0755. The authenticated raw
# restore preflight rejects a setuid shell; normalize the exact image inode
# before validation and assembly so the candidate and every derived raw image
# carry a non-setuid BusyBox.
normalize_busybox_mode() {
	local image="$1" mode
	mode="$(debugfs -R 'stat /usr/bin/busybox' "$image" 2>/dev/null | sed -n 's/.*Mode:  *\([0-7]*\).*/\1/p' | head -n 1)"
	[ -n "$mode" ] || {
		echo "busybox is missing from the rootfs image" >&2
		exit 1
	}
	case "$mode" in
		0755|0100755) ;;
		*)
			debugfs -w -R 'sif /usr/bin/busybox mode 0100755' "$image" >/dev/null 2>&1 || {
				echo "could not clear the busybox setuid bit in $image" >&2
				exit 1
			}
			;;
	esac
	mode="$(debugfs -R 'stat /usr/bin/busybox' "$image" 2>/dev/null | sed -n 's/.*Mode:  *\([0-7]*\).*/\1/p' | head -n 1)"
	case "$mode" in
		0755|0100755) ;;
		*)
			echo "busybox remains setuid after normalization: mode=$mode" >&2
			exit 1
			;;
	esac
}
normalize_busybox_mode "$ROOTFS_IMAGE"

EXPECTED_BUILDROOT_VERSION="$BUILDROOT_VERSION" \
EXPECTED_KVMAPP_VERSION="${EXPECTED_KVMAPP_VERSION:-2.0.41}" \
	EXPECTED_SYSTEM_VERSION="$EXPECTED_SYSTEM_VERSION" \
	EXPECTED_SYSTEM_KERNEL_VERSION="$EXPECTED_SYSTEM_KERNEL_VERSION" \
	EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL="$EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL" \
	"$ROOT/scripts/validate-latest-buildroot-sg2002-rootfs.sh" "$ROOTFS_IMAGE"

if [ -e "$OUTPUT_DIR" ]; then
	echo "refusing to overwrite SD image output: $OUTPUT_DIR" >&2
	echo "set HARDENED_SG2002_SD_OUTPUT_DIR to a new path for another candidate" >&2
	exit 1
fi

mkdir -p "$OUTPUT_DIR/root" "$OUTPUT_DIR/tmp" "$OUTPUT_DIR/input/rawimages" "$OUTPUT_DIR/images"
cp "$FIP_IMAGE" "$OUTPUT_DIR/input/fip.bin"
cp "$BOOT_IMAGE" "$OUTPUT_DIR/input/rawimages/boot.sd"
cp "$ROOTFS_IMAGE" "$OUTPUT_DIR/input/rootfs.sd"
cp "$LOGO_IMAGE" "$OUTPUT_DIR/input/logo.jpeg"

touch "$OUTPUT_DIR/input/usb.dev" "$OUTPUT_DIR/input/usb.disk0" \
	"$OUTPUT_DIR/input/wifi.sta" "$OUTPUT_DIR/input/gt9xx"
printf 'hardened-sg2002-port-%s.img\n' "$BUILDROOT_VERSION" > "$OUTPUT_DIR/input/ver"
find "$OUTPUT_DIR/input" -print0 | xargs -0 -r touch -hd "@$ASSEMBLY_EPOCH"

env PATH="$CLEAN_PATH" HARDENED_MCOPY_REAL="$MCOPY_REAL" "$GENIMAGE" \
	--mcopy "$ROOT/scripts/mcopy-preserve-time.sh" \
	--rootpath "$OUTPUT_DIR/root" \
	--tmppath "$OUTPUT_DIR/tmp" \
	--inputpath "$OUTPUT_DIR/input" \
	--outputpath "$OUTPUT_DIR/images" \
	--config "$EXTERNAL_DIR/board/sg2002/genimage.cfg"

IMAGE="$OUTPUT_DIR/images/hardened-sg2002-port.img"
require_file "$IMAGE"
partx -g -o NR,START,SECTORS,SIZE,TYPE "$IMAGE"
sha256sum "$IMAGE" > "$OUTPUT_DIR/SHA256SUMS"

printf '%s\n' "$IMAGE"
printf '%s\n' "$OUTPUT_DIR/SHA256SUMS"
echo "This candidate is restricted to an explicitly authorized recoverable-media boot test."
