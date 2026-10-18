#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/build-security.sh"
DEFCONFIG="$ROOT/buildroot-external/hardened-sg2002/configs/hardened_sg2002_licheervnano_defconfig"
PATCH_ROOT="$ROOT/buildroot-external/hardened-sg2002/board/sg2002/patches"
PREPARE="$ROOT/scripts/prepare-buildroot-2026.05.1-security-source.sh"
VENDOR_MK="$ROOT/buildroot-external/hardened-sg2002/package/hardened-sg2002-vendor-runtime/hardened-sg2002-vendor-runtime.mk"
PACKAGE_SCRIPT="$ROOT/scripts/package-rust-kvmapp.sh"
AVAHI_CONFIG="$ROOT/buildroot-external/hardened-sg2002/board/sg2002/overlay/etc/avahi/avahi-daemon.conf"
POST_BUILD="$ROOT/buildroot-external/hardened-sg2002/board/sg2002/post-build.sh"
KVM_CMAKE="$ROOT/support/sg2002/additional/kvm/CMakeLists.txt"

# Source coverage only, not proof that services/writers are quiescent.
python3 "$ROOT/scripts/validate-state-writer-inventory.py" --root "$ROOT"

require_line() {
	line=$1
	file=$2
	grep -Fqx "$line" "$file" || {
		echo "missing required policy line in $file: $line" >&2
		exit 1
	}
}

reject_text() {
	text=$1
	file=$2
	if grep -Fq "$text" "$file"; then
		echo "forbidden policy text in $file: $text" >&2
		exit 1
	fi
}

verify_prepare_hash() {
	file=$1
	hash="$(sha256sum "$file" | awk '{print $1}')"
	grep -Fq "$hash" "$PREPARE" || {
		echo "prepare script does not pin $file at $hash" >&2
		exit 1
	}
}

require_line 'BR2_REPRODUCIBLE=y' "$DEFCONFIG"
require_line 'BR2_STRIP_EXCLUDE_FILES="NanoKVM-Server nanokvm-hwmon kvm_system libkvm.so libkvm_mmf.so soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko"' "$DEFCONFIG"
require_line '# BR2_TARGET_ENABLE_ROOT_LOGIN is not set' "$DEFCONFIG"
reject_text 'BR2_TARGET_GENERIC_ROOT_PASSWD=' "$DEFCONFIG"
require_line 'BR2_ROOTFS_POST_BUILD_SCRIPT="$(BR2_EXTERNAL_HARDENED_SG2002_PATH)/board/sg2002/post-build.sh"' "$DEFCONFIG"
require_line '# BR2_PACKAGE_LIBOPENSSL_ENABLE_QUIC is not set' "$DEFCONFIG"
require_line '# BR2_PACKAGE_HOSTAPD_DRIVER_HOSTAP is not set' "$DEFCONFIG"
require_line 'BR2_PACKAGE_HOSTAPD_DRIVER_NL80211=y' "$DEFCONFIG"
require_line '# BR2_PACKAGE_HOSTAPD_ACS is not set' "$DEFCONFIG"
require_line '# BR2_PACKAGE_HOSTAPD_VLAN is not set' "$DEFCONFIG"
require_line 'BR2_TARGET_ROOTFS_EXT2_MKFS_OPTIONS="-O ^64bit -U 23df1b1c-cbf0-5e1c-b42b-de68dec5ad95 -E hash_seed=23df1b1c-cbf0-5e1c-b42b-de68dec5ad95"' "$DEFCONFIG"
reject_text 'BR2_PACKAGE_DNSMASQ=' "$DEFCONFIG"
reject_text 'clients-max=' "$AVAHI_CONFIG"
require_line 'rlimit-nofile=256' "$AVAHI_CONFIG"

test ! -e "$ROOT/kvmapp/system/init.d/S80dnsmasq"
test -x "$POST_BUILD"
grep -Fq -- "-name '.files-list*'" "$POST_BUILD"
grep -Fq -- "-name '*-gdb.py'" "$POST_BUILD"
grep -Fq 'EXPECTED_RUST_RUNPATH=' "$POST_BUILD"
grep -Fq 'restore_rust_elf server/NanoKVM-Server' "$POST_BUILD"
reject_text '/tmp/server/dl_lib' "$ROOT/server-rust/scripts/build-linked-libkvm.sh"
reject_text '/tmp/server/dl_lib' "$ROOT/kvmapp/system/init.d/S95nanokvm"
require_line 'NANOKVM_NATIVE_LIBRARY_PATH=/kvmapp/server/dl_lib:/mnt/system/usr/lib:/mnt/system/usr/lib/3rd' \
	"$ROOT/kvmapp/system/init.d/S95nanokvm"
test -f "$ROOT/kvmapp/system/keys/update-keys/README.md"
test -f "$ROOT/kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem"
test -f "$ROOT/kvmapp/system/keys/update-key-policy"
test "$(openssl pkey -pubin \
	-in "$ROOT/kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem" \
	-outform DER | sha256sum | awk '{print $1}')" = \
	97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75
for key_id in hardened-system-dev hardened-system-test hardened-system-prod-2026q3; do
	grep -qx "$key_id" "$ROOT/kvmapp/system/keys/update-key-policy"
done
build_assert_no_private_keys "$ROOT/kvmapp" || exit 1
test -f "$PATCH_ROOT/libopenssl/3.6.3/0001-CVE-2026-54876-fix-OCSP-response-leak.patch"
test -f "$PATCH_ROOT/busybox/1.38.0/0012-CVE-2026-38753-fix-awk-sub-use-after-free.patch"
test -f "$PATCH_ROOT/busybox/1.38.0/0013-CVE-2026-38755-limit-ash-function-recursion.patch"
test -f "$PATCH_ROOT/busybox/1.38.0/0014-CVE-2026-38754-clear-stale-ifs-regions.patch"

for patch in "$ROOT"/buildroot-external/hardened-sg2002/buildroot-patches/2026.05.1/*.patch; do
	verify_prepare_hash "$patch"
done

grep -Fq 'patch -d "$SOURCE" -p1 --forward --batch -F 0' "$PREPARE"
grep -Fq 'rm -f "$KVMAPP_STAGE/server/dl_lib/libz.so"' "$PACKAGE_SCRIPT"
grep -Fq 'must not contain a build-host RPATH/RUNPATH' "$PACKAGE_SCRIPT"
grep -Fq 'set_target_properties(kvm PROPERTIES SKIP_BUILD_RPATH TRUE)' "$KVM_CMAKE"
reject_text 'ln -sf libz.so.1.3' "$VENDOR_MK"
grep -Fq '$(NANOKVM_KVMAPP_SOURCE_DIR)/server/dl_lib/libkvm.so' "$VENDOR_MK"
grep -Fq '$(NANOKVM_KVMAPP_SOURCE_DIR)/server/dl_lib/libkvm_mmf.so' "$VENDOR_MK"
grep -Fq 'vendor-runtime-source-media-v1' "$VENDOR_MK"
grep -Fq 'vendor-runtime-source-media-v1' \
	"$ROOT/scripts/build-latest-buildroot-sg2002-rootfs.sh"
grep -Fq 'HARDENED_SG2002_FIP_IMAGE' \
	"$ROOT/scripts/assemble-latest-buildroot-sg2002-sd-image.sh"
grep -Fq 'HARDENED_SG2002_BOOT_IMAGE' \
	"$ROOT/scripts/assemble-latest-buildroot-sg2002-sd-image.sh"
grep -Fq 'HARDENED_SG2002_LOGO_IMAGE' \
	"$ROOT/scripts/assemble-latest-buildroot-sg2002-sd-image.sh"
grep -Fq 'SYSTEM_UPDATE_KEY_POLICY=/etc/kvm/update-key-policy' \
	"$ROOT/kvmapp/system/init.d/S95nanokvm"

if [ -d "$ROOT/build/kvmapp-rust/kvmapp/server/dl_lib" ]; then
	test ! -e "$ROOT/build/kvmapp-rust/kvmapp/server/dl_lib/libz.so"
	test ! -e "$ROOT/build/kvmapp-rust/kvmapp/server/dl_lib/libz.so.1"
	test ! -e "$ROOT/build/kvmapp-rust/kvmapp/server/dl_lib/libz.so.1.3"
fi

printf 'latest Buildroot raw.11 security policy: PASS\n'
