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
SSHD_CONFIG="$ROOT/buildroot-external/hardened-sg2002/board/sg2002/overlay/etc/ssh/sshd_config"

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
require_line 'BR2_ROOTFS_POST_FAKEROOT_SCRIPT="$(BR2_EXTERNAL_HARDENED_SG2002_PATH)/board/sg2002/post-fakeroot.sh"' "$DEFCONFIG"
require_line 'BR2_TARGET_TZ_INFO=y' "$DEFCONFIG"
require_line 'BR2_TARGET_LOCALTIME="Etc/UTC"' "$DEFCONFIG"
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
require_line 'Compression no' "$SSHD_CONFIG"
require_line 'PermitEmptyPasswords no' "$SSHD_CONFIG"
require_line 'UsePAM no' "$SSHD_CONFIG"

test ! -e "$ROOT/kvmapp/system/init.d/S80dnsmasq"
test -x "$POST_BUILD"
grep -Fq -- "-name '.files-list*'" "$POST_BUILD"
grep -Fq -- "-name '*-gdb.py'" "$POST_BUILD"
grep -Fq 'EXPECTED_RUST_RUNPATH=' "$POST_BUILD"
grep -Fq 'restore_rust_elf server/NanoKVM-Server' "$POST_BUILD"
reject_text '/tmp/server/dl_lib' "$ROOT/server-rust/scripts/build-linked-libkvm.sh"
reject_text '/tmp/server/dl_lib' "$ROOT/kvmapp/system/init.d/S95nanokvm"
require_line 'pub const LIBRARY_PATH: &str = "/kvmapp/server/dl_lib:/mnt/system/usr/lib:/mnt/system/usr/lib/3rd";' \
	"$ROOT/server-rust/src/native_owner/mod.rs"
require_line '            nanokvm_rust_server::native_owner::LIBRARY_PATH,' \
	"$ROOT/server-rust/src/bin/nanokvm-native-owner.rs"
require_line '            "/kvmapp/server/NanoKVM-Server",' \
	"$ROOT/server-rust/src/bin/nanokvm-native-owner.rs"
for operation in ensure-backend restart-backend restart-backend-safe; do
	require_line "    \"\$NATIVE_CTL\" $operation >/dev/null" "$ROOT/kvmapp/system/init.d/S95nanokvm"
done
for obsolete in SERVER_PID_FILE SERVER_RUNTIME_DIR NANOKVM_XTHEAD_LOADER stop_server_process; do
	reject_text "$obsolete" "$ROOT/kvmapp/system/init.d/S95nanokvm"
done
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
# Fixed upstream in the refreshed versions: the board carries no libopenssl or
# wpa_supplicant patch any more, the version bumps below replace them.
test ! -e "$PATCH_ROOT/libopenssl/3.6.3"
test ! -e "$PATCH_ROOT/wpa_supplicant/2.11"
for bump in 0004-libopenssl-3.6.5 0005-openssh-10.6p1 0006-expat-2.9.0 0007-libcurl-8.23.0 0008-wpa_supplicant-2.12; do
	test -f "$ROOT/buildroot-external/hardened-sg2002/buildroot-patches/2026.05.1/$bump.patch"
done
test -f "$PATCH_ROOT/busybox/1.38.0/0012-CVE-2026-38753-fix-awk-sub-use-after-free.patch"
test -f "$PATCH_ROOT/busybox/1.38.0/0013-CVE-2026-38755-limit-ash-function-recursion.patch"
test -f "$PATCH_ROOT/busybox/1.38.0/0014-CVE-2026-38754-clear-stale-ifs-regions.patch"
# The ntpd bind-failure crash is fixed by Buildroot's own package patch
# 0004-Fix-crash-when-binding-IPv6-address.patch; a board copy of the same
# change made the ntp patch step fail ("Reversed (or previously applied)").
test ! -e "$PATCH_ROOT/ntp"

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
grep -Fq 'let _permit = writers.configuration()?;' \
	"$ROOT/server-rust/src/update/keys.rs"
grep -Fq 'install_runtime_update_trust(&config);' "$ROOT/server-rust/src/main.rs"
reject_text 'install_system_update_public_key' "$ROOT/kvmapp/system/init.d/S95nanokvm"
reject_text 'SYSTEM_UPDATE_BUNDLED_' "$ROOT/kvmapp/system/init.d/S95nanokvm"
reject_text 'system-update-signing.pub.pem' "$ROOT/kvmapp/system/init.d/S95nanokvm"
reject_text 'update-key-policy' "$ROOT/kvmapp/system/init.d/S95nanokvm"
reject_text 'update-keys' "$ROOT/kvmapp/system/init.d/S95nanokvm"
for verifier in application system_update; do
	source="$ROOT/server-rust/src/api/$verifier.rs"
	grep -Fq 'keys::verify_metadata_signature,' "$source"
	reject_text 'resolve_update_public_key' "$source"
	reject_text 'temp_verify_path' "$source"
	reject_text 'write_verify_temp_file' "$source"
done
grep -Fq 'run_allowed_owned(AllowedCommand::OpenSsl, arguments, timeout, self)' \
	"$ROOT/server-rust/src/update/trust_snapshot.rs"
grep -Fq 'native_bootstrap::prepare_boot_support()' "$ROOT/server-rust/src/main.rs"
grep -Fq 'install_runtime_boot_scripts(boot_support.is_some())?;' "$ROOT/server-rust/src/main.rs"
grep -Fq 'drop(boot_support);' "$ROOT/server-rust/src/main.rs"
grep -Fq 'super::native_bootstrap::check_installed()?;' \
	"$ROOT/server-rust/src/update/app_bootstrap.rs"

if [ -d "$ROOT/build/kvmapp-rust/kvmapp/server/dl_lib" ]; then
	test ! -e "$ROOT/build/kvmapp-rust/kvmapp/server/dl_lib/libz.so"
	test ! -e "$ROOT/build/kvmapp-rust/kvmapp/server/dl_lib/libz.so.1"
	test ! -e "$ROOT/build/kvmapp-rust/kvmapp/server/dl_lib/libz.so.1.3"
fi

printf 'latest Buildroot raw.11 security policy: PASS\n'
