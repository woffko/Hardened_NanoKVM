#!/bin/sh
set -eu

usage() {
	echo "usage: $0 <rootfs.ext4>" >&2
	echo "Current security candidates only; historical RC12 uses verify-rc12-raw-bundle.sh." >&2
	exit 1
}

die() {
	echo "error: $*" >&2
	exit 1
}

[ "$#" -eq 1 ] || usage

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
IMAGE="$1"
EXPECTED_BUILDROOT_VERSION="${EXPECTED_BUILDROOT_VERSION:-2026.05.1}"
EXPECTED_KVMAPP_VERSION="${EXPECTED_KVMAPP_VERSION:-2.0.41}"
EXPECTED_SYSTEM_VERSION="${EXPECTED_SYSTEM_VERSION:-0.3.0-raw.11}"
EXPECTED_ROOTFS_UUID="${EXPECTED_ROOTFS_UUID:-23df1b1c-cbf0-5e1c-b42b-de68dec5ad95}"
EXPECTED_SOPH_VCODEC_SHA256="${EXPECTED_SOPH_VCODEC_SHA256:-0f0927cd796275f2241e8914b3efa57b124b8cc2aabc087ee899a56346a5c2be}"
EXPECTED_SOPH_JPEG_SHA256="${EXPECTED_SOPH_JPEG_SHA256:-eacf2af2c75c23816af129843912f5072c9cb81d44434d563ceb449ee2899666}"
EXPECTED_SOPH_VC_DRIVER_SHA256="${EXPECTED_SOPH_VC_DRIVER_SHA256:-cc543c2a1b25c63c0372d7a687643605b1d07a5624403e3cf7d74b52ecadecf5}"
EXPECTED_MEDIA_DEVICE_ACCEPTANCE="${EXPECTED_MEDIA_DEVICE_ACCEPTANCE:-10.0.87.133-20260821T032009Z}"
EXPECTED_RUNTIME_KERNEL_RELEASE="${EXPECTED_RUNTIME_KERNEL_RELEASE:-}"
EXPECTED_SYSTEM_KERNEL_VERSION="${EXPECTED_SYSTEM_KERNEL_VERSION:-}"
EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL="${EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL:-}"

[ -f "$IMAGE" ] || die "rootfs image does not exist: $IMAGE"
command -v debugfs >/dev/null 2>&1 || die "debugfs is required"
python3 "$ROOT/scripts/validate-sg2002-account-ids.py" "$IMAGE"
LC_ALL=C debugfs -R "cat /etc/kvm/server.yaml" "$IMAGE" 2>/dev/null | grep -qx 'proto: https' || \
	die "the image does not start a new installation on HTTPS"

ROOTFS_STATS="$(LC_ALL=C debugfs -R stats "$IMAGE" 2>&1 || true)"
printf '%s\n' "$ROOTFS_STATS" | grep -Eq "^Filesystem UUID:[[:space:]]+$EXPECTED_ROOTFS_UUID$" || \
	die "unexpected rootfs UUID; reproducibility identity is not pinned"
printf '%s\n' "$ROOTFS_STATS" | grep -Eq "^Directory Hash Seed:[[:space:]]+$EXPECTED_ROOTFS_UUID$" || \
	die "unexpected ext4 directory hash seed; reproducibility identity is not pinned"

EXPECTED_BACKEND=rust \
EXPECTED_KVMAPP_VERSION="$EXPECTED_KVMAPP_VERSION" \
	"$ROOT/scripts/validate-nanokvm-rootfs.sh" "$IMAGE" >/dev/null

debugfs_stat() {
	LC_ALL=C debugfs -R "stat $1" "$IMAGE" 2>&1 || true
}

require_path() {
	output="$(debugfs_stat "$1")"
	case "$output" in
		*"File not found"* | *"not found by ext2_lookup"* | *"No such file or directory"*)
			die "missing required path: $1"
			;;
	esac
}

reject_path() {
	output="$(debugfs_stat "$1")"
	case "$output" in
		*"File not found"* | *"not found by ext2_lookup"* | *"No such file or directory"*)
			return 0
			;;
	esac
	die "forbidden path exists: $1"
}

verify_sha256() {
	path="$1"
	expected="$2"
	name="$3"
	dest="$TMP_DIR/$name"
	debugfs -R "dump $path $dest" "$IMAGE" >/dev/null 2>&1 || \
		die "could not extract $path for hashing"
	actual="$(sha256sum "$dest" | awk '{print $1}')"
	[ "$actual" = "$expected" ] || \
		die "unexpected SHA-256 for $path: $actual"
}

verify_matches_staged() {
	image_path="$1"
	staged_path="$2"
	name="$3"
	[ -f "$staged_path" ] || die "staged provenance input is missing: $staged_path"
	dest="$TMP_DIR/$name"
	debugfs -R "dump $image_path $dest" "$IMAGE" >/dev/null 2>&1 || \
		die "could not extract $image_path for provenance comparison"
	expected="$(sha256sum "$staged_path" | awk '{print $1}')"
	actual="$(sha256sum "$dest" | awk '{print $1}')"
	[ "$actual" = "$expected" ] || \
		die "Buildroot modified $image_path: expected $expected, got $actual"
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nanokvm-latest-buildroot-validate.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM
STAGED_KVMAPP_DIR="${STAGED_KVMAPP_DIR:-$ROOT/build/kvmapp-rust/kvmapp}"

if [ -n "$EXPECTED_SYSTEM_KERNEL_VERSION" ] || [ -n "$EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL" ]; then
	[ -n "$EXPECTED_SYSTEM_KERNEL_VERSION" ] && [ -n "$EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL" ] || \
		die "system kernel and security metadata expectations must be set together"
	SYSTEM_VERSION_JSON="$TMP_DIR/system-version.json"
	debugfs -R "dump /etc/kvm/system-version.json $SYSTEM_VERSION_JSON" \
		"$IMAGE" >/dev/null 2>&1 || die "could not extract system version metadata"
	grep -Fq "\"kernel_version\": \"$EXPECTED_SYSTEM_KERNEL_VERSION\"" \
		"$SYSTEM_VERSION_JSON" || die "system metadata kernel version is incorrect"
	grep -Fq "\"security_patch_level\": \"$EXPECTED_SYSTEM_SECURITY_PATCH_LEVEL\"" \
		"$SYSTEM_VERSION_JSON" || die "system security patch metadata is incorrect"
fi

for path in \
	/mnt/system/ko/soph_sys.ko \
	/mnt/system/ko/soph_mipi_rx.ko \
		/mnt/system/ko/soph_vcodec.ko \
		/mnt/system/ko/soph_jpeg.ko \
		/mnt/system/ko/soph_vc_driver.ko \
		/mnt/system/ko/hardened-source-media-provenance.txt \
	/mnt/system/ko/soph_vi.ko \
	/mnt/system/ko/soph_vpss.ko \
	/mnt/system/usr/lib/libsns_lt6911.so \
	/lib/ld-musl-riscv64xthead.so.1 \
	/lib/ld-musl-riscv64v0p7_xthead.so.1 \
	/etc/kvm/system-version.json \
	/etc/ssh/sshd_config \
	/etc/ssl/certs/ca-certificates.crt \
	/kvmapp/server/dl_lib/libopencv_video.so.409 \
	/kvmapp/server/dl_lib/libopencv_dnn.so.409 \
	/kvmapp/server/dl_lib/libopencv_calib3d.so.409 \
	/kvmapp/server/dl_lib/libopencv_features2d.so.409 \
	/kvmapp/server/dl_lib/libopencv_flann.so.409 \
	/kvmapp/server/dl_lib/libprotobuf.so.32 \
	/kvmapp/server/dl_lib/libstdc++.so.6 \
	/kvmapp/server/dl_lib/libgcc_s.so.1 \
	/kvmapp/server/dl_lib/libgomp.so.1 \
	/kvmapp/server/dl_lib/libatomic.so.1 \
	/kvmapp/server/dl_lib/libc.so \
	/usr/lib/libgomp.so.1 \
	/usr/lib/libatomic.so.1 \
	/usr/lib/libstdc++.so.6 \
	/usr/lib/libgcc_s.so.1 \
	/usr/lib/libz.so.1 \
	/usr/lib/libz.so.1.3.2 \
	/usr/sbin/sshd \
	/usr/sbin/avahi-daemon \
	/usr/sbin/hostapd \
	/usr/sbin/wpa_supplicant \
	/usr/sbin/wpa_passphrase \
	/usr/bin/curl \
	/usr/bin/openssl \
	/usr/bin/ntpdate \
	/usr/sbin/parted \
	/usr/sbin/mkfs.exfat \
	/usr/sbin/resize2fs
do
	require_path "$path"
done

reject_path /usr/bin/python
reject_path /usr/bin/python3
reject_path /usr/bin/ffmpeg
reject_path /usr/bin/ffprobe
reject_path /usr/sbin/dnsmasq
reject_path /etc/init.d/S80dnsmasq
reject_path /kvmapp/system/init.d/S80dnsmasq
reject_path /kvmapp/server/dl_lib/libz.so
reject_path /kvmapp/server/dl_lib/libz.so.1
reject_path /kvmapp/server/dl_lib/libz.so.1.3
reject_path /kvmapp/.files-list.before
reject_path /usr/lib/firmware/aic8800_sdio/.files-list.before
reject_path /usr/share/fw_vcodec/.files-list.before
reject_path /usr/lib/libstdc++.so.6.0.33-gdb.py

SHADOW_FILE="$TMP_DIR/shadow"
debugfs -R "dump /etc/shadow $SHADOW_FILE" "$IMAGE" >/dev/null 2>&1 || \
	die "could not read /etc/shadow"
grep -q '^root:\*:' "$SHADOW_FILE" || \
	die "clean image root account is not locked"

AVAHI_CONFIG="$TMP_DIR/avahi-daemon.conf"
debugfs -R "dump /etc/avahi/avahi-daemon.conf $AVAHI_CONFIG" "$IMAGE" >/dev/null 2>&1 || \
	die "could not read Avahi configuration"
if grep -q '^clients-max=' "$AVAHI_CONFIG"; then
	die "Avahi clients-max is invalid when D-Bus support is disabled"
fi
grep -qx 'enable-wide-area=no' "$AVAHI_CONFIG" || die "Avahi wide-area mode is enabled"
grep -qx 'rlimit-nofile=256' "$AVAHI_CONFIG" || die "Avahi file descriptors are not bounded"

verify_sha256 /kvmapp/server/dl_lib/libopencv_video.so.4.9.0 \
	4bda8c165e9e53090cdc783a826c8c61a81ccff3a022bef5f7243a95596f52c7 opencv-video
verify_sha256 /kvmapp/server/dl_lib/libopencv_dnn.so.4.9.0 \
	3d2ae102eb4a2d2eb2e109ba23015d761ad43cf9299fdbc427e02c52377bfc79 opencv-dnn
verify_sha256 /kvmapp/server/dl_lib/libopencv_calib3d.so.4.9.0 \
	119f69d7bb3c5fd033689e87faeaa37c75547a226dde150fadf01ded04e85466 opencv-calib3d
verify_sha256 /kvmapp/server/dl_lib/libopencv_features2d.so.4.9.0 \
	f620d5466f0bd241ce70ed34d3bca07a4dc666a2addf624a2f52902e3c6ec015 opencv-features2d
verify_sha256 /kvmapp/server/dl_lib/libopencv_flann.so.4.9.0 \
	1dadc13c42828b3fef7b3c20026b3a0263fcbcd882bfb904105de0bea1a0c991 opencv-flann
verify_sha256 /kvmapp/server/dl_lib/libprotobuf.so.32.0.12 \
	096d35f5f085b74d6654d30bdfa91c69398093fc47548979d5c8ed4e5caebd27 protobuf
SYSTEM_ZLIB="$TMP_DIR/system-libz.so.1.3.2"
debugfs -R "dump /usr/lib/libz.so.1.3.2 $SYSTEM_ZLIB" "$IMAGE" >/dev/null 2>&1 || \
	die "could not extract Buildroot system zlib"
"$ROOT/scripts/verify-zlib-runtime-abi.sh" "$SYSTEM_ZLIB" "$TMP_DIR/protobuf" || \
	die "Buildroot system zlib does not satisfy the vendor protobuf ABI"
verify_sha256 /kvmapp/server/dl_lib/libstdc++.so.6.0.28 \
	9ebc8352014fbb7499194fdca56eb496c51c119b50d08d7b70b96058d3c5be17 libstdcpp
verify_sha256 /kvmapp/server/dl_lib/libgcc_s.so.1 \
	4b483b84f730b5e127ee8441cc143d5d90f1a31f0bfb999f94ef834eefa3da8c libgcc
verify_sha256 /kvmapp/server/dl_lib/libgomp.so.1.0.0 \
	986f21b24574f0e58672c865b34d9eba102ba45c05f18a608bf612816b84c901 libgomp
verify_sha256 /kvmapp/server/dl_lib/libatomic.so.1.2.0 \
	2421e827d033c3a055b973e6fbcf5a78fe987b50dd21e82a422a3728f4d3da3d libatomic
verify_matches_staged /kvmapp/server/NanoKVM-Server \
	"$STAGED_KVMAPP_DIR/server/NanoKVM-Server" backend-server
verify_matches_staged /kvmapp/backends/NanoKVM-Server.rust \
	"$STAGED_KVMAPP_DIR/backends/NanoKVM-Server.rust" backend-rust-copy
verify_matches_staged /kvmapp/hwmon/nanokvm-hwmon \
	"$STAGED_KVMAPP_DIR/hwmon/nanokvm-hwmon" hwmon
verify_matches_staged /kvmapp/server/dl_lib/libkvm.so \
	"$STAGED_KVMAPP_DIR/server/dl_lib/libkvm.so" libkvm
verify_matches_staged /kvmapp/server/dl_lib/libkvm_mmf.so \
	"$STAGED_KVMAPP_DIR/server/dl_lib/libkvm_mmf.so" libkvm-mmf
verify_sha256 /kvmapp/server/dl_lib/libc.so \
	fbc494806cad67edbf4584221bdc481593fa04b317d9405cf3418aad9a9500c4 vendor-libc
verify_sha256 /lib/ld-musl-riscv64xthead.so.1 \
	e966ce689d386af715ec2ca558a90661731cd875192af91749b52475629cb7d2 xhead-loader
verify_sha256 /lib/ld-musl-riscv64v0p7_xthead.so.1 \
	8e4f81c0280b2337abea47bf151259f6fa3bf3261578dee8bba30f83c60fe7e8 v0p7-loader
verify_sha256 /mnt/system/ko/soph_vcodec.ko \
	"$EXPECTED_SOPH_VCODEC_SHA256" soph-vcodec
verify_sha256 /mnt/system/ko/soph_jpeg.ko \
	"$EXPECTED_SOPH_JPEG_SHA256" soph-jpeg
verify_sha256 /mnt/system/ko/soph_vc_driver.ko \
	"$EXPECTED_SOPH_VC_DRIVER_SHA256" soph-vc-driver

MEDIA_PROVENANCE="$TMP_DIR/source-media-provenance.txt"
debugfs -R "dump /mnt/system/ko/hardened-source-media-provenance.txt $MEDIA_PROVENANCE" \
	"$IMAGE" >/dev/null 2>&1 || die "could not extract source-built media provenance"
grep -qx 'sophgo_vc_commit=5ed7cc28daf7194885d87df2aa534a27a1956c70' "$MEDIA_PROVENANCE" || \
	die "source-built VC provenance is incorrect"
grep -qx "device_acceptance=$EXPECTED_MEDIA_DEVICE_ACCEPTANCE" "$MEDIA_PROVENANCE" || \
	die "source-built media device acceptance provenance is missing"
grep -qx 'redistribution=disabled-pending-license-grant' "$MEDIA_PROVENANCE" || \
	die "source-built media redistribution restriction is missing"

if [ -n "$EXPECTED_RUNTIME_KERNEL_RELEASE" ]; then
	KERNEL_PROVENANCE="$TMP_DIR/kernel-provenance.txt"
	debugfs -R "dump /mnt/system/ko/hardened-kernel-5.10.265-provenance.txt $KERNEL_PROVENANCE" \
		"$IMAGE" >/dev/null 2>&1 || die "could not extract kernel provenance"
	grep -qx "kernel_release=$EXPECTED_RUNTIME_KERNEL_RELEASE" "$KERNEL_PROVENANCE" || \
		die "runtime kernel provenance release is incorrect"
	grep -qx 'redistribution=disabled-pending-license-grant' "$KERNEL_PROVENANCE" || \
		die "runtime kernel redistribution restriction is missing"
fi

KVM_SYSTEM="$TMP_DIR/kvm_system"
debugfs -R "dump /kvmapp/kvm_system/kvm_system $KVM_SYSTEM" "$IMAGE" >/dev/null 2>&1 || \
	die "could not extract /kvmapp/kvm_system/kvm_system"
STAGED_KVM_SYSTEM="${STAGED_KVM_SYSTEM:-$STAGED_KVMAPP_DIR/kvm_system/kvm_system}"
[ -f "$STAGED_KVM_SYSTEM" ] || die "staged kvm_system is unavailable for provenance validation"
expected_kvm_system_sha256="$(sha256sum "$STAGED_KVM_SYSTEM" | awk '{print $1}')"
actual_kvm_system_sha256="$(sha256sum "$KVM_SYSTEM" | awk '{print $1}')"
[ "$actual_kvm_system_sha256" = "$expected_kvm_system_sha256" ] || \
	die "Buildroot modified kvm_system: expected $expected_kvm_system_sha256, got $actual_kvm_system_sha256"
KVM_SYSTEM_DYNAMIC="$TMP_DIR/kvm_system.dynamic"
readelf -d "$KVM_SYSTEM" >"$KVM_SYSTEM_DYNAMIC" 2>&1 || \
	die "kvm_system dynamic table is invalid"
grep -Fq 'Shared library: [libstdc++.so.6]' "$KVM_SYSTEM_DYNAMIC" || \
	die "kvm_system is missing the libstdc++.so.6 dependency"
grep -Fq 'Shared library: [libgcc_s.so.1]' "$KVM_SYSTEM_DYNAMIC" || \
	die "kvm_system is missing the libgcc_s.so.1 dependency"
grep -Fq 'Shared library: [libc.so]' "$KVM_SYSTEM_DYNAMIC" || \
	die "kvm_system is missing the libc.so dependency"
if grep -Eq '\((RPATH|RUNPATH)\)' "$KVM_SYSTEM_DYNAMIC"; then
	die "kvm_system contains RPATH/RUNPATH and will be rewritten by Buildroot"
fi
readelf -rW "$KVM_SYSTEM" >/dev/null 2>&1 || \
	die "kvm_system relocation table is invalid"
readelf -A "$KVM_SYSTEM" 2>/dev/null | grep -Fq 'v0p7' || \
	die "kvm_system is not the expected RISC-V v0p7 binary"

python3 -B "$ROOT/scripts/verify-app-recovery-rootfs.py" "$IMAGE" || \
	die "independent app recovery does not match its protected rootfs/backend binding"
python3 -B "$ROOT/scripts/verify-native-runtime-rootfs.py" "$IMAGE" || \
	die "independent native runtimes do not match their protected rootfs/backend bindings"

KVMAPP_S95="$TMP_DIR/kvmapp-S95nanokvm"
ETC_S95="$TMP_DIR/etc-S95nanokvm"
debugfs -R "dump /kvmapp/system/init.d/S95nanokvm $KVMAPP_S95" "$IMAGE" >/dev/null 2>&1 || \
	die "could not extract packaged S95nanokvm"
debugfs -R "dump /etc/init.d/S95nanokvm $ETC_S95" "$IMAGE" >/dev/null 2>&1 || \
	die "could not extract installed S95nanokvm"
cmp -s "$KVMAPP_S95" "$ETC_S95" || \
	die "packaged and installed S95nanokvm differ"
# kvm_system is owned by the native broker: S95 asks it whether kvm_system
# runs and starts it through it. No PID file, process scan or orphan adoption.
grep -Fq '"$NATIVE_CTL" kvm-running' "$KVMAPP_S95" || \
	die "S95nanokvm does not ask the native broker whether kvm_system runs"
grep -Fq '"$NATIVE_CTL" ensure-kvm' "$KVMAPP_S95" || \
	die "S95nanokvm does not start kvm_system through the native broker"
for legacy in KVM_SYSTEM_PID_FILE find_kvm_system_pids adopt_single_kvm_system_process; do
	grep -Fq "$legacy" "$KVMAPP_S95" && \
		die "S95nanokvm still tracks or adopts kvm_system by PID ($legacy)"
done
grep -Fq 'kvm_system_is_running || return 1' "$KVMAPP_S95" || \
	die "system-update boot health does not require kvm_system"

KVMAPP_S30="$TMP_DIR/kvmapp-S30eth"
ETC_S30="$TMP_DIR/etc-S30eth"
debugfs -R "dump /kvmapp/system/init.d/S30eth $KVMAPP_S30" "$IMAGE" >/dev/null 2>&1 || \
	die "could not extract packaged S30eth"
debugfs -R "dump /etc/init.d/S30eth $ETC_S30" "$IMAGE" >/dev/null 2>&1 || \
	die "could not extract installed S30eth"
cmp -s "$KVMAPP_S30" "$ETC_S30" || \
	die "packaged and installed S30eth differ"
grep -Fq 'render_static_dns()' "$KVMAPP_S30" || \
	die "S30eth lacks idempotent static DNS rendering"
grep -Fq 'if (!seen[$2]++) print "nameserver " $2' "$KVMAPP_S30" || \
	die "S30eth does not de-duplicate static nameservers"

KVMAPP_S01="$TMP_DIR/kvmapp-S01fs"
ETC_S01="$TMP_DIR/etc-S01fs"
debugfs -R "dump /kvmapp/system/init.d/S01fs $KVMAPP_S01" "$IMAGE" >/dev/null 2>&1 || \
	die "could not extract packaged S01fs"
debugfs -R "dump /etc/init.d/S01fs $ETC_S01" "$IMAGE" >/dev/null 2>&1 || \
	die "could not extract installed S01fs"
cmp -s "$KVMAPP_S01" "$ETC_S01" || \
	die "packaged and installed S01fs differ"
# The generic rootfs gate above already checks both installed/packaged copies,
# rejects legacy p3 restore/rollback selectors and fails on inspection errors.

OS_RELEASE="$TMP_DIR/os-release"
debugfs -R "dump /usr/lib/os-release $OS_RELEASE" "$IMAGE" >/dev/null 2>&1 || \
	die "could not read /usr/lib/os-release"
grep -qx "VERSION_ID=$EXPECTED_BUILDROOT_VERSION" "$OS_RELEASE" || \
	die "unexpected Buildroot VERSION_ID"

SYSTEM_VERSION_FILE="$TMP_DIR/system-version.json"
debugfs -R "dump /etc/kvm/system-version.json $SYSTEM_VERSION_FILE" "$IMAGE" >/dev/null 2>&1 || \
	die "could not read /etc/kvm/system-version.json"
grep -q "\"version\": \"$EXPECTED_SYSTEM_VERSION\"" "$SYSTEM_VERSION_FILE" || \
	die "unexpected system update version"

SSHD_CONFIG="$TMP_DIR/sshd_config"
debugfs -R "dump /etc/ssh/sshd_config $SSHD_CONFIG" "$IMAGE" >/dev/null 2>&1 || \
	die "could not read /etc/ssh/sshd_config"
grep -qx "PermitRootLogin yes" "$SSHD_CONFIG" || \
	die "root SSH password login is not explicitly enabled"
grep -qx "PasswordAuthentication yes" "$SSHD_CONFIG" || \
	die "SSH password authentication is not explicitly enabled"
grep -qx "PermitEmptyPasswords no" "$SSHD_CONFIG" || \
	die "empty SSH passwords are not explicitly disabled"

echo "validated latest Buildroot SG2002 rootfs: $IMAGE"
echo "Buildroot version: $EXPECTED_BUILDROOT_VERSION"
echo "kvmapp version: $EXPECTED_KVMAPP_VERSION"
echo "system version: $EXPECTED_SYSTEM_VERSION"
