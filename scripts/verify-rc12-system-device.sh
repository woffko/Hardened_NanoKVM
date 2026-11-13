#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BASE_VERIFIER="${RC12_BASE_VERIFIER:-$SCRIPT_DIR/verify-kernel-slab-random-only-device.sh}"
EXPECTED_BOOT_SHA256=a296fd70af3a965d105512b67254db9d7d08998b14632bfea194e2208e02b9aa
EXPECTED_SECURITY_PATCH_LEVEL='Buildroot 2026.05.1 security maintenance Linux 5.10.265 SG2002 vendor port'
EXPECTED_SERVER_SHA256=fd116fc459a1961cfc16fd0c7077a8f4c5e24d8f32d8745fd3b9744217083d6d
EXPECTED_LEGACY_PUBLIC_KEY_DER_SHA256=2167216b8ccca472124a0f5bfc7889a3ab55772c221d8540e577243a1aa90926
EXPECTED_PRODUCTION_PUBLIC_KEY_DER_SHA256=97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

[ -f "$BASE_VERIFIER" ] || fail "base device verifier is missing"
[ "$(sha256sum /boot/boot.sd | awk '{print $1}')" = "$EXPECTED_BOOT_SHA256" ] || \
	fail "running boot FIT is not the selected RC12 artifact"
grep -Fq '"version": "0.3.0-raw.12"' /etc/kvm/system-version.json || \
	fail "RC12 system version metadata is missing"
grep -Fq '"kernel_version": "5.10.265-tag-"' /etc/kvm/system-version.json || \
	fail "RC12 kernel metadata is missing"
grep -Fq "\"security_patch_level\": \"$EXPECTED_SECURITY_PATCH_LEVEL\"" \
	/etc/kvm/system-version.json || fail "RC12 security patch metadata is missing"
[ "$(sha256sum /kvmapp/server/NanoKVM-Server | awk '{print $1}')" = "$EXPECTED_SERVER_SHA256" ] || \
	fail "RC12 bridge server is not the selected artifact"
fingerprint() {
	openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | sha256sum | awk '{print $1}'
}
[ "$(fingerprint /etc/kvm/system-update-signing.pub.pem)" = "$EXPECTED_LEGACY_PUBLIC_KEY_DER_SHA256" ] || \
	fail "legacy update trust does not match"
[ "$(fingerprint /etc/kvm/update-keys/hardened-system-prod-2026q3.pub.pem)" = "$EXPECTED_PRODUCTION_PUBLIC_KEY_DER_SHA256" ] || \
	fail "production update trust does not match"
for key_id in hardened-system-dev hardened-system-test hardened-system-prod-2026q3
do
	grep -qx "$key_id" /etc/kvm/update-key-policy || fail "update trust policy is incomplete"
done

printf 'RC12_BOOT_SHA256=%s\n' "$EXPECTED_BOOT_SHA256"
printf 'RC12_SYSTEM_METADATA=exact\n'
EXPECTED_KERNEL_RELEASE=5.10.265-tag- \
EXPECTED_SYSTEM_VERSION=0.3.0-raw.12 \
EXPECTED_APP_VERSION=2.0.42 \
EXPECTED_CONFIG_SHA256=845714bfa1ab3d03ef356eb9896ad0198460aa9cd2a6d0cdb0021a5d639a9a6d \
EXPECTED_PROVENANCE_SHA256=0af808c218f094e9e8dc0e62a425a1fc77a1d14d1a25c9823f7fa7d1df7c605a \
EXPECTED_MODULE_SET_SHA256=bcc0f878699001f5e06249598ad6744d157d26cd89cb345e769eeff38cdcc961 \
EXPECTED_ROOTFS_COMMIT=9567b5f \
EXPECTED_OS_RELEASE_SHA256=31d16e0569d24a0e85bce2caf7ff8ed0b9a3f04e2be5174096c16062bea4c835 \
EXPECTED_CURL_SHA256=50fa6ba0c85ebf583def8241f5dd394e09e9ed8921d69c609d11450ce64237db \
EXPECTED_UDEVD_SHA256=0f6673ae5a6d627cea530059a39667aae7366af488164d75b5dbbabf1f0a76dd \
EXPECTED_LIBCURL_SHA256=8cff7b4619b0ed2da1cb210f857319d022dcd99cf05e0b896eb359f91559c2e5 \
EXPECTED_INIT_ON_ALLOC=on \
EXPECTED_INIT_ON_FREE=off \
	exec "$BASE_VERIFIER"
