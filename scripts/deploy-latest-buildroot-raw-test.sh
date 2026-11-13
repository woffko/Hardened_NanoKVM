#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_IP="10.0.87.133"
TARGET_USER="root"
EXPECTED_HOSTNAME="secondary"
EXPECTED_ROOTFS_BYTES=1610612736
EXPECTED_BOOT_BYTES=16777216
EXPECTED_REQUIRED_FREE_BYTES=671088640
EXPECTED_ED25519="SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4"
PUBLIC_KEY="$ROOT/kvmapp/system/keys/system-update-signing.pub.pem"
REMOTE_PUBLIC_KEY=/etc/kvm/system-update-signing.pub.pem

PROFILE="${1:-}"
shift || true
EXPECTED_SOURCE_SYSTEM_VERSION=""
EXPECTED_SOURCE_APP_VERSION=""
case "$PROFILE" in
	published-0.2.23)
		VERSION="0.2.23-raw.1"
		EXPECTED_APP_VERSION="2.0.32"
		EXPECTED_ARCHIVE_SHA256="d7d50d279619f5a964c7367a3cd506385a423c1751c79220e6dc03ab5ca4b458"
		ARTIFACT_DIR="$ROOT/build/system-updates"
		;;
	latest-0.3.0)
		VERSION="0.3.0-raw.1"
		EXPECTED_APP_VERSION="2.0.36"
		EXPECTED_ARCHIVE_SHA256="6f551a605ae6e06e1df39f81d349f81e9f8bc34d8b738e5bac56ec328e3e21d0"
		ARTIFACT_DIR="$ROOT/build/latestbuildroot/raw-system-update-$VERSION/artifacts"
		;;
	raw11-lab)
		VERSION="0.3.0-raw.11"
		EXPECTED_SOURCE_SYSTEM_VERSION="0.3.0-raw.10"
		EXPECTED_SOURCE_APP_VERSION="2.0.41"
		EXPECTED_APP_VERSION="2.0.41"
		EXPECTED_ARCHIVE_SHA256="c1b8cfad21bc519dba71065d228dd3f2bd057ba5522c12735e5645f8c594ccd3"
		ARTIFACT_DIR="$ROOT/build/latestbuildroot/raw-system-update-$VERSION-secure-preflight/signed-lab-066770e"
		;;
	raw12-bridge)
		VERSION="0.3.0-raw.12"
		EXPECTED_SOURCE_SYSTEM_VERSION="0.3.0-raw.11"
		EXPECTED_SOURCE_APP_VERSION="2.0.42"
		EXPECTED_APP_VERSION="2.0.42"
		EXPECTED_ARCHIVE_SHA256="cf6bbef5599197f4b5ed926f22bed12352f2fdc275eb8f32fc8344d3ed7eae96"
		ARTIFACT_DIR="$ROOT/build/latestbuildroot/raw-system-update-$VERSION-bridge/artifacts"
		PUBLIC_KEY="$ROOT/kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem"
		REMOTE_PUBLIC_KEY=/etc/kvm/update-keys/hardened-system-prod-2026q3.pub.pem
		;;
	*)
		printf 'usage: %s {published-0.2.23|latest-0.3.0|raw11-lab|raw12-bridge} --confirm-device %s\n' "$0" "$TARGET_IP" >&2
		exit 2
		;;
esac

ARCHIVE="$ARTIFACT_DIR/hardened-nanokvm-system-$VERSION.tar.gz"
METADATA="$ARTIFACT_DIR/system-latest.json"
SIGNATURE="$ARTIFACT_DIR/system-latest.json.sig"
SSHPASS="$ROOT/build/host-deps/sshpass/usr/bin/sshpass"
JQ="/home/w0w/.local/bin/jq"
REMOTE_STAGE="/data/.hardened-kvmcache/system-update"
REMOTE_ARCHIVE="$REMOTE_STAGE/$(basename "$ARCHIVE")"
API_BASE="https://$TARGET_IP"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_DIR="$ROOT/build/latestbuildroot/device-tests/$VERSION-$TARGET_IP-$RUN_ID"
REPORT="$RESULT_DIR/report.txt"
WORK="$RESULT_DIR/work"
KNOWN_HOSTS="$RESULT_DIR/known_hosts"

if [[ "${1:-}" != "--confirm-device" || "${2:-}" != "$TARGET_IP" ]]; then
	printf 'refusing destructive deployment: pass --confirm-device %s\n' "$TARGET_IP" >&2
	exit 2
fi

mkdir -p "$WORK"
: >"$REPORT"

step() {
	printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >>"$REPORT"
}

fail() {
	step "FAILED: $1"
	printf '%s\n' "$1" >&2
	exit 1
}

on_error() {
	local rc=$?
	step "FAILED: unexpected command error rc=$rc line=${BASH_LINENO[0]:-unknown}"
	exit "$rc"
}
trap on_error ERR

IFS= read -r DEVICE_PASSWORD || fail "secret stdin was not supplied"
[[ -n "$DEVICE_PASSWORD" ]] || fail "secret stdin was empty"
trap 'unset DEVICE_PASSWORD LOGIN_JSON API_COOKIE API_CSRF' EXIT

for path in "$ARCHIVE" "$METADATA" "$SIGNATURE" "$PUBLIC_KEY" "$SSHPASS" "$JQ"; do
	[[ -e "$path" ]] || fail "required local input is missing: $path"
done
[[ -x "$SSHPASS" ]] || fail "sshpass is not executable"

step "pinning the physically confirmed SSH host key"
/usr/bin/ssh-keyscan -T 5 -t ed25519 "$TARGET_IP" >"$KNOWN_HOSTS" 2>/dev/null || fail "SSH host key scan failed"
fingerprints="$(/usr/bin/ssh-keygen -lf "$KNOWN_HOSTS")"
[[ "$fingerprints" == *"$EXPECTED_ED25519 $TARGET_IP (ED25519)"* ]] || fail "unexpected SSH host fingerprint"
unset fingerprints

SSH_OPTIONS=(
	-o ConnectTimeout=10
	-o ConnectionAttempts=1
	-o PreferredAuthentications=password,keyboard-interactive
	-o PubkeyAuthentication=no
	-o StrictHostKeyChecking=yes
	-o "UserKnownHostsFile=$KNOWN_HOSTS"
)

with_password() {
	printf '%s\n' "$DEVICE_PASSWORD" | "$SSHPASS" -d 0 "$@"
}

remote() {
	with_password ssh "${SSH_OPTIONS[@]}" "$TARGET_USER@$TARGET_IP" "$1"
}

copy_to_remote() {
	with_password scp -O "${SSH_OPTIONS[@]}" "$1" "$TARGET_USER@$TARGET_IP:$2"
}

field() {
	local key=$1
	awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$WORK/preflight.txt"
}

api_login() {
	local response headers body api_code
	LOGIN_JSON="$(printf 'admin\n%s\n' "$DEVICE_PASSWORD" | "$JQ" -R -s '
		split("\n") | {username: .[0], password: .[1]}
	')"
	response="$(printf '%s' "$LOGIN_JSON" | curl --http1.1 -kfsS --connect-timeout 10 --max-time 30 \
		-i -H 'Content-Type: application/json' --data-binary @- "$API_BASE/api/auth/login")"
	headers="${response%%$'\r\n\r\n'*}"
	body="${response#*$'\r\n\r\n'}"
	API_COOKIE="$(printf '%s\n' "$headers" | awk '
		BEGIN { IGNORECASE=1 }
		/^set-cookie: nano-kvm-token=/ {
			sub(/\r$/, ""); sub(/^set-cookie: /, ""); sub(/;.*/, ""); print; exit
		}
	')"
	API_CSRF="$(printf '%s' "$body" | "$JQ" -r '.data.csrfToken // empty')"
	api_code="$(printf '%s' "$body" | "$JQ" -r '.code // empty')"
	[[ "$api_code" == "0" && -n "$API_COOKIE" && -n "$API_CSRF" ]] || fail "API login failed"
	unset response headers body LOGIN_JSON
}

api_config() {
	printf 'header = "Cookie: %s"\n' "$API_COOKIE"
	printf 'header = "x-csrf-token: %s"\n' "$API_CSRF"
	printf 'header = "Content-Type: application/json"\n'
}

api_get() {
	curl --http1.1 -kfsS --connect-timeout 10 --max-time 30 \
		--config <(api_config) "$API_BASE$1"
}

api_post() {
	local path=$1
	local body=$2
	printf '%s' "$body" | curl --http1.1 -kfsS --connect-timeout 10 --max-time 180 \
		--config <(api_config) -X POST --data-binary @- "$API_BASE$path"
}

step "validating local signed raw update"
[[ "$(sha256sum "$ARCHIVE" | awk '{print $1}')" == "$EXPECTED_ARCHIVE_SHA256" ]] || fail "local archive sha256 mismatch"
"$ROOT/scripts/verify-system-update-metadata.sh" "$METADATA" "$SIGNATURE" "$PUBLIC_KEY" >/dev/null
tar -xOf "$ARCHIVE" manifest.json >"$WORK/manifest.json"
[[ "$("$JQ" -r '.version' "$WORK/manifest.json")" == "$VERSION" ]] || fail "manifest version mismatch"
[[ "$("$JQ" -r '.raw_images[] | select(.device == "/dev/mmcblk0p2") | .size' "$WORK/manifest.json")" == "$EXPECTED_ROOTFS_BYTES" ]] || fail "manifest rootfs size mismatch"
[[ "$("$JQ" -r '.raw_images[] | select(.device == "/dev/mmcblk0p1") | .size' "$WORK/manifest.json")" == "$EXPECTED_BOOT_BYTES" ]] || fail "manifest boot size mismatch"
[[ "$("$JQ" -r '.required_free_bytes' "$WORK/manifest.json")" == "$EXPECTED_REQUIRED_FREE_BYTES" ]] || fail "manifest free-space requirement mismatch"

"$JQ" -n \
	--argjson staged_at "$(date +%s)" \
	--slurpfile latest "$METADATA" \
	--slurpfile manifest "$WORK/manifest.json" \
	'{staged_at: $staged_at, latest: $latest[0], manifest: $manifest[0]}' \
	>"$WORK/staged.json"

step "running read-only device preflight"
remote 'set -eu
printf "UID=%s\n" "$(id -u)"
printf "HOSTNAME=%s\n" "$(hostname)"
printf "KERNEL=%s\n" "$(uname -r)"
printf "CMDLINE=%s\n" "$(cat /proc/cmdline)"
printf "ROOT_MOUNT=%s\n" "$(awk '\''$2 == "/" { print $1 ":" $3 ":" $4 }'\'' /proc/mounts)"
printf "BOOT_MOUNT=%s\n" "$(awk '\''$2 == "/boot" { print $1 ":" $3 ":" $4 }'\'' /proc/mounts)"
printf "DATA_MOUNT=%s\n" "$(awk '\''$2 == "/data" { print $1 ":" $3 ":" $4 }'\'' /proc/mounts)"
printf "DATA_FREE_KB=%s\n" "$(df -Pk /data | awk '\''NR == 2 { print $4 }'\'')"
printf "P1_SECTORS=%s\n" "$(cat /sys/class/block/mmcblk0p1/size)"
printf "P2_SECTORS=%s\n" "$(cat /sys/class/block/mmcblk0p2/size)"
printf "P3_SECTORS=%s\n" "$(cat /sys/class/block/mmcblk0p3/size)"
printf "SYSTEM_VERSION=%s\n" "$(sed -n '\''s/.*"version"[[:space:]]*:[[:space:]]*"\([^" ]*\)".*/\1/p'\'' /etc/kvm/system-version.json | head -n 1)"
printf "APP_VERSION=%s\n" "$(cat /kvmapp/version 2>/dev/null || true)"
printf "BACKEND_PID=%s\n" "$(pidof NanoKVM-Server 2>/dev/null || true)"
printf "PUBLIC_KEY=%s\n" "$([ -f /etc/kvm/system-update-signing.pub.pem ] && echo present || echo missing)"
printf "BUSYBOX=%s\n" "$([ -x /bin/busybox ] && echo present || echo missing)"
printf "MUSL_LOADER=%s\n" "$(for loader in /lib/ld-musl-riscv64*.so.1; do [ -e "$loader" ] && [ -x "$loader" ] && { printf "%s\n" "$loader"; break; }; done)"
' >"$WORK/preflight.txt"

[[ "$(field UID)" == "0" ]] || fail "remote SSH user is not root"
[[ "$(field HOSTNAME)" == "$EXPECTED_HOSTNAME" ]] || fail "unexpected target hostname"
[[ -z "$EXPECTED_SOURCE_SYSTEM_VERSION" || "$(field SYSTEM_VERSION)" == "$EXPECTED_SOURCE_SYSTEM_VERSION" ]] || fail "unexpected source system version"
[[ -z "$EXPECTED_SOURCE_APP_VERSION" || "$(field APP_VERSION)" == "$EXPECTED_SOURCE_APP_VERSION" ]] || fail "unexpected source application version"
[[ "$(field DATA_MOUNT)" == /dev/mmcblk0p3:* ]] || fail "/data is not mounted from mmcblk0p3"
[[ "$(field BOOT_MOUNT)" == /dev/mmcblk0p1:* ]] || fail "/boot is not mounted from mmcblk0p1"
[[ "$(field P1_SECTORS)" =~ ^[0-9]+$ && "$(field P1_SECTORS)" -ge 32768 ]] || fail "boot partition is too small"
[[ "$(field P2_SECTORS)" =~ ^[0-9]+$ && "$(field P2_SECTORS)" -ge 3145728 ]] || fail "rootfs partition is too small"
[[ "$(field DATA_FREE_KB)" =~ ^[0-9]+$ && "$(( $(field DATA_FREE_KB) * 1024 ))" -ge "$EXPECTED_REQUIRED_FREE_BYTES" ]] || fail "insufficient free space on /data"
[[ "$(field PUBLIC_KEY)" == "present" ]] || fail "system update public key is missing"
remote "test -f '$REMOTE_PUBLIC_KEY'" || fail "selected system update public key is missing"
[[ "$(field BUSYBOX)" == "present" ]] || fail "busybox is missing"
[[ -n "$(field MUSL_LOADER)" ]] || fail "musl loader is missing"

{
	printf 'target=%s\n' "$TARGET_IP"
	printf 'hostname=%s\n' "$(field HOSTNAME)"
	printf 'before_system=%s\n' "$(field SYSTEM_VERSION)"
	printf 'before_app=%s\n' "$(field APP_VERSION)"
	printf 'before_kernel=%s\n' "$(field KERNEL)"
	printf 'root_mount=%s\n' "$(field ROOT_MOUNT)"
	printf 'boot_mount=%s\n' "$(field BOOT_MOUNT)"
	printf 'data_mount=%s\n' "$(field DATA_MOUNT)"
	printf 'data_free_kb=%s\n' "$(field DATA_FREE_KB)"
	printf 'p1_sectors=%s\n' "$(field P1_SECTORS)"
	printf 'p2_sectors=%s\n' "$(field P2_SECTORS)"
	printf 'archive_sha256=%s\n' "$EXPECTED_ARCHIVE_SHA256"
} >>"$REPORT"

step "recording partition table without copying credential-bearing filesystems"
remote 'dd if=/dev/mmcblk0 bs=512 count=1 2>/dev/null' >"$RESULT_DIR/mmcblk0-mbr.bin"
[[ "$(wc -c <"$RESULT_DIR/mmcblk0-mbr.bin")" == "512" ]] || fail "MBR capture size mismatch"
sha256sum "$RESULT_DIR/mmcblk0-mbr.bin" >"$RESULT_DIR/mmcblk0-mbr.bin.sha256"

step "uploading archive and verified staged record to /data"
remote "set -eu; mkdir -p '$REMOTE_STAGE'; rm -rf '$REMOTE_STAGE/extract'; rm -f '$REMOTE_STAGE/progress.json' '$REMOTE_STAGE/staged.json' '$REMOTE_ARCHIVE.incoming' '$REMOTE_STAGE/staged.json.incoming' '$REMOTE_STAGE/system-latest.json.incoming' '$REMOTE_STAGE/system-latest.json.sig.incoming'"
copy_to_remote "$ARCHIVE" "$REMOTE_ARCHIVE.incoming"
copy_to_remote "$WORK/staged.json" "$REMOTE_STAGE/staged.json.incoming"
copy_to_remote "$METADATA" "$REMOTE_STAGE/system-latest.json.incoming"
copy_to_remote "$SIGNATURE" "$REMOTE_STAGE/system-latest.json.sig.incoming"
remote "set -eu
test \"\$(sha256sum '$REMOTE_ARCHIVE.incoming' | awk '{print \$1}')\" = '$EXPECTED_ARCHIVE_SHA256'
openssl dgst -sha256 -verify '$REMOTE_PUBLIC_KEY' -signature '$REMOTE_STAGE/system-latest.json.sig.incoming' '$REMOTE_STAGE/system-latest.json.incoming' >/dev/null
mv '$REMOTE_ARCHIVE.incoming' '$REMOTE_ARCHIVE'
mv '$REMOTE_STAGE/staged.json.incoming' '$REMOTE_STAGE/staged.json'
mv '$REMOTE_STAGE/system-latest.json.incoming' '$REMOTE_STAGE/system-latest.json'
mv '$REMOTE_STAGE/system-latest.json.sig.incoming' '$REMOTE_STAGE/system-latest.json.sig'
chmod 0600 '$REMOTE_ARCHIVE' '$REMOTE_STAGE/staged.json' '$REMOTE_STAGE/system-latest.json' '$REMOTE_STAGE/system-latest.json.sig'
sync"

step "authenticating to the local device API"
api_login
status_json="$(api_get /api/system-update/status)"
[[ "$(printf '%s' "$status_json" | "$JQ" -r '.code')" == "0" ]] || fail "system update status API failed"
if [[ "$(printf '%s' "$status_json" | "$JQ" -r '.data.staged.version // empty')" != "$VERSION" ]]; then
	status_error="$(printf '%s' "$status_json" | "$JQ" -r '.data.error // "none"')"
	step "staged_status_error=$status_error"
	unset status_error
	fail "backend did not accept the staged update"
fi
[[ "$(printf '%s' "$status_json" | "$JQ" -r '.data.staged.destructive // false')" == "true" ]] || fail "staged update is not marked destructive"
unset status_json

step "enabling guarded raw updates"
raw_enable_json="$(api_post /api/system-update/raw-enabled '{"enabled":true}')"
[[ "$(printf '%s' "$raw_enable_json" | "$JQ" -r '.code')" == "0" ]] || fail "failed to enable raw updates"
unset raw_enable_json

step "starting the stock Rust raw updater; p2 is written before p1"
set +e
install_json="$(api_post /api/system-update/install '{}')"
install_rc=$?
set -e
if [[ $install_rc -eq 0 ]]; then
	install_code="$(printf '%s' "$install_json" | "$JQ" -r '.code // empty' 2>/dev/null || true)"
	[[ "$install_code" == "0" ]] || fail "raw install API rejected the update"
fi
unset install_json install_code API_COOKIE API_CSRF

step "waiting for updater shutdown and reboot"
went_offline=0
for _ in $(seq 1 36); do
	if ! curl -kfsS --connect-timeout 2 --max-time 3 "$API_BASE/api/health" >/dev/null 2>&1; then
		went_offline=1
		break
	fi
	sleep 5
done
[[ "$went_offline" == "1" ]] || step "warning: HTTPS outage was too short to observe"

came_online=0
for _ in $(seq 1 180); do
	if curl -kfsS --connect-timeout 3 --max-time 5 "$API_BASE/api/health" >/dev/null 2>&1; then
		came_online=1
		break
	fi
	sleep 5
done
[[ "$came_online" == "1" ]] || fail "device did not return to HTTPS within 15 minutes"

step "device returned; validating the new rootfs over SSH"
for _ in $(seq 1 24); do
	if remote 'true' >/dev/null 2>&1; then
		break
	fi
	sleep 5
done
remote 'true' >/dev/null 2>&1 || fail "SSH did not return with preserved credentials"

remote 'set -eu
printf "SYSTEM_VERSION=%s\n" "$(sed -n '\''s/.*"version"[[:space:]]*:[[:space:]]*"\([^" ]*\)".*/\1/p'\'' /etc/kvm/system-version.json | head -n 1)"
printf "APP_VERSION=%s\n" "$(cat /kvmapp/version)"
printf "KERNEL=%s\n" "$(uname -r)"
printf "ROOT_MOUNT=%s\n" "$(awk '\''$2 == "/" { print $1 ":" $3 ":" $4 }'\'' /proc/mounts)"
printf "BOOT_MOUNT=%s\n" "$(awk '\''$2 == "/boot" { print $1 ":" $3 ":" $4 }'\'' /proc/mounts)"
printf "DATA_MOUNT=%s\n" "$(awk '\''$2 == "/data" { print $1 ":" $3 ":" $4 }'\'' /proc/mounts)"
BACKEND_PID="$(cat /tmp/nanokvm-server.pid 2>/dev/null || true)"
[ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null || BACKEND_PID=''
KVM_SYSTEM_PID="$(cat /tmp/kvm-system.pid 2>/dev/null || true)"
[ -n "$KVM_SYSTEM_PID" ] && kill -0 "$KVM_SYSTEM_PID" 2>/dev/null || KVM_SYSTEM_PID=''
printf "BACKEND_PID=%s\n" "$BACKEND_PID"
printf "KVM_SYSTEM_PID=%s\n" "$KVM_SYSTEM_PID"
printf "WEB_INDEX=%s\n" "$([ -f /kvmapp/server/web/index.html ] && echo present || echo missing)"
printf "RESTORE_DONE=%s\n" "$([ -f /data/.hardened-kvmcache/system-update/root-restore-done ] && echo present || echo missing)"
printf "RAW_MARKER=%s\n" "$([ -f /data/hardened-system-raw-update-pending.json ] && echo present || echo cleared)"
printf "BOOT_GOOD=%s\n" "$([ -f /etc/kvm/system-update-boot-good.json ] && echo present || echo missing)"
printf "LOG_TAIL_BEGIN\n"
tail -n 25 /data/hardened-system-raw-update.log 2>/dev/null || true
printf "LOG_TAIL_END\n"
' >"$WORK/postflight.txt"

post_field() {
	local key=$1
	awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$WORK/postflight.txt"
}

[[ "$(post_field SYSTEM_VERSION)" == "$VERSION" ]] || fail "new system version mismatch"
[[ "$(post_field APP_VERSION)" == "$EXPECTED_APP_VERSION" ]] || fail "new app version mismatch"
[[ -n "$(post_field BACKEND_PID)" ]] || fail "NanoKVM-Server is not running"
[[ -n "$(post_field KVM_SYSTEM_PID)" ]] || fail "kvm_system is not running"
[[ "$(post_field WEB_INDEX)" == "present" ]] || fail "web root is missing"
[[ "$(post_field RESTORE_DONE)" == "present" ]] || fail "preserved root configuration was not restored"

step "waiting for automatic boot-good confirmation"
for _ in $(seq 1 18); do
	if [[ "$(remote '[ -f /data/hardened-system-raw-update-pending.json ] && echo pending || echo cleared')" == "cleared" ]]; then
		break
	fi
	sleep 10
done
[[ "$(remote '[ -f /data/hardened-system-raw-update-pending.json ] && echo pending || echo cleared')" == "cleared" ]] || fail "raw update marker was not auto-confirmed"

step "disabling guarded raw updates after successful boot"
api_login
raw_disable_json="$(api_post /api/system-update/raw-enabled '{"enabled":false}')"
[[ "$(printf '%s' "$raw_disable_json" | "$JQ" -r '.code')" == "0" ]] || fail "failed to disable raw updates"
unset raw_disable_json API_COOKIE API_CSRF

health_json="$(curl -kfsS --connect-timeout 5 --max-time 15 "$API_BASE/api/health")"
[[ "$(printf '%s' "$health_json" | "$JQ" -r '.code')" == "0" ]] || fail "final health endpoint failed"
unset health_json

{
	printf 'after_system=%s\n' "$(post_field SYSTEM_VERSION)"
	printf 'after_app=%s\n' "$(post_field APP_VERSION)"
	printf 'after_kernel=%s\n' "$(post_field KERNEL)"
	printf 'after_root_mount=%s\n' "$(post_field ROOT_MOUNT)"
	printf 'after_boot_mount=%s\n' "$(post_field BOOT_MOUNT)"
	printf 'after_data_mount=%s\n' "$(post_field DATA_MOUNT)"
	printf 'backend_pid=%s\n' "$(post_field BACKEND_PID)"
	printf 'kvm_system_pid=%s\n' "$(post_field KVM_SYSTEM_PID)"
	printf 'boot_good=confirmed\n'
	printf 'raw_updates=disabled\n'
} >>"$REPORT"

sed -n '/LOG_TAIL_BEGIN/,/LOG_TAIL_END/p' "$WORK/postflight.txt" >>"$REPORT"
step "SUCCESS: raw update deployment and basic boot validation completed"
