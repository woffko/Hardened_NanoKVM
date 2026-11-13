#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_IP="10.0.87.133"
VERSION="0.2.23-raw.1"
EXPECTED_APP_VERSION="2.0.32"
EXPECTED_ARCHIVE_SHA256="d7d50d279619f5a964c7367a3cd506385a423c1751c79220e6dc03ab5ca4b458"
API_BASE="https://$TARGET_IP"
JQ="/home/w0w/.local/bin/jq"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_DIR="$ROOT/build/latestbuildroot/device-tests/api-$VERSION-$TARGET_IP-$RUN_ID"
REPORT="$RESULT_DIR/report.txt"
RAW_ENABLED_BY_SCRIPT=0

if [[ "${1:-}" != "--confirm-device" || "${2:-}" != "$TARGET_IP" ]]; then
	printf 'refusing destructive deployment: pass --confirm-device %s\n' "$TARGET_IP" >&2
	exit 2
fi

mkdir -p "$RESULT_DIR"
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

cleanup() {
	local rc=$?
	if [[ $rc -ne 0 && "$RAW_ENABLED_BY_SCRIPT" == "1" && -n "${API_COOKIE:-}" && -n "${API_CSRF:-}" ]]; then
		api_post /api/system-update/raw-enabled '{"enabled":false}' 30 >/dev/null 2>&1 || true
	fi
	unset DEVICE_PASSWORD LOGIN_JSON API_COOKIE API_CSRF
}
trap cleanup EXIT

[[ -x "$JQ" ]] || fail "jq is unavailable"

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
	[[ "$api_code" == "0" && -n "$API_COOKIE" && -n "$API_CSRF" ]] || fail "web API login failed"
	unset response headers body LOGIN_JSON
}

api_config() {
	printf 'header = "Cookie: %s"\n' "$API_COOKIE"
	printf 'header = "x-csrf-token: %s"\n' "$API_CSRF"
	printf 'header = "Content-Type: application/json"\n'
}

api_get() {
	curl --http1.1 -kfsS --connect-timeout 10 --max-time 60 \
		--config <(api_config) "$API_BASE$1"
}

api_post() {
	local path=$1
	local body=$2
	local max_time=${3:-180}
	printf '%s' "$body" | curl --http1.1 -kfsS --connect-timeout 10 --max-time "$max_time" \
		--config <(api_config) -X POST --data-binary @- "$API_BASE$path"
}

json_code_ok() {
	[[ "$(printf '%s' "$1" | "$JQ" -r '.code // empty')" == "0" ]]
}

step "verifying the published control release inputs"
metadata="$ROOT/build/system-updates/system-latest.json"
signature="$ROOT/build/system-updates/system-latest.json.sig"
archive="$ROOT/build/system-updates/hardened-nanokvm-system-$VERSION.tar.gz"
[[ "$(sha256sum "$archive" | awk '{print $1}')" == "$EXPECTED_ARCHIVE_SHA256" ]] || fail "local control archive sha256 mismatch"
"$ROOT/scripts/verify-system-update-metadata.sh" "$metadata" "$signature" \
	"$ROOT/kvmapp/system/keys/system-update-signing.pub.pem" >/dev/null
[[ "$("$JQ" -r '.version' "$metadata")" == "$VERSION" ]] || fail "local control metadata version mismatch"

step "authenticating to the device web API"
api_login

version_json="$(api_get /api/system-update/version)"
json_code_ok "$version_json" || fail "system version API failed"
before_system="$(printf '%s' "$version_json" | "$JQ" -r '.data.current.version // empty')"
before_base="$(printf '%s' "$version_json" | "$JQ" -r '.data.current.baseVersion // .data.current.base_version // empty')"
before_kernel="$(printf '%s' "$version_json" | "$JQ" -r '.data.current.kernelVersion // .data.current.kernel_version // empty')"
unset version_json
{
	printf 'target=%s\n' "$TARGET_IP"
	printf 'before_system=%s\n' "$before_system"
	printf 'before_base=%s\n' "$before_base"
	printf 'before_kernel=%s\n' "$before_kernel"
	printf 'control_version=%s\n' "$VERSION"
	printf 'control_sha256=%s\n' "$EXPECTED_ARCHIVE_SHA256"
} >>"$REPORT"

if [[ "$before_system" == "$VERSION" ]]; then
	fail "device already runs the newest published control raw; API correctly refuses reinstall"
fi

step "checking the signed GitHub system channel from the device"
check_json="$(api_get /api/system-update/check)"
json_code_ok "$check_json" || fail "system update check API failed"
[[ "$(printf '%s' "$check_json" | "$JQ" -r '.data.latest.version // empty')" == "$VERSION" ]] || fail "device does not see the expected GitHub control release"
[[ "$(printf '%s' "$check_json" | "$JQ" -r '.data.latest.sha256 // empty')" == "$EXPECTED_ARCHIVE_SHA256" ]] || fail "device metadata sha256 differs from the GitHub control release"
[[ "$(printf '%s' "$check_json" | "$JQ" -r '.data.updateAvailable // false')" == "true" ]] || fail "control update is not considered newer"
unset check_json

step "enabling guarded raw updates"
raw_enable_json="$(api_post /api/system-update/raw-enabled '{"enabled":true}')"
json_code_ok "$raw_enable_json" || fail "failed to enable raw updates"
RAW_ENABLED_BY_SCRIPT=1
unset raw_enable_json

step "downloading and verifying the published control raw on the device"
download_json="$(api_post /api/system-update/download '{}' 1200)"
json_code_ok "$download_json" || fail "device download/verification failed"
[[ "$(printf '%s' "$download_json" | "$JQ" -r '.data.staged.version // empty')" == "$VERSION" ]] || fail "wrong version was staged"
[[ "$(printf '%s' "$download_json" | "$JQ" -r '.data.staged.destructive // false')" == "true" ]] || fail "control update is not marked destructive"
unset download_json

step "starting the published control raw updater"
set +e
install_json="$(api_post /api/system-update/install '{}' 240)"
install_rc=$?
set -e
if [[ $install_rc -eq 0 ]]; then
	json_code_ok "$install_json" || fail "control raw install API rejected the update"
fi
unset install_json API_COOKIE API_CSRF

step "waiting for updater shutdown and reboot"
went_offline=0
for _ in $(seq 1 48); do
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

step "web API returned; verifying preserved account and installed versions"
sleep 10
api_login
version_json="$(api_get /api/system-update/version)"
json_code_ok "$version_json" || fail "post-reboot system version API failed"
after_system="$(printf '%s' "$version_json" | "$JQ" -r '.data.current.version // empty')"
after_kernel="$(printf '%s' "$version_json" | "$JQ" -r '.data.current.kernelVersion // .data.current.kernel_version // empty')"
[[ "$after_system" == "$VERSION" ]] || fail "post-reboot system version mismatch"
unset version_json

app_json="$(api_get /api/application/version)"
json_code_ok "$app_json" || fail "post-reboot application version API failed"
after_app="$(printf '%s' "$app_json" | "$JQ" -r '.data.current // .data.currentVersion // .data.version // empty')"
[[ "$after_app" == "$EXPECTED_APP_VERSION" ]] || fail "post-reboot application version mismatch"
unset app_json

step "waiting for automatic boot-good confirmation"
confirmed=0
for _ in $(seq 1 18); do
	status_json="$(api_get /api/system-update/status)"
	if json_code_ok "$status_json" && [[ "$(printf '%s' "$status_json" | "$JQ" -r '.data.pending // empty')" == "" ]]; then
		confirmed=1
		break
	fi
	sleep 10
done
[[ "$confirmed" == "1" ]] || fail "control raw update was not auto-confirmed"
unset status_json

step "disabling guarded raw updates after successful control boot"
raw_disable_json="$(api_post /api/system-update/raw-enabled '{"enabled":false}')"
json_code_ok "$raw_disable_json" || fail "failed to disable raw updates"
RAW_ENABLED_BY_SCRIPT=0
unset raw_disable_json API_COOKIE API_CSRF

health_json="$(curl -kfsS --connect-timeout 5 --max-time 15 "$API_BASE/api/health")"
json_code_ok "$health_json" || fail "final health endpoint failed"
unset health_json

{
	printf 'after_system=%s\n' "$after_system"
	printf 'after_app=%s\n' "$after_app"
	printf 'after_kernel=%s\n' "$after_kernel"
	printf 'web_account_preserved=yes\n'
	printf 'boot_good=confirmed\n'
	printf 'raw_updates=disabled\n'
} >>"$REPORT"
step "SUCCESS: published control raw completed through the device GitHub/API path"
