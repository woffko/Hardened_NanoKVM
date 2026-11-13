#!/bin/sh
set -eu

EXPECTED_KERNEL_RELEASE="${EXPECTED_KERNEL_RELEASE:-5.10.265-tag-}"
EXPECTED_SYSTEM_VERSION="${EXPECTED_SYSTEM_VERSION:-0.3.0-raw.11}"
EXPECTED_APP_VERSION="${EXPECTED_APP_VERSION:-2.0.41}"
EXPECTED_CONFIG_SHA256="${EXPECTED_CONFIG_SHA256:-388f5ad008bd3193317f8a1ac20648462f430c889c142366dbf0af2c59792ccb}"
EXPECTED_PROVENANCE_SHA256="${EXPECTED_PROVENANCE_SHA256:-5158d92465e17ebdea692f3e2569a7efefc829881f4f01e9503627e76b730886}"
EXPECTED_MODULE_SET_SHA256="${EXPECTED_MODULE_SET_SHA256:-bcc0f878699001f5e06249598ad6744d157d26cd89cb345e769eeff38cdcc961}"
DMESG_ALERT_PATTERN='oops|panic|segfault|BUG:|Unknown symbol|disagrees about version|invalid module format|hung task|rcu.*stall'

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

[ "$(id -u)" = 0 ] || fail "device verifier must run as root"
[ "$(uname -r)" = "$EXPECTED_KERNEL_RELEASE" ] || fail "unexpected kernel release"
[ "$(cat /kvmapp/version)" = "$EXPECTED_APP_VERSION" ] || fail "unexpected app version"

system_version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
	/etc/kvm/system-version.json | head -n 1)"
[ "$system_version" = "$EXPECTED_SYSTEM_VERSION" ] || fail "unexpected system version"

[ -r /proc/config.gz ] || fail "running kernel config is unavailable"
config_sha256="$(zcat /proc/config.gz | sha256sum | awk '{print $1}')"
[ "$config_sha256" = "$EXPECTED_CONFIG_SHA256" ] || \
	fail "running kernel config hash does not match the reviewed slab candidate"
zcat /proc/config.gz | grep -qx 'CONFIG_SLUB=y' || \
	fail "running kernel is not using SLUB"
zcat /proc/config.gz | grep -qx 'CONFIG_SLAB_FREELIST_RANDOM=y' || \
	fail "slab freelist randomisation is missing"
zcat /proc/config.gz | grep -qx 'CONFIG_SLAB_FREELIST_HARDENED=y' || \
	fail "slab freelist hardening is missing"
zcat /proc/config.gz | grep -qx '# CONFIG_USER_NS is not set' || \
	fail "accepted user-namespace restriction is missing"
zcat /proc/config.gz | grep -qx 'CONFIG_SECURITY_DMESG_RESTRICT=y' || \
	fail "accepted dmesg restriction is missing"

userns_proc_surfaces=0
for surface in \
	/proc/self/ns/user \
	/proc/self/uid_map \
	/proc/self/gid_map \
	/proc/self/projid_map \
	/proc/self/setgroups
do
	if [ -e "$surface" ]; then
		userns_proc_surfaces=$((userns_proc_surfaces + 1))
		printf 'UNEXPECTED_USERNS_PROC_SURFACE=%s\n' "$surface"
	fi
done
[ "$userns_proc_surfaces" -eq 0 ] || \
	fail "user-namespace proc interfaces remain exposed"

userns_helpers=0
for helper in unshare nsenter newuidmap newgidmap bwrap bubblewrap
do
	if command -v "$helper" >/dev/null 2>&1; then
		userns_helpers=$((userns_helpers + 1))
		printf 'UNEXPECTED_USERNS_HELPER=%s:%s\n' "$helper" "$(command -v "$helper")"
	fi
done
[ "$userns_helpers" -eq 0 ] || fail "a namespace-management helper is installed"

[ "$(cat /proc/sys/kernel/dmesg_restrict)" = 1 ] || \
	fail "kernel.dmesg_restrict is not enabled"
dmesg >/dev/null 2>&1 || fail "root can no longer read the kernel log"

unprivileged_error="/tmp/hardened-dmesg-unprivileged.$$.err"
trap 'rm -f "$unprivileged_error"' EXIT INT TERM
if su -s /bin/sh nobody -c 'dmesg >/dev/null' 2>"$unprivileged_error"; then
	fail "unprivileged dmesg unexpectedly succeeded"
fi
grep -Eqi 'not permitted|permission denied' "$unprivileged_error" || \
	fail "unprivileged dmesg failed without a permission error"

module_count="$(find /mnt/system/ko -type f -name '*.ko' | wc -l)"
[ "$module_count" -eq 57 ] || fail "packaged runtime module inventory is not 57"
module_set_sha256="$(
	(
		cd /mnt/system/ko
		find . -type f -name '*.ko' | LC_ALL=C sort |
			while IFS= read -r module
			do
				sha256sum "$module"
			done
	) | sha256sum | awk '{print $1}'
)"
[ "$module_set_sha256" = "$EXPECTED_MODULE_SET_SHA256" ] || \
	fail "runtime module set hash does not match the reviewed candidate"
provenance=/mnt/system/ko/hardened-kernel-5.10.265-provenance.txt
[ -f "$provenance" ] || fail "kernel provenance file is missing"
provenance_sha256="$(sha256sum "$provenance" | awk '{print $1}')"
[ "$provenance_sha256" = "$EXPECTED_PROVENANCE_SHA256" ] || \
	fail "kernel provenance hash does not match the reviewed candidate"
for module in soph_sys soph_base soph_vi soph_vcodec soph_jpeg soph_vc_driver
do
	grep -q "^$module " /proc/modules || fail "required module is not loaded: $module"
done

awk '$2 == "/" && $4 ~ /(^|,)rw(,|$)/ { found=1 } END { exit !found }' /proc/mounts || \
	fail "root filesystem is not mounted read-write"
awk '$2 == "/boot" && $4 ~ /(^|,)rw(,|$)/ { found=1 } END { exit !found }' /proc/mounts || \
	fail "boot filesystem is not mounted read-write"
awk '$2 == "/data" && $4 ~ /(^|,)rw(,|$)/ { found=1 } END { exit !found }' /proc/mounts || \
	fail "data filesystem is not mounted read-write"
[ -e /sys/class/net/eth0 ] || fail "Ethernet interface is missing"

dmesg_alerts="$(dmesg | grep -Eic "$DMESG_ALERT_PATTERN" || true)"
[ "$dmesg_alerts" -eq 0 ] || fail "kernel log contains $dmesg_alerts alert lines"

temperature_samples=0
for sensor in /sys/class/thermal/thermal_zone*/temp /sys/class/hwmon/hwmon*/temp*_input
do
	[ -r "$sensor" ] || continue
	temperature_samples=$((temperature_samples + 1))
	printf 'TEMPERATURE_SAMPLE=%s:%s\n' "$sensor" "$(cat "$sensor")"
done

printf 'KERNEL=%s\n' "$(uname -r)"
printf 'CONFIG_SHA256=%s\n' "$config_sha256"
printf 'SLUB=yes\n'
printf 'SLAB_FREELIST_RANDOM=yes\n'
printf 'SLAB_FREELIST_HARDENED=yes\n'
printf 'USER_NS=disabled\n'
printf 'USERNS_PROC_SURFACES=%s\n' "$userns_proc_surfaces"
printf 'USERNS_HELPERS=%s\n' "$userns_helpers"
printf 'DMESG_RESTRICT=%s\n' "$(cat /proc/sys/kernel/dmesg_restrict)"
printf 'ROOT_DMESG=ok\n'
printf 'UNPRIVILEGED_DMESG=denied\n'
printf 'MODULES=%s\n' "$module_count"
printf 'MODULE_SET_SHA256=%s\n' "$module_set_sha256"
printf 'PROVENANCE_SHA256=%s\n' "$provenance_sha256"
printf 'DMESG_ALERTS=%s\n' "$dmesg_alerts"
printf 'UPTIME_SECONDS=%s\n' "$(cut -d' ' -f1 /proc/uptime)"
printf 'LOADAVG=%s\n' "$(cat /proc/loadavg)"
printf 'TEMPERATURE_SAMPLES=%s\n' "$temperature_samples"
printf 'SUCCESS: Phase 3 slab freelist device gate passed\n'
