#!/bin/sh
set -eu

ITERATIONS="${SLAB_BENCH_ITERATIONS:-7}"
FILES_PER_ITERATION="${SLAB_BENCH_FILES:-2048}"
WARMUP_FILES="${SLAB_BENCH_WARMUP_FILES:-512}"
DMESG_ALERT_PATTERN='oops|panic|segfault|BUG:|Unknown symbol|disagrees about version|invalid module format|hung task|rcu.*stall'

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

case "$ITERATIONS" in
	''|*[!0-9]*) fail "SLAB_BENCH_ITERATIONS must be an integer" ;;
esac
case "$FILES_PER_ITERATION" in
	''|*[!0-9]*) fail "SLAB_BENCH_FILES must be an integer" ;;
esac
case "$WARMUP_FILES" in
	''|*[!0-9]*) fail "SLAB_BENCH_WARMUP_FILES must be an integer" ;;
esac
[ "$ITERATIONS" -ge 3 ] && [ "$ITERATIONS" -le 15 ] || \
	fail "SLAB_BENCH_ITERATIONS must be from 3 through 15"
[ "$FILES_PER_ITERATION" -ge 256 ] && [ "$FILES_PER_ITERATION" -le 8192 ] || \
	fail "SLAB_BENCH_FILES must be from 256 through 8192"
[ "$WARMUP_FILES" -ge 64 ] && [ "$WARMUP_FILES" -le "$FILES_PER_ITERATION" ] || \
	fail "SLAB_BENCH_WARMUP_FILES is outside the allowed range"
[ "$(id -u)" = 0 ] || fail "slab benchmark must run as root"
[ -r /proc/config.gz ] || fail "running kernel config is unavailable"

work_dir="/tmp/hardened-slab-benchmark.$$"
durations="$work_dir/durations.txt"
trap 'rm -rf "$work_dir"' EXIT INT TERM
mkdir -m 0700 "$work_dir"
: > "$durations"

uptime_centiseconds() {
	awk '{ printf "%.0f\n", $1 * 100 }' /proc/uptime
}

temperature_sample() {
	for sensor in /sys/class/thermal/thermal_zone*/temp /sys/class/hwmon/hwmon*/temp*_input
	do
		[ -r "$sensor" ] || continue
		printf '%s:%s\n' "$sensor" "$(cat "$sensor")"
		return
	done
	printf 'absent\n'
}

run_workload() {
	file_count="$1"
	run_dir="$work_dir/run"
	rm -rf "$run_dir"
	mkdir "$run_dir"
	start_cs="$(uptime_centiseconds)"
	i=0
	while [ "$i" -lt "$file_count" ]
	do
		: > "$run_dir/object.$i"
		i=$((i + 1))
	done
	observed="$(find "$run_dir" -type f | wc -l)"
	[ "$observed" -eq "$file_count" ] || fail "tmpfs workload file count mismatch"
	LC_ALL=C ls -l "$run_dir" >/dev/null
	rm -rf "$run_dir"
	end_cs="$(uptime_centiseconds)"
	printf '%s\n' "$(((end_cs - start_cs) * 10))"
}

dmesg_alerts_before="$(dmesg | grep -Eic "$DMESG_ALERT_PATTERN" || true)"
[ "$dmesg_alerts_before" -eq 0 ] || \
	fail "kernel log already contains $dmesg_alerts_before alert lines"

config_sha256="$(zcat /proc/config.gz | sha256sum | awk '{print $1}')"
temperature_before="$(temperature_sample)"
loadavg_before="$(cat /proc/loadavg)"
meminfo_before="$(awk '/^(Slab|SReclaimable|SUnreclaim):/ { printf "%s=%s%s;", $1, $2, $3 }' /proc/meminfo)"

run_workload "$WARMUP_FILES" >/dev/null

iteration=1
while [ "$iteration" -le "$ITERATIONS" ]
do
	duration_ms="$(run_workload "$FILES_PER_ITERATION")"
	printf '%s\n' "$duration_ms" >> "$durations"
	printf 'ITERATION_%s_MS=%s\n' "$iteration" "$duration_ms"
	iteration=$((iteration + 1))
done

sorted="$work_dir/durations.sorted"
LC_ALL=C sort -n "$durations" > "$sorted"
median_line=$(((ITERATIONS + 1) / 2))
minimum_ms="$(sed -n '1p' "$sorted")"
median_ms="$(sed -n "${median_line}p" "$sorted")"
maximum_ms="$(sed -n "${ITERATIONS}p" "$sorted")"
total_ms="$(awk '{ sum += $1 } END { print sum + 0 }' "$durations")"

temperature_after="$(temperature_sample)"
loadavg_after="$(cat /proc/loadavg)"
meminfo_after="$(awk '/^(Slab|SReclaimable|SUnreclaim):/ { printf "%s=%s%s;", $1, $2, $3 }' /proc/meminfo)"
dmesg_alerts_after="$(dmesg | grep -Eic "$DMESG_ALERT_PATTERN" || true)"
[ "$dmesg_alerts_after" -eq 0 ] || \
	fail "kernel log contains $dmesg_alerts_after alert lines after benchmark"

printf 'KERNEL=%s\n' "$(uname -r)"
printf 'CONFIG_SHA256=%s\n' "$config_sha256"
printf 'ITERATIONS=%s\n' "$ITERATIONS"
printf 'FILES_PER_ITERATION=%s\n' "$FILES_PER_ITERATION"
printf 'WARMUP_FILES=%s\n' "$WARMUP_FILES"
printf 'MINIMUM_MS=%s\n' "$minimum_ms"
printf 'MEDIAN_MS=%s\n' "$median_ms"
printf 'MAXIMUM_MS=%s\n' "$maximum_ms"
printf 'TOTAL_MS=%s\n' "$total_ms"
printf 'TEMPERATURE_BEFORE=%s\n' "$temperature_before"
printf 'TEMPERATURE_AFTER=%s\n' "$temperature_after"
printf 'LOADAVG_BEFORE=%s\n' "$loadavg_before"
printf 'LOADAVG_AFTER=%s\n' "$loadavg_after"
printf 'MEMINFO_BEFORE=%s\n' "$meminfo_before"
printf 'MEMINFO_AFTER=%s\n' "$meminfo_after"
printf 'DMESG_ALERTS_BEFORE=%s\n' "$dmesg_alerts_before"
printf 'DMESG_ALERTS_AFTER=%s\n' "$dmesg_alerts_after"
printf 'SUCCESS: slab benchmark complete\n'
