#!/bin/sh
set -eu

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

[ "$(id -u)" = 0 ] || fail "user-namespace audit must run as root"

zcat /proc/config.gz | grep -qx 'CONFIG_USER_NS=y' || \
	fail "running kernel does not have CONFIG_USER_NS=y"

init_user_ns="$(readlink /proc/1/ns/user)"
[ -n "$init_user_ns" ] || fail "cannot read init user namespace"

processes=0
different_user_namespaces=0
for proc in /proc/[0-9]*
do
	[ -e "$proc/ns/user" ] || continue
	user_ns="$(readlink "$proc/ns/user" 2>/dev/null || true)"
	[ -n "$user_ns" ] || continue
	processes=$((processes + 1))
	if [ "$user_ns" != "$init_user_ns" ]; then
		different_user_namespaces=$((different_user_namespaces + 1))
		cmdline="$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)"
		printf 'NON_INIT_USER_NS=%s:%s:%s\n' "${proc##*/}" "$user_ns" "$cmdline"
	fi
done

helpers=0
for helper in unshare nsenter newuidmap newgidmap bwrap bubblewrap
do
	if command -v "$helper" >/dev/null 2>&1; then
		helpers=$((helpers + 1))
		printf 'USER_NS_HELPER=%s:%s\n' "$helper" "$(command -v "$helper")"
	fi
done

max_user_namespaces="$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo absent)"
self_uid_map="$(tr '\n' ';' < /proc/self/uid_map 2>/dev/null || echo unreadable)"
self_gid_map="$(tr '\n' ';' < /proc/self/gid_map 2>/dev/null || echo unreadable)"

printf 'INIT_USER_NS=%s\n' "$init_user_ns"
printf 'PROCESSES_AUDITED=%s\n' "$processes"
printf 'NON_INIT_USER_NAMESPACES=%s\n' "$different_user_namespaces"
printf 'USER_NS_HELPERS=%s\n' "$helpers"
printf 'MAX_USER_NAMESPACES=%s\n' "$max_user_namespaces"
printf 'SELF_UID_MAP=%s\n' "$self_uid_map"
printf 'SELF_GID_MAP=%s\n' "$self_gid_map"

[ "$different_user_namespaces" -eq 0 ] || \
	fail "a live process uses a non-init user namespace"
[ "$helpers" -eq 0 ] || fail "a user-namespace helper is installed"

printf 'SUCCESS: no active or installed user-namespace consumer found\n'
