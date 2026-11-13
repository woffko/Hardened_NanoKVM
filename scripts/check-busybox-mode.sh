#!/bin/sh
# Refuses a root filesystem image whose BusyBox is anything but plain 0755.
set -eu
[ "$#" = 1 ] || { echo "usage: $0 <rootfs image>" >&2; exit 2; }
mode="$(LC_ALL=C debugfs -R 'stat /usr/bin/busybox' "$1" 2>/dev/null |
	sed -n 's/.*Mode:  *\([0-7]*\).*/\1/p')"
case "$mode" in
	0755) ;;
	'') echo "busybox is missing from the rootfs image" >&2; exit 1 ;;
	*) echo "busybox has mode $mode, expected 0755" >&2; exit 1 ;;
esac
