#!/bin/sh
# Runs inside fakeroot after Buildroot's permission table, for every image
# format. That table marks BusyBox setuid, and a raw restore refuses a setuid
# shell. Nothing on this system needs it: every service runs as root or drops
# its own privileges.
set -eu
chmod 0755 "$1/bin/busybox"

# CVE-2026-123158: without PAM, OpenSSH before 10.6p2 takes any password over
# 256 bytes for an account whose shadow field is "*" once another account has a
# hash, and a raw update carries this image's service accounts onto devices.
# Every account but root ships locked with "!". Root keeps "*" until the first
# setup gives it a hash. The file is rewritten in place to keep its mode.
shadow="$1/etc/shadow"
awk -F: -v OFS=: '$1 != "root" && length($2) < 4 && substr($2, 1, 1) != "!" { $2 = "!" $2 } { print }' \
	"$shadow" > "$shadow.locked"
cat "$shadow.locked" > "$shadow"
rm -f "$shadow.locked"
