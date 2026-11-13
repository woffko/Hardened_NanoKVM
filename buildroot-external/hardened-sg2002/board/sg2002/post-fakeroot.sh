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

# Every account can write in /tmp and /dev/shm, and nothing on this system runs
# a program from either, so both are mounted without device files, setuid bits
# or execution. A missing tmpfs line fails the build: a changed skeleton must
# not drop the options without notice.
fstab="$1/etc/fstab"
awk -v OFS='\t' '
	function with(options, flag) {
		return ("," options ",") ~ ("," flag ",") ? options : options "," flag
	}
	$1 !~ /^#/ && $3 == "tmpfs" && ($2 == "/tmp" || $2 == "/dev/shm") {
		$4 = with(with(with($4, "nosuid"), "nodev"), "noexec")
		seen[$2] = 1
	}
	{ print }
	END { exit !(seen["/tmp"] && seen["/dev/shm"]) }
' "$fstab" > "$fstab.restricted"
cat "$fstab.restricted" > "$fstab"
rm -f "$fstab.restricted"
