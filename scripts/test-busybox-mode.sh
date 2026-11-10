#!/usr/bin/env bash
# The post-fakeroot hook on the tree Buildroot leaves, and the image check on
# real ext4 images.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PATH="/usr/sbin:/sbin:$PATH"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fail() {
	echo "busybox mode test: $*" >&2
	exit 1
}
tree="$T/target"
mkdir -p "$tree/usr/bin"
ln -s usr/bin "$tree/bin"
printf 'synthetic\n' > "$tree/usr/bin/busybox"
chmod 4755 "$tree/usr/bin/busybox"
mkdir -p "$tree/etc"
printf '%s\n' 'root:*:19000:0:99999:7:::' 'daemon:*:10933:0:99999:7:::' 'nobody:*:::::::' \
	'sshd:!:19000::::::' 'svc::::::::' 'mail:$6$saltsalt$hash:::::::' > "$tree/etc/shadow"
chmod 0600 "$tree/etc/shadow"
# The skeleton's lines, with one option already present on /run.
printf '%b\n' '# <file system>\t<mount pt>\t<type>\t<options>\t<dump>\t<pass>' \
	'/dev/root\t/\text2\trw,noauto\t0\t1' 'tmpfs\t\t/dev/shm\ttmpfs\tmode=1777\t0\t0' \
	'tmpfs\t\t/tmp\t\ttmpfs\tmode=1777,nodev\t0\t0' 'tmpfs\t\t/run\t\ttmpfs\tmode=0755,nosuid,nodev\t0\t0' \
	> "$tree/etc/fstab"

image() {
	rm -f "$T/rootfs.ext4"
	mke2fs -q -t ext4 -d "$tree" "$T/rootfs.ext4" 8M
}
image
if "$ROOT/scripts/check-busybox-mode.sh" "$T/rootfs.ext4" 2>/dev/null; then
	fail "a setuid busybox passed"
fi
sh "$ROOT/buildroot-external/hardened-sg2002/board/sg2002/post-fakeroot.sh" "$tree"
[ "$(stat -c %a "$tree/usr/bin/busybox")" = 755 ] || fail "the hook left another mode"
# CVE-2026-123158: every account but root leaves locked, nothing else changes.
expected="$(printf '%s\n' 'root:*:19000:0:99999:7:::' 'daemon:!*:10933:0:99999:7:::' 'nobody:!*:::::::' \
	'sshd:!:19000::::::' 'svc:!:::::::' 'mail:$6$saltsalt$hash:::::::')"
[ "$(cat "$tree/etc/shadow")" = "$expected" ] || fail "the hook locked the accounts wrongly: $(cat "$tree/etc/shadow")"
[ "$(stat -c %a "$tree/etc/shadow")" = 600 ] || fail "the hook changed the shadow mode"
[ ! -e "$tree/etc/shadow.locked" ] || fail "the hook left its temporary file"
# /tmp and /dev/shm get nosuid, nodev and noexec once each; other lines stay.
options() {
	awk -v point="$1" '$1 !~ /^#/ && $2 == point { print $4 }' "$tree/etc/fstab"
}
[ "$(options /dev/shm)" = mode=1777,nosuid,nodev,noexec ] || fail "/dev/shm options: $(options /dev/shm)"
[ "$(options /tmp)" = mode=1777,nodev,nosuid,noexec ] || fail "/tmp options: $(options /tmp)"
[ "$(options /run)" = mode=0755,nosuid,nodev ] || fail "/run options changed: $(options /run)"
[ "$(options /)" = rw,noauto ] || fail "the root line changed: $(options /)"
[ ! -e "$tree/etc/fstab.restricted" ] || fail "the hook left its temporary fstab"
# A skeleton without one of the two lines stops the build.
cp -a "$tree" "$T/no-shm"
sed -i '/\/dev\/shm/d' "$T/no-shm/etc/fstab"
if sh "$ROOT/buildroot-external/hardened-sg2002/board/sg2002/post-fakeroot.sh" "$T/no-shm" 2>/dev/null; then
	fail "the hook accepted an fstab without /dev/shm"
fi
image
"$ROOT/scripts/check-busybox-mode.sh" "$T/rootfs.ext4" || fail "a plain busybox was refused"
rm "$tree/usr/bin/busybox"
image
if "$ROOT/scripts/check-busybox-mode.sh" "$T/rootfs.ext4" 2>/dev/null; then
	fail "an image without busybox passed"
fi
echo "busybox mode test: PASS"
