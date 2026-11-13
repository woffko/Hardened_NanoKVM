#!/bin/sh
# Check the on-image prerequisites used before any network service starts.
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 <rootfs-image>" >&2; exit 2; }
image=$1
fail() { echo "raw restore rootfs: $*" >&2; exit 1; }
check_inode() {
    path=$1 type=$2 mode=$3
    info=$(LC_ALL=C debugfs -R "stat $path" "$image" 2>/dev/null) || fail "cannot inspect $path"
    printf '%s\n' "$info" | grep -Eq "Type: $type[[:space:]]+Mode:[[:space:]]+$mode([[:space:]]|$)" || fail "$path type/mode"
    printf '%s\n' "$info" | grep -Eq 'User:[[:space:]]+0[[:space:]]+Group:[[:space:]]+0[[:space:]]' || fail "$path owner"
}
check_inode /etc/kvm/.raw-restore directory 0700
check_inode /etc/kvm/raw-restore-required regular 0644
check_inode /usr/libexec/nanokvm-early-restore regular 0755
check_inode /etc/init.d/S01restore regular 0755
# Keep the trailing newline significant by appending a sentinel.
marker=$(debugfs -R 'cat /etc/kvm/raw-restore-required' "$image" 2>/dev/null; printf '.')
expected=$(printf 'nanokvm-raw-restore-required-v1\n.')
[ "$marker" = "$expected" ] || fail "invalid discriminator bytes"
echo 'raw restore rootfs: PASS'
