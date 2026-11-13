#!/usr/bin/env bash
# S01fs partition steps (L-B10), taken from the script itself and run under the
# host's sh and, when present, BusyBox sh. Stand-ins for parted, mkfs.exfat,
# sync and sleep record their calls; the disk is a temporary directory. p2 is
# grown only on a card where it ends before 8192MB, and the data partition is
# formatted only when this script created it and never finished.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
S01="$ROOT_DIR/kvmapp/system/init.d/S01fs"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

fail() {
    echo "S01fs test: $*" >&2
    exit 1
}

for name in protect_shared_directories grow_root_partition wait_for_data_device ensure_data_partition; do
    awk -v start="$name() {" '$0 == start {p = 1} p {print} p && $0 == "}" {exit}' "$S01" >> "$T/lib.sh"
    grep -qx "$name() {" "$T/lib.sh" || fail "no function $name in S01fs"
done

# A function, not a file in PATH: BusyBox sh runs its own mount applet first,
# and the real mount must never run from this test.
printf 'mount() { echo "mount $*" >> "$CALLS"; }\n' >> "$T/lib.sh"

mkdir -p "$T/bin"
cat > "$T/bin/parted" <<'EOF'
#!/bin/sh
echo "parted $*" >> "$CALLS"
[ -z "$PARTED_FAIL" ] || exit 1
case "$*" in
    *mkpart*) : > "$DATA_DEVICE" ;;
esac
cat > /dev/null
EOF
cat > "$T/bin/mkfs.exfat" <<'EOF'
#!/bin/sh
echo "mkfs.exfat $*" >> "$CALLS"
[ -z "$MKFS_FAIL" ] || exit 1
EOF
printf '#!/bin/sh\n' > "$T/bin/sync"
printf '#!/bin/sh\n' > "$T/bin/sleep"
chmod +x "$T/bin"/*

shells="sh"
command -v busybox >/dev/null 2>&1 && shells="sh busybox"

# run SHELL FUNCTION: a fresh call log; the disk state persists across runs.
run() {
    : > "$T/calls"
    status=0
    env PATH="$T/bin:$PATH" CALLS="$T/calls" PARTED_FAIL="${PARTED_FAIL:-}" MKFS_FAIL="${MKFS_FAIL:-}" \
        ROOT_DISK="$T/disk" ROOT_PARTITION="$T/sys/mmcblk0p2" ROOT_END_SECTOR=16000000 \
        DATA_DEVICE="$T/disk3" DATA_LOG="$T/data.log" DATA_READY="$T/etc/kvm.disk0" \
        DATA_PENDING="$T/etc/kvm.disk0.creating" SYSCTL_FS="$T/fs" \
        $([ "$1" = busybox ] && echo busybox) sh -c ". '$T/lib.sh'; $2" < /dev/null || status=$?
    return "$status"
}
calls() {
    cat "$T/calls"
}
reset() {
    rm -rf "$T/sys" "$T/etc" "$T/disk3"
    mkdir -p "$T/sys/mmcblk0p2" "$T/etc"
}
partition() {
    echo "$1" > "$T/sys/mmcblk0p2/start"
    echo "$2" > "$T/sys/mmcblk0p2/size"
}

for shell in $shells; do
    # Every link, hard link, file and FIFO protection of shared directories is on.
    rm -rf "$T/fs" && mkdir -p "$T/fs"
    for knob in protected_symlinks protected_hardlinks protected_regular protected_fifos; do
        echo 0 > "$T/fs/$knob"
    done
    run "$shell" protect_shared_directories || fail "$shell: protect_shared_directories failed"
    [ "$(cat "$T/fs/protected_symlinks" "$T/fs/protected_hardlinks" "$T/fs/protected_regular" \
        "$T/fs/protected_fifos" | tr '\n' ' ')" = "1 1 2 2 " ] || fail "$shell: shared directories are not protected"
    grep -qx '        protect_shared_directories' "$S01" || fail "S01fs start does not protect shared directories"
    # An older image mounts /tmp and /dev/shm with defaults; both are restricted.
    [ "$(calls)" = "mount -o remount,nosuid,nodev,noexec /tmp
mount -o remount,nosuid,nodev,noexec /dev/shm" ] || fail "$shell: shared mounts are not restricted: $(calls)"
    echo "ok $shell: links, files and FIFOs in shared directories are protected"

    reset
    partition 8192 3145728
    run "$shell" grow_root_partition || fail "$shell: grow on a fresh card"
    [ "$(calls)" = "parted -s $T/disk resizepart 2 -0
parted ---pretend-input-tty $T/disk resizepart 2 8192MB" ] || fail "$shell: fresh card calls: $(calls)"
    partition 8192 15991808
    run "$shell" grow_root_partition || fail "$shell: grown card"
    [ -z "$(calls)" ] || fail "$shell: a grown card touched the table: $(calls)"
    rm -rf "$T/sys/mmcblk0p2"
    run "$shell" grow_root_partition || fail "$shell: no sysfs entry"
    [ -z "$(calls)" ] || fail "$shell: no sysfs entry touched the table"
    echo "ok $shell: p2 grows only on a card where it ends before 8192MB"

    reset
    run "$shell" ensure_data_partition || fail "$shell: fresh data partition"
    [ "$(calls)" = "parted -s $T/disk mkpart primary 8193MB 100%
mkfs.exfat $T/disk3" ] || fail "$shell: fresh calls: $(calls)"
    [ -e "$T/etc/kvm.disk0" ] && [ ! -e "$T/etc/kvm.disk0.creating" ] || fail "$shell: fresh markers"
    run "$shell" ensure_data_partition || fail "$shell: second boot"
    [ -z "$(calls)" ] || fail "$shell: a finished partition was touched again: $(calls)"
    echo "ok $shell: a fresh card gets p3 and its filesystem once"

    reset
    : > "$T/disk3"
    run "$shell" ensure_data_partition || fail "$shell: existing partition"
    [ -z "$(calls)" ] || fail "$shell: an existing p3 was touched: $(calls)"
    [ -e "$T/etc/kvm.disk0" ] || fail "$shell: existing partition marker"
    echo "ok $shell: an existing p3 is never partitioned or formatted"

    reset
    PARTED_FAIL=1 run "$shell" ensure_data_partition && fail "$shell: a failed mkpart succeeded"
    [ -e "$T/etc/kvm.disk0.creating" ] && [ ! -e "$T/etc/kvm.disk0" ] || fail "$shell: failed mkpart markers"
    run "$shell" ensure_data_partition || fail "$shell: retry after a failed mkpart"
    [ "$(calls)" = "parted -s $T/disk mkpart primary 8193MB 100%
mkfs.exfat $T/disk3" ] || fail "$shell: retry calls: $(calls)"
    echo "ok $shell: a failed mkpart is retried on the next boot"

    reset
    MKFS_FAIL=1 run "$shell" ensure_data_partition && fail "$shell: a failed mkfs succeeded"
    [ -e "$T/etc/kvm.disk0.creating" ] && [ ! -e "$T/etc/kvm.disk0" ] || fail "$shell: failed mkfs markers"
    run "$shell" ensure_data_partition || fail "$shell: retry after a failed mkfs"
    [ "$(calls)" = "mkfs.exfat $T/disk3" ] || fail "$shell: an interrupted p3 calls: $(calls)"
    [ -e "$T/etc/kvm.disk0" ] && [ ! -e "$T/etc/kvm.disk0.creating" ] || fail "$shell: recovered markers"
    echo "ok $shell: a partition left without a filesystem is formatted on the next boot"
done
echo "S01fs test: PASS"
