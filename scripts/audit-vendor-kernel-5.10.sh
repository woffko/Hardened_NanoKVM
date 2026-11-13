#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build}"
VENDOR_KERNEL_DIR="$VENDOR_SDK_DIR/linux_5.10"
BOARD_DEFCONFIG="$VENDOR_SDK_DIR/build/boards/sg200x/sg2002_licheervnano_sd/linux/sg2002_licheervnano_sd_defconfig"
BUILT_KERNEL_CONFIG="$VENDOR_KERNEL_DIR/build/sg2002_licheervnano_sd/.config"
BUILDROOT_ARCHIVE="$ROOT_DIR/build/latestbuildroot/buildroot-2026.05.1/dl/linux/linux-5.10.258.tar.xz"
BUILDROOT_HEADER_VERSION="5.10.258"
AUDIT_DIR="${KERNEL_AUDIT_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-5.10-security-audit}"
DOWNLOAD_DIR="$AUDIT_DIR/downloads"
SOURCE_DIR="$AUDIT_DIR/sources"
REPORT_DIR="$AUDIT_DIR/report"
UPSTREAM_OLD_ARCHIVE="$DOWNLOAD_DIR/linux-5.10.4.tar.xz"
UPSTREAM_OLD_SHA256="904e396c26e9992a16cd1cc989460171536bed7739bf36049f6eb020ee5d56ec"
BUILDROOT_HEADER_SHA256="9e7ccb1efc5796e6f8398b778a8b25f7e227e7c54ef5caf6377b8c37d66fb4e5"
UPSTREAM_LTS_VERSION="5.10.265"
UPSTREAM_LTS_ARCHIVE="$DOWNLOAD_DIR/linux-$UPSTREAM_LTS_VERSION.tar.xz"
UPSTREAM_LTS_SHA256="d10cb9169e49da3d5f7154a01e450012486565fa9442e23d660b0581a3f92645"
THEAD_BASE_COMMIT="b1313fe517ca3703119dcc99ef3bbf75ab42bcfb"
THEAD_BASE_ARCHIVE="$DOWNLOAD_DIR/thead-linux-$THEAD_BASE_COMMIT.tar.gz"
THEAD_BASE_SOURCE_DIR="$SOURCE_DIR/linux-$THEAD_BASE_COMMIT"

require_file() {
    if [ ! -f "$1" ]; then
        echo "required file is missing: $1" >&2
        exit 1
    fi
}

require_dir() {
    if [ ! -d "$1" ]; then
        echo "required directory is missing: $1" >&2
        exit 1
    fi
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required command is missing: $1" >&2
        exit 1
    fi
}

require_command curl
require_command git
require_command python3
require_command sha256sum
require_command tar
require_command xz
require_dir "$VENDOR_KERNEL_DIR"
require_file "$BOARD_DEFCONFIG"
require_file "$BUILT_KERNEL_CONFIG"
require_file "$BUILDROOT_ARCHIVE"

mkdir -p "$DOWNLOAD_DIR" "$SOURCE_DIR" "$REPORT_DIR"
rm -f "$REPORT_DIR/stable-v5.10.4-to-v5.10.258-name-status.tsv"

verify_sha256() {
    expected="$1"
    file="$2"
    read -r actual _ < <(sha256sum "$file")
    if [ "$actual" != "$expected" ]; then
        echo "SHA-256 mismatch for $file: expected $expected, got $actual" >&2
        exit 1
    fi
}

if [ ! -f "$UPSTREAM_OLD_ARCHIVE" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
        --output "$UPSTREAM_OLD_ARCHIVE.part" \
        https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.4.tar.xz
    mv "$UPSTREAM_OLD_ARCHIVE.part" "$UPSTREAM_OLD_ARCHIVE"
fi

if [ ! -f "$UPSTREAM_LTS_ARCHIVE" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
        --output "$UPSTREAM_LTS_ARCHIVE.part" \
        "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-$UPSTREAM_LTS_VERSION.tar.xz"
    mv "$UPSTREAM_LTS_ARCHIVE.part" "$UPSTREAM_LTS_ARCHIVE"
fi

if [ ! -f "$THEAD_BASE_ARCHIVE" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
        --output "$THEAD_BASE_ARCHIVE.part" \
        "https://codeload.github.com/XUANTIE-RV/linux/tar.gz/$THEAD_BASE_COMMIT"
    mv "$THEAD_BASE_ARCHIVE.part" "$THEAD_BASE_ARCHIVE"
fi

xz --test "$UPSTREAM_OLD_ARCHIVE"
xz --test "$BUILDROOT_ARCHIVE"
xz --test "$UPSTREAM_LTS_ARCHIVE"
verify_sha256 "$UPSTREAM_OLD_SHA256" "$UPSTREAM_OLD_ARCHIVE"
verify_sha256 "$BUILDROOT_HEADER_SHA256" "$BUILDROOT_ARCHIVE"
verify_sha256 "$UPSTREAM_LTS_SHA256" "$UPSTREAM_LTS_ARCHIVE"

extract_once() {
    archive="$1"
    expected_dir="$2"
    if [ ! -d "$expected_dir" ]; then
        tar -xf "$archive" -C "$SOURCE_DIR"
    fi
}

extract_once "$UPSTREAM_OLD_ARCHIVE" "$SOURCE_DIR/linux-5.10.4"
extract_once "$UPSTREAM_LTS_ARCHIVE" "$SOURCE_DIR/linux-$UPSTREAM_LTS_VERSION"
extract_once "$THEAD_BASE_ARCHIVE" "$THEAD_BASE_SOURCE_DIR"

sha256sum \
    "$UPSTREAM_OLD_ARCHIVE" \
    "$BUILDROOT_ARCHIVE" \
    "$UPSTREAM_LTS_ARCHIVE" \
    "$THEAD_BASE_ARCHIVE" >"$REPORT_DIR/archive-sha256.txt"

vendor_commit="$(git -C "$VENDOR_SDK_DIR" rev-parse HEAD 2>/dev/null || true)"
vendor_shallow="$(git -C "$VENDOR_SDK_DIR" rev-parse --is-shallow-repository 2>/dev/null || printf 'unknown')"

python3 - \
    "$SOURCE_DIR/linux-5.10.4" \
    "$VENDOR_KERNEL_DIR" \
    "$THEAD_BASE_SOURCE_DIR" \
    "$SOURCE_DIR/linux-$UPSTREAM_LTS_VERSION" \
    "$BOARD_DEFCONFIG" \
    "$BUILT_KERNEL_CONFIG" \
    "$BUILDROOT_HEADER_VERSION" \
    "$REPORT_DIR" \
    "$vendor_commit" \
    "$vendor_shallow" <<'PY'
from __future__ import annotations

import hashlib
import os
from collections import Counter
from pathlib import Path
import sys

old_root = Path(sys.argv[1])
vendor_root = Path(sys.argv[2])
thead_root = Path(sys.argv[3])
new_root = Path(sys.argv[4])
defconfig = Path(sys.argv[5])
built_config = Path(sys.argv[6])
buildroot_header_version = sys.argv[7]
report_dir = Path(sys.argv[8])
vendor_commit = sys.argv[9] or "unknown"
vendor_shallow = sys.argv[10] or "unknown"

ignored_names = {
    ".git",
    ".config",
    ".scmversion",
    "Module.symvers",
    "modules.order",
}


def file_fingerprint(path: Path) -> tuple[str, str]:
    if path.is_symlink():
        return ("L", os.readlink(path))
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return ("F", digest.hexdigest())


def inventory(root: Path) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for directory, dirnames, filenames in os.walk(root):
        relative_directory = Path(directory).relative_to(root)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in ignored_names
            and not (relative_directory == Path(".") and name == "build")
        )
        for name in sorted(filenames):
            if name in ignored_names:
                continue
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            result[relative] = file_fingerprint(path)
    return result


def compare(left: dict[str, tuple[str, str]], right: dict[str, tuple[str, str]]):
    changes: dict[str, str] = {}
    for path in sorted(left.keys() | right.keys()):
        if path not in left:
            changes[path] = "A"
        elif path not in right:
            changes[path] = "D"
        elif left[path] != right[path]:
            changes[path] = "M"
    return changes


subsystems = (
    "arch/riscv/",
    "crypto/",
    "drivers/i2c/",
    "drivers/media/",
    "drivers/mmc/",
    "drivers/net/",
    "drivers/usb/",
    "fs/",
    "kernel/",
    "lib/",
    "mm/",
    "net/",
    "security/",
)


def subsystem_for(path: str) -> str:
    for prefix in subsystems:
        if path.startswith(prefix):
            return prefix.rstrip("/")
    return "other"


def write_changes(path: Path, changes: dict[str, str]) -> None:
    path.write_text(
        "".join(f"{status}\t{name}\n" for name, status in sorted(changes.items())),
        encoding="utf-8",
    )


old = inventory(old_root)
vendor = inventory(vendor_root)
thead = inventory(thead_root)
new = inventory(new_root)
vendor_changes = compare(old, vendor)
thead_changes = compare(old, thead)
post_thead_vendor_changes = compare(thead, vendor)
stable_changes = compare(old, new)
overlap = {path: vendor_changes[path] for path in vendor_changes.keys() & stable_changes.keys()}
post_thead_overlap = {
    path: post_thead_vendor_changes[path]
    for path in post_thead_vendor_changes.keys() & stable_changes.keys()
}

write_changes(report_dir / "vendor-v5.10.4-name-status.tsv", vendor_changes)
write_changes(report_dir / "thead-v5.10.4-name-status.tsv", thead_changes)
write_changes(
    report_dir / "vendor-after-thead-name-status.tsv", post_thead_vendor_changes
)
write_changes(report_dir / "stable-v5.10.4-to-v5.10.265-name-status.tsv", stable_changes)
write_changes(report_dir / "vendor-stable-exact-overlap.tsv", overlap)
write_changes(
    report_dir / "vendor-after-thead-stable-exact-overlap.tsv", post_thead_overlap
)

config: dict[str, str] = {}
for raw_line in built_config.read_text(encoding="utf-8", errors="replace").splitlines():
    line = raw_line.strip()
    if line.startswith("CONFIG_") and "=" in line:
        key, value = line.split("=", 1)
        config[key] = value
    elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
        config[line[2 : -len(" is not set")]] = "n"

security_options = (
    "CONFIG_SECURITY",
    "CONFIG_SECURITYFS",
    "CONFIG_SECURITY_YAMA",
    "CONFIG_SECURITY_DMESG_RESTRICT",
    "CONFIG_SECURITY_LOCKDOWN_LSM",
    "CONFIG_LSM",
    "CONFIG_STACKPROTECTOR",
    "CONFIG_STACKPROTECTOR_STRONG",
    "CONFIG_FORTIFY_SOURCE",
    "CONFIG_HARDENED_USERCOPY",
    "CONFIG_HARDENED_USERCOPY_FALLBACK",
    "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
    "CONFIG_INIT_ON_FREE_DEFAULT_ON",
    "CONFIG_SLAB_FREELIST_RANDOM",
    "CONFIG_SLAB_FREELIST_HARDENED",
    "CONFIG_SHUFFLE_PAGE_ALLOCATOR",
    "CONFIG_STRICT_KERNEL_RWX",
    "CONFIG_STRICT_MODULE_RWX",
    "CONFIG_RANDOMIZE_BASE",
    "CONFIG_MODULES",
    "CONFIG_MODULE_SIG",
    "CONFIG_MODULE_SIG_FORCE",
    "CONFIG_DEVMEM",
    "CONFIG_DEVKMEM",
    "CONFIG_STRICT_DEVMEM",
    "CONFIG_KEXEC",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_BPF_JIT",
    "CONFIG_BPF_JIT_ALWAYS_ON",
    "CONFIG_USER_NS",
    "CONFIG_SECCOMP",
    "CONFIG_SECCOMP_FILTER",
    "CONFIG_DEBUG_FS",
)
(report_dir / "board-security-config.tsv").write_text(
    "".join(f"{option}\t{config.get(option, 'absent')}\n" for option in security_options),
    encoding="utf-8",
)

vendor_counts = Counter(subsystem_for(path) for path in vendor_changes)
thead_counts = Counter(subsystem_for(path) for path in thead_changes)
post_thead_vendor_counts = Counter(
    subsystem_for(path) for path in post_thead_vendor_changes
)
stable_counts = Counter(subsystem_for(path) for path in stable_changes)
overlap_counts = Counter(subsystem_for(path) for path in overlap)
post_thead_overlap_counts = Counter(subsystem_for(path) for path in post_thead_overlap)

def count_table(counts: Counter[str]) -> str:
    return "\n".join(
        f"| `{name}` | {count} |" for name, count in sorted(counts.items())
    )

old_makefile = (old_root / "Makefile").read_text(encoding="utf-8", errors="replace")
vendor_makefile = (vendor_root / "Makefile").read_text(encoding="utf-8", errors="replace")
thead_makefile = (thead_root / "Makefile").read_text(encoding="utf-8", errors="replace")
new_makefile = (new_root / "Makefile").read_text(encoding="utf-8", errors="replace")

def kernel_version(makefile: str) -> str:
    values: dict[str, str] = {}
    for line in makefile.splitlines():
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in {"VERSION", "PATCHLEVEL", "SUBLEVEL", "EXTRAVERSION"}:
            values[key] = value
    return (
        f"{values.get('VERSION', '?')}.{values.get('PATCHLEVEL', '?')}."
        f"{values.get('SUBLEVEL', '?')}{values.get('EXTRAVERSION', '')}"
    )

summary = f"""# SG2002 vendor kernel 5.10 audit

This report is an inventory and backport-planning input. It does not claim that
the vendor kernel is CVE-current, ABI-compatible with upstream 5.10.265, or safe
to replace without a complete boot/module/hardware acceptance cycle.

## Provenance

- official comparison base: `{kernel_version(old_makefile)}`
- T-Head base commit imported by Milk-V: `b1313fe517ca3703119dcc99ef3bbf75ab42bcfb`
- Milk-V import commit documenting that base: `5c7dd7acc3624737c37e5db9390f5d24db6e9457`
- T-Head base version: `{kernel_version(thead_makefile)}`
- vendor source version: `{kernel_version(vendor_makefile)}`
- official stable comparison endpoint: `{kernel_version(new_makefile)}`
- Buildroot userspace header baseline (not the running kernel): `{buildroot_header_version}`
- vendor SDK commit: `{vendor_commit}`
- vendor SDK shallow repository: `{vendor_shallow}`
- board defconfig: `{defconfig}`
- built kernel config used for the security inventory: `{built_config}`

## Change inventory

- vendor paths added, removed, or modified relative to official 5.10.4: **{len(vendor_changes)}**
- T-Head base paths different from official 5.10.4: **{len(thead_changes)}**
- CVITEK/Milk-V/Sipeed paths different from the exact T-Head base: **{len(post_thead_vendor_changes)}**
- upstream paths changed from 5.10.4 through 5.10.265: **{len(stable_changes)}**
- exact paths touched by both the vendor delta and the stable series: **{len(overlap)}**
- exact paths touched by both the post-T-Head vendor delta and stable series: **{len(post_thead_overlap)}**

Exact path overlap is only a conflict-risk signal. A zero path overlap would
not prove semantic compatibility, and this audit does not attempt to apply the
stable patch series.

### Vendor delta by subsystem

| Subsystem | Changed paths |
|---|---:|
{count_table(vendor_counts)}

### T-Head base delta by subsystem

| Subsystem | Changed paths |
|---|---:|
{count_table(thead_counts)}

### CVITEK/Milk-V/Sipeed delta after the T-Head base

| Subsystem | Changed paths |
|---|---:|
{count_table(post_thead_vendor_counts)}

### Stable-series changes by subsystem

| Subsystem | Changed paths |
|---|---:|
{count_table(stable_counts)}

### Exact overlap by subsystem

| Subsystem | Changed paths |
|---|---:|
{count_table(overlap_counts)}

### Post-T-Head exact overlap by subsystem

| Subsystem | Changed paths |
|---|---:|
{count_table(post_thead_overlap_counts)}

## Required next step

1. Obtain the full vendor repository history or a documented vendor base and
   reproduce the board kernel/modules from source.
2. Preserve the vendor delta as a reviewable patch stack on an isolated kernel
   branch; do not mix modules built for another kernel image.
3. Rebase or backport in bounded subsystem batches, prioritising RISC-V, MMC,
   USB gadget/configfs/DWC2, networking, media/I2C, memory management,
   filesystems, crypto, and core security fixes.
4. For every batch, rebuild `boot.sd` and every module together, boot only from
   recoverable media, and repeat native/video/USB/HID/storage/watchdog/reboot
   gates plus kernel-log inspection.
5. Map applicable CVEs only after the actual vendor delta and final config are
   known; version-string matching alone is insufficient.

The generated top-level vendor `build/` directory is excluded from source-delta
counts. See the adjacent TSV files for the full path inventories and selected
values from the final built kernel `.config`.
"""
(report_dir / "summary.md").write_text(summary, encoding="utf-8")
print(summary)
PY

echo "kernel audit report: $REPORT_DIR/summary.md"
