#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build}"
KERNEL_BASELINE_DIR="${KERNEL_BASELINE_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/kernel-baseline-5.10.4-v2}"
REFERENCE_BOOT_SD="${REFERENCE_BOOT_SD:-$VENDOR_SDK_DIR/install/soc_sg2002_licheervnano_sd/rawimages/boot.sd}"
RAMDISK_WORKSPACE="${VENDOR_RAMDISK_WORKSPACE:-$VENDOR_SDK_DIR/ramdisk/build/sg2002_licheervnano_sd/workspace}"
MKIMAGE="${VENDOR_MKIMAGE:-$VENDOR_SDK_DIR/build/tools/common/prebuild/mkimage}"
KEY_DIR="${VENDOR_BOOT_KEY_DIR:-$VENDOR_SDK_DIR/ramdisk/keys}"
OUTPUT_DIR="${BOOT_SD_BASELINE_OUTPUT_DIR:-$ROOT_DIR/build/latestbuildroot/boot-sd-5.10.4-v3}"
WORKSPACE="$OUTPUT_DIR/workspace"
REPORT_DIR="$OUTPUT_DIR/report"
FIT_EPOCH="1782723554"
BOOT_SD_BUILD_MODE="${BOOT_SD_BUILD_MODE:-byte-exact-baseline}"
EXPECTED_KERNEL_RELEASE="${EXPECTED_KERNEL_RELEASE:-}"

require_command() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "required command is missing: $1" >&2
		exit 1
	}
}

for command in dumpimage gzip python3 sed sha256sum
do
	require_command "$command"
done

for path in \
	"$REFERENCE_BOOT_SD" \
	"$RAMDISK_WORKSPACE/boot.cpio" \
	"$RAMDISK_WORKSPACE/multi.its" \
	"$KERNEL_BASELINE_DIR/arch/riscv/boot/Image" \
	"$KERNEL_BASELINE_DIR/arch/riscv/boot/dts/cvitek/sg2002_licheervnano_sd.dtb" \
	"$MKIMAGE" \
	"$KEY_DIR"
do
	[ -e "$path" ] || {
		echo "required boot.sd baseline input is missing: $path" >&2
		exit 1
	}
done

case "$BOOT_SD_BUILD_MODE" in
	byte-exact-baseline) ;;
	candidate)
		[ -n "$EXPECTED_KERNEL_RELEASE" ] || {
			echo "EXPECTED_KERNEL_RELEASE is required in candidate mode" >&2
			exit 1
		}
		[ -f "$KERNEL_BASELINE_DIR/include/generated/utsrelease.h" ] || {
			echo "candidate kernel release header is missing" >&2
			exit 1
		}
		kernel_release="$(sed -n 's/^#define UTS_RELEASE "\(.*\)"$/\1/p' \
			"$KERNEL_BASELINE_DIR/include/generated/utsrelease.h")"
		[ "$kernel_release" = "$EXPECTED_KERNEL_RELEASE" ] || {
			echo "unexpected boot candidate kernel release: $kernel_release" >&2
			exit 1
		}
		;;
	*)
		echo "unsupported BOOT_SD_BUILD_MODE: $BOOT_SD_BUILD_MODE" >&2
		exit 1
		;;
esac

if [ -e "$OUTPUT_DIR" ]; then
	echo "refusing to overwrite boot.sd baseline output: $OUTPUT_DIR" >&2
	exit 1
fi

mkdir -p "$WORKSPACE" "$REPORT_DIR" "$OUTPUT_DIR/reference" "$OUTPUT_DIR/candidate"

dumpimage -T flat_dt -p 0 -o "$OUTPUT_DIR/reference/Image" "$REFERENCE_BOOT_SD" >/dev/null
dumpimage -T flat_dt -p 1 -o "$OUTPUT_DIR/reference/boot.cpio.gz" "$REFERENCE_BOOT_SD" >/dev/null
dumpimage -T flat_dt -p 2 -o "$OUTPUT_DIR/reference/sg2002_licheervnano_sd.dtb" "$REFERENCE_BOOT_SD" >/dev/null

cp "$KERNEL_BASELINE_DIR/arch/riscv/boot/Image" "$WORKSPACE/Image"
cp "$KERNEL_BASELINE_DIR/arch/riscv/boot/dts/cvitek/sg2002_licheervnano_sd.dtb" \
	"$WORKSPACE/sg2002_licheervnano_sd.dtb"
cp "$RAMDISK_WORKSPACE/multi.its" "$WORKSPACE/multi.its"

python3 - \
	"$OUTPUT_DIR/reference/boot.cpio.gz" \
	"$RAMDISK_WORKSPACE/boot.cpio" \
	"$WORKSPACE/boot.cpio" <<'PY'
from __future__ import annotations

import gzip
from pathlib import Path
import sys

FIELDS = (
    "ino", "mode", "uid", "gid", "nlink", "mtime", "filesize",
    "devmajor", "devminor", "rdevmajor", "rdevminor", "namesize", "check",
)


def parse(data: bytes):
    result = []
    offset = 0
    while True:
        header_offset = offset
        header = data[offset : offset + 110]
        if len(header) != 110 or bytes(header[:6]) not in {b"070701", b"070702"}:
            raise SystemExit(f"invalid newc header at {offset}")
        values = [int(header[6 + i * 8 : 14 + i * 8], 16) for i in range(13)]
        metadata = dict(zip(FIELDS, values))
        offset += 110
        raw_name = data[offset : offset + metadata["namesize"]]
        name = raw_name[:-1].decode("utf-8", "strict")
        offset = (offset + metadata["namesize"] + 3) & ~3
        payload = data[offset : offset + metadata["filesize"]]
        offset = (offset + metadata["filesize"] + 3) & ~3
        result.append((name, metadata, payload, header_offset))
        if name == "TRAILER!!!":
            return result


with gzip.open(sys.argv[1], "rb") as stream:
    reference_bytes = stream.read()
candidate_bytes = bytearray(Path(sys.argv[2]).read_bytes())
reference = parse(reference_bytes)
candidate = parse(candidate_bytes)

if [entry[0] for entry in reference] != [entry[0] for entry in candidate]:
    raise SystemExit("candidate cpio entry order differs from accepted FIT ramdisk")

for ref_entry, candidate_entry in zip(reference, candidate):
    ref_name, ref_meta, ref_payload, _ = ref_entry
    name, metadata, payload, header_offset = candidate_entry
    for field in FIELDS:
        if field == "mtime":
            continue
        if metadata[field] != ref_meta[field]:
            raise SystemExit(f"cpio metadata differs for {name}: {field}")
    if payload != ref_payload:
        raise SystemExit(f"cpio payload differs for {name}")
    mtime_offset = header_offset + 6 + FIELDS.index("mtime") * 8
    candidate_bytes[mtime_offset : mtime_offset + 8] = f"{ref_meta['mtime']:08X}".encode("ascii")

if bytes(candidate_bytes) != reference_bytes:
    raise SystemExit("normalized candidate cpio does not match accepted FIT ramdisk")
Path(sys.argv[3]).write_bytes(candidate_bytes)
PY

# The accepted gzip header records the cpio creation epoch and source basename.
touch -d '@1782723553' "$WORKSPACE/boot.cpio"
gzip -9 -c "$WORKSPACE/boot.cpio" > "$WORKSPACE/boot.cpio.gz"
cmp -s "$WORKSPACE/boot.cpio.gz" "$OUTPUT_DIR/reference/boot.cpio.gz" || {
	echo "reconstructed ramdisk gzip differs from accepted FIT payload" >&2
	exit 1
}

# Recreate the single-board ITS emitted for CONFIG_KERNEL_UNCOMPRESSED=y.
sed -i \
	-e 's#data = /incbin/("./Image.gz");#data = /incbin/("./Image");#' \
	-e 's/compression = "gzip";/compression = "none";/g' \
	"$WORKSPACE/multi.its"

(
	cd "$WORKSPACE"
	SOURCE_DATE_EPOCH="$FIT_EPOCH" \
	LD_LIBRARY_PATH="$VENDOR_SDK_DIR/host" \
		"$MKIMAGE" -f multi.its -k "$KEY_DIR" -r boot.itb
)

dumpimage -T flat_dt -p 0 -o "$OUTPUT_DIR/candidate/Image" \
	"$WORKSPACE/boot.itb" >/dev/null
dumpimage -T flat_dt -p 1 -o "$OUTPUT_DIR/candidate/boot.cpio.gz" \
	"$WORKSPACE/boot.itb" >/dev/null
dumpimage -T flat_dt -p 2 -o "$OUTPUT_DIR/candidate/sg2002_licheervnano_sd.dtb" \
	"$WORKSPACE/boot.itb" >/dev/null
cmp -s "$OUTPUT_DIR/candidate/Image" "$WORKSPACE/Image" || {
	echo "candidate FIT kernel payload differs from selected Image" >&2
	exit 2
}
cmp -s "$OUTPUT_DIR/candidate/boot.cpio.gz" "$WORKSPACE/boot.cpio.gz" || {
	echo "candidate FIT ramdisk payload differs from reconstructed ramdisk" >&2
	exit 2
}
cmp -s "$OUTPUT_DIR/candidate/sg2002_licheervnano_sd.dtb" \
	"$WORKSPACE/sg2002_licheervnano_sd.dtb" || {
	echo "candidate FIT DTB payload differs from selected board DTB" >&2
	exit 2
}

if [ "$BOOT_SD_BUILD_MODE" = byte-exact-baseline ]; then
	cmp -s "$WORKSPACE/boot.itb" "$REFERENCE_BOOT_SD" || {
		echo "reconstructed boot.itb differs from accepted boot.sd" >&2
		exit 2
	}
else
	if cmp -s "$WORKSPACE/boot.itb" "$REFERENCE_BOOT_SD"; then
		echo "5.10.265 candidate FIT unexpectedly equals 5.10.4 baseline" >&2
		exit 2
	fi
fi

sha256sum \
	"$WORKSPACE/Image" \
	"$WORKSPACE/boot.cpio" \
	"$WORKSPACE/boot.cpio.gz" \
	"$WORKSPACE/sg2002_licheervnano_sd.dtb" \
	"$WORKSPACE/multi.its" \
	"$WORKSPACE/boot.itb" > "$REPORT_DIR/SHA256SUMS"

cat > "$REPORT_DIR/summary.md" <<EOF
# Vendor boot.sd $BOOT_SD_BUILD_MODE rebuild

- selected kernel Image embedded and extracted: **match**
- selected board DTB embedded and extracted: **match**
- source-generated ramdisk entries and payloads: **match**
- historical cpio/gzip metadata normalization: **match**
- FIT creation epoch: \`$FIT_EPOCH\`
- reconstructed boot.itb SHA-256:
  \`$(sha256sum "$WORKSPACE/boot.itb" | awk '{print $1}')\`
- accepted boot.sd SHA-256:
  \`$(sha256sum "$REFERENCE_BOOT_SD" | awk '{print $1}')\`
- build mode: **$BOOT_SD_BUILD_MODE**
- baseline byte identity required: **$([ "$BOOT_SD_BUILD_MODE" = byte-exact-baseline ] && printf yes || printf no)**

The accepted ramdisk and the current source-generated cpio contain identical
entry ordering, metadata other than mtime, and payload bytes. Historical mtimes
are restored before deterministic gzip and FIT assembly. No accepted FIT
payload is copied into the reconstructed image.
EOF

cat "$REPORT_DIR/summary.md"
printf 'boot.sd baseline report: %s\n' "$REPORT_DIR/summary.md"
