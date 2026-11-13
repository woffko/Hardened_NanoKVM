#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_SDK_DIR="${HARDENED_SG2002_VENDOR_SDK_DIR:-$ROOT/build/vendor/LicheeRV-Nano-Build}"
VENDOR_OUTPUT_DIR="${HARDENED_SG2002_VENDOR_OUTPUT_DIR:-$VENDOR_SDK_DIR/install/soc_sg2002_licheervnano_sd}"
VENDOR_ROOTFS="${HARDENED_SG2002_VENDOR_ROOTFS:-$VENDOR_OUTPUT_DIR/rawimages/rootfs.sd}"
OUTPUT_DIR="${NANOKVM_VENDOR_RUNTIME_SOURCE_DIR:-$ROOT/build/latestbuildroot/vendor-runtime-source-media-v1}"
SOURCE_MEDIA_DIR="${SOURCE_BUILT_MEDIA_MODULE_DIR:-$ROOT/build/latestbuildroot/source-built-media-modules-5.10.4-v2}"

require_file() {
	[ -f "$1" ] || {
		echo "missing required file: $1" >&2
		exit 1
	}
}

require_file "$VENDOR_ROOTFS"
command -v debugfs >/dev/null 2>&1 || {
	echo "debugfs is required" >&2
	exit 1
}

if [ -e "$OUTPUT_DIR" ]; then
	echo "refusing to overwrite vendor runtime staging: $OUTPUT_DIR" >&2
	echo "set NANOKVM_VENDOR_RUNTIME_SOURCE_DIR to a new path for another extraction" >&2
	exit 1
fi

SOURCE_BUILT_MEDIA_MODULE_DIR="$SOURCE_MEDIA_DIR" \
	"$ROOT/scripts/prepare-source-built-media-modules-5.10.sh"
for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko; do
	require_file "$SOURCE_MEDIA_DIR/$module"
done

mkdir -p "$OUTPUT_DIR/kvmapp-dl-lib" "$OUTPUT_DIR/loaders"
RDUMP_LOG="$OUTPUT_DIR/debugfs-rdump.log"
if ! debugfs -R "rdump /mnt/system $OUTPUT_DIR" "$VENDOR_ROOTFS" > /dev/null 2> "$RDUMP_LOG"; then
	echo "failed to extract /mnt/system; see $RDUMP_LOG" >&2
	exit 1
fi

install -m 0644 "$SOURCE_MEDIA_DIR/soph_vcodec.ko" "$OUTPUT_DIR/system/ko/soph_vcodec.ko"
install -m 0644 "$SOURCE_MEDIA_DIR/soph_jpeg.ko" "$OUTPUT_DIR/system/ko/soph_jpeg.ko"
install -m 0644 "$SOURCE_MEDIA_DIR/soph_vc_driver.ko" "$OUTPUT_DIR/system/ko/soph_vc_driver.ko"
install -m 0644 "$SOURCE_MEDIA_DIR/provenance.txt" "$OUTPUT_DIR/system/ko/hardened-source-media-provenance.txt"

extract_file() {
	path="$1"
	dest="$2"
	expected="$3"
	debugfs -R "dump $path $dest" "$VENDOR_ROOTFS" >/dev/null 2>&1
	actual="$(sha256sum "$dest" | awk '{print $1}')"
	if [ "$actual" != "$expected" ]; then
		echo "unexpected SHA-256 for $path: $actual" >&2
		echo "expected: $expected" >&2
		exit 1
	fi
}

extract_library() {
	path="$1"
	name="$2"
	expected="$3"
	extract_file "$path" "$OUTPUT_DIR/kvmapp-dl-lib/$name" "$expected"
}

extract_library /usr/lib/libopencv_video.so.4.9.0 \
	libopencv_video.so.4.9.0 4bda8c165e9e53090cdc783a826c8c61a81ccff3a022bef5f7243a95596f52c7
extract_library /usr/lib/libopencv_dnn.so.4.9.0 \
	libopencv_dnn.so.4.9.0 3d2ae102eb4a2d2eb2e109ba23015d761ad43cf9299fdbc427e02c52377bfc79
extract_library /usr/lib/libopencv_calib3d.so.4.9.0 \
	libopencv_calib3d.so.4.9.0 119f69d7bb3c5fd033689e87faeaa37c75547a226dde150fadf01ded04e85466
extract_library /usr/lib/libopencv_features2d.so.4.9.0 \
	libopencv_features2d.so.4.9.0 f620d5466f0bd241ce70ed34d3bca07a4dc666a2addf624a2f52902e3c6ec015
extract_library /usr/lib/libopencv_flann.so.4.9.0 \
	libopencv_flann.so.4.9.0 1dadc13c42828b3fef7b3c20026b3a0263fcbcd882bfb904105de0bea1a0c991
extract_library /usr/lib/libprotobuf.so.32.0.12 \
	libprotobuf.so.32.0.12 096d35f5f085b74d6654d30bdfa91c69398093fc47548979d5c8ed4e5caebd27
extract_library /usr/lib/libstdc++.so.6.0.28 \
	libstdc++.so.6.0.28 9ebc8352014fbb7499194fdca56eb496c51c119b50d08d7b70b96058d3c5be17
extract_library /usr/lib/libgcc_s.so.1 \
	libgcc_s.so.1 4b483b84f730b5e127ee8441cc143d5d90f1a31f0bfb999f94ef834eefa3da8c
extract_library /usr/lib/libgomp.so.1.0.0 \
	libgomp.so.1.0.0 986f21b24574f0e58672c865b34d9eba102ba45c05f18a608bf612816b84c901
extract_library /usr/lib/libatomic.so.1.2.0 \
	libatomic.so.1.2.0 2421e827d033c3a055b973e6fbcf5a78fe987b50dd21e82a422a3728f4d3da3d
extract_library /lib/libc.so \
	libc.so fbc494806cad67edbf4584221bdc481593fa04b317d9405cf3418aad9a9500c4
extract_file /lib/ld-musl-riscv64xthead.so.1 \
	"$OUTPUT_DIR/loaders/ld-musl-riscv64xthead.so.1" e966ce689d386af715ec2ca558a90661731cd875192af91749b52475629cb7d2
extract_file /lib/ld-musl-riscv64v0p7_xthead.so.1 \
	"$OUTPUT_DIR/loaders/ld-musl-riscv64v0p7_xthead.so.1" 8e4f81c0280b2337abea47bf151259f6fa3bf3261578dee8bba30f83c60fe7e8

find "$OUTPUT_DIR" -type f -exec touch -d '@0' {} +
find "$OUTPUT_DIR" -type d -exec touch -d '@0' {} +
sha256sum "$OUTPUT_DIR"/kvmapp-dl-lib/* "$OUTPUT_DIR"/loaders/* > "$OUTPUT_DIR/SHA256SUMS"

printf '%s\n' "$OUTPUT_DIR"
printf '%s\n' "$OUTPUT_DIR/SHA256SUMS"
