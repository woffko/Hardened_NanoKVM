#!/usr/bin/env bash
# The byte count of an uncompressed image keeps the fractional bytes-per-pixel
# factor of the size table: a 1920x1080 frame of the 4:2:0 capture format is
# 3110400 bytes, not 2073600. An optional argument names another copy of the
# helper header to test (for negative controls).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HEADER=${1:-$ROOT/support/sg2002/additional/vision/include_private/maix_image_size.hpp}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cp "$HEADER" "$WORK/maix_image_size.hpp"
c++ -std=c++17 -O1 -Wall -Wextra -Werror -I "$WORK" \
	"$ROOT/support/sg2002/kvm_vision_host_test/image_size_test.cpp" -o "$WORK/image_size_test"
"$WORK/image_size_test"

# The image source must take its sizes from the helper, not from the table
# with a cast of its own.
SOURCE=$ROOT/support/sg2002/additional/vision/src/maix_image.cpp
if grep -nE 'static_cast<(size_t|int|unsigned)>\((image::)?fmt_size\[' "$SOURCE"; then
	echo "image size test: maix_image.cpp rounds a bytes-per-pixel factor" >&2
	exit 1
fi
[ "$(grep -c 'uncompressed_bytes(' "$SOURCE")" -ge 2 ] || {
	echo "image size test: maix_image.cpp does not use the size helper in both places" >&2
	exit 1
}
