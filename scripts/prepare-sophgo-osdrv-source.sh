#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OSDRV_COMMIT="aa542c41df94f7bc656cb740f6622a5dca7dc403"
HISTORICAL_VC_COMMIT="5ed7cc28daf7194885d87df2aa534a27a1956c70"
OUTPUT_DIR="${SOPHGO_OSDRV_SOURCE_DIR:-$ROOT_DIR/build/latestbuildroot/sophgo-osdrv-$OSDRV_COMMIT}"
REPORT_DIR="$OUTPUT_DIR-audit"

for command_name in git sha256sum; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "required command is missing: $command_name" >&2
        exit 1
    fi
done

if [ -e "$OUTPUT_DIR" ] || [ -e "$REPORT_DIR" ]; then
    echo "refusing to reuse SOPHGO osdrv output" >&2
    exit 1
fi

git clone --filter=blob:none --no-checkout \
    https://github.com/sophgo/osdrv.git "$OUTPUT_DIR"
git -C "$OUTPUT_DIR" fetch --depth 1 origin "$OSDRV_COMMIT"
git -C "$OUTPUT_DIR" fetch --depth 1 origin "$HISTORICAL_VC_COMMIT"
git -C "$OUTPUT_DIR" checkout --detach "$OSDRV_COMMIT"

actual_commit="$(git -C "$OUTPUT_DIR" rev-parse HEAD)"
if [ "$actual_commit" != "$OSDRV_COMMIT" ]; then
    echo "unexpected osdrv commit: $actual_commit" >&2
    exit 1
fi

for required_path in \
    interdrv/cvi_vc_drv/Makefile \
    interdrv/cvi_vc_drv/cvi_vc_drv.c \
    interdrv/jpeg/Makefile \
    interdrv/jpeg/cvi_jpeg.c; do
    if [ ! -f "$OUTPUT_DIR/$required_path" ]; then
        echo "required osdrv source is missing: $required_path" >&2
        exit 1
    fi
done

mkdir -p "$REPORT_DIR"
git -C "$OUTPUT_DIR" show -s --format=fuller HEAD >"$REPORT_DIR/commit.txt"
git -C "$OUTPUT_DIR" status --short >"$REPORT_DIR/status.txt"
git -C "$OUTPUT_DIR" ls-tree -r --full-tree HEAD \
    >"$REPORT_DIR/tracked-tree.txt"
sha256sum \
    "$OUTPUT_DIR/interdrv/cvi_vc_drv/cvi_vc_drv.c" \
    "$OUTPUT_DIR/interdrv/jpeg/cvi_jpeg.c" \
    >"$REPORT_DIR/core-source-sha256.txt"

if [ -s "$REPORT_DIR/status.txt" ]; then
    echo "SOPHGO osdrv checkout is not clean" >&2
    exit 1
fi

cat <<EOF
SOPHGO osdrv source prepared
commit: $actual_commit
historical VC commit: $HISTORICAL_VC_COMMIT
source: $OUTPUT_DIR
report: $REPORT_DIR
root license file: absent
EOF
