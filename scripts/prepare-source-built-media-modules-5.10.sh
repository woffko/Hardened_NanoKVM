#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BASELINE_REPORT="$ROOT_DIR/build/latestbuildroot/kernel-baseline-5.10.4-v2/report/summary.md"
SOPHGO_SOURCE="$ROOT_DIR/build/latestbuildroot/sophgo-osdrv-aa542c41df94f7bc656cb740f6622a5dca7dc403"
SOPHGO_SOURCE_REPORT="${SOPHGO_SOURCE}-audit/commit.txt"
SOPHGO_MEDIA_REPORT="$ROOT_DIR/build/latestbuildroot/sophgo-media-modules-5.10.4-v2/report/summary.md"
MINIMAL_VCODEC_REPORT="$ROOT_DIR/build/latestbuildroot/minimal-vendor-vcodec-5.10.4-v2/report/summary.md"
HISTORICAL_VC_REPORT="$ROOT_DIR/build/latestbuildroot/historical-sophgo-vc-5.10.4-v2/report/summary.md"
OUTPUT_DIR="${SOURCE_BUILT_MEDIA_MODULE_DIR:-$ROOT_DIR/build/latestbuildroot/source-built-media-modules-5.10.4-v2}"

VCODEC="$ROOT_DIR/build/latestbuildroot/minimal-vendor-vcodec-5.10.4-v2/artifacts/soph_vcodec.ko"
JPEG="$ROOT_DIR/build/latestbuildroot/sophgo-media-modules-5.10.4-v2/artifacts/soph_jpeg.ko"
VC_DRIVER="$ROOT_DIR/build/latestbuildroot/historical-sophgo-vc-5.10.4-v2/artifacts/soph_vc_driver.ko"

VCODEC_SHA256="0f0927cd796275f2241e8914b3efa57b124b8cc2aabc087ee899a56346a5c2be"
JPEG_SHA256="eacf2af2c75c23816af129843912f5072c9cb81d44434d563ceb449ee2899666"
VC_DRIVER_SHA256="cc543c2a1b25c63c0372d7a687643605b1d07a5624403e3cf7d74b52ecadecf5"

run_if_missing() {
    evidence="$1"
    shift
    if [ ! -f "$evidence" ]; then
        "$@"
    fi
    [ -f "$evidence" ] || {
        echo "required build evidence was not produced: $evidence" >&2
        exit 1
    }
}

verify_sha256() {
    expected="$1"
    filename="$2"
    [ -f "$filename" ] || {
        echo "required media module is missing: $filename" >&2
        exit 1
    }
    read -r actual _ < <(sha256sum "$filename")
    if [ "$actual" != "$expected" ]; then
        echo "unexpected SHA-256 for $filename: $actual" >&2
        echo "expected: $expected" >&2
        exit 1
    fi
}

run_if_missing "$BASELINE_REPORT" "$ROOT_DIR/scripts/rebuild-vendor-kernel-5.10-baseline.sh"
run_if_missing "$SOPHGO_SOURCE_REPORT" "$ROOT_DIR/scripts/prepare-sophgo-osdrv-source.sh"
run_if_missing "$SOPHGO_MEDIA_REPORT" "$ROOT_DIR/scripts/build-sophgo-media-module-replacements.sh"
run_if_missing "$MINIMAL_VCODEC_REPORT" "$ROOT_DIR/scripts/build-minimal-vendor-vcodec-compat.sh"
run_if_missing "$HISTORICAL_VC_REPORT" "$ROOT_DIR/scripts/build-historical-sophgo-vc-driver.sh"

verify_sha256 "$VCODEC_SHA256" "$VCODEC"
verify_sha256 "$JPEG_SHA256" "$JPEG"
verify_sha256 "$VC_DRIVER_SHA256" "$VC_DRIVER"

if [ -e "$OUTPUT_DIR" ]; then
    verify_sha256 "$VCODEC_SHA256" "$OUTPUT_DIR/soph_vcodec.ko"
    verify_sha256 "$JPEG_SHA256" "$OUTPUT_DIR/soph_jpeg.ko"
    verify_sha256 "$VC_DRIVER_SHA256" "$OUTPUT_DIR/soph_vc_driver.ko"
    [ -f "$OUTPUT_DIR/provenance.txt" ] || {
        echo "source-built media provenance is missing: $OUTPUT_DIR" >&2
        exit 1
    }
    printf '%s\n' "$OUTPUT_DIR"
    printf '%s\n' "$OUTPUT_DIR/SHA256SUMS"
    exit 0
fi

mkdir -p "$OUTPUT_DIR"
cp "$VCODEC" "$OUTPUT_DIR/soph_vcodec.ko"
cp "$JPEG" "$OUTPUT_DIR/soph_jpeg.ko"
cp "$VC_DRIVER" "$OUTPUT_DIR/soph_vc_driver.ko"
chmod 0644 "$OUTPUT_DIR"/*.ko

cat >"$OUTPUT_DIR/provenance.txt" <<EOF
kernel_release=5.10.4-tag-
vendor_sdk_commit=d88d58feca49ef15f4cc7bd1f27dbf17dc25f85e
sophgo_current_commit=aa542c41df94f7bc656cb740f6622a5dca7dc403
sophgo_vc_commit=5ed7cc28daf7194885d87df2aa534a27a1956c70
soph_vcodec_sha256=$VCODEC_SHA256
soph_jpeg_sha256=$JPEG_SHA256
soph_vc_driver_sha256=$VC_DRIVER_SHA256
device_acceptance=10.0.87.133-20260821T032009Z
redistribution=disabled-pending-license-grant
EOF

find "$OUTPUT_DIR" -type f -exec touch -d '@0' {} +
(
    cd "$OUTPUT_DIR"
    sha256sum ./*.ko > SHA256SUMS
)
touch -d '@0' "$OUTPUT_DIR/SHA256SUMS"
printf '%s\n' "$OUTPUT_DIR"
printf '%s\n' "$OUTPUT_DIR/SHA256SUMS"
