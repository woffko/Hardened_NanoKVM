#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="${VENDOR_SDK_DIR:-$ROOT/build/vendor}"

SDK_REPO="${LICHEERV_NANO_SDK_REPO:-https://github.com/sipeed/LicheeRV-Nano-Build.git}"
SDK_REF="${LICHEERV_NANO_SDK_REF:-NanoKVM}"
SDK_EXPECTED_SHA="${LICHEERV_NANO_SDK_SHA:-d88d58feca49ef15f4cc7bd1f27dbf17dc25f85e}"
SDK_DIR="${LICHEERV_NANO_SDK_DIR:-$VENDOR_DIR/LicheeRV-Nano-Build}"

HOST_TOOLS_REPO="${SOPHGO_HOST_TOOLS_REPO:-https://github.com/sophgo/host-tools.git}"
HOST_TOOLS_REF="${SOPHGO_HOST_TOOLS_REF:-master}"
HOST_TOOLS_EXPECTED_SHA="${SOPHGO_HOST_TOOLS_SHA:-103c66f126fa98fcaa8b54f37fa06f6b293fd074}"
HOST_TOOLS_DIR="${SOPHGO_HOST_TOOLS_DIR:-$SDK_DIR/host-tools}"

checkout_ref() {
  local repo="$1"
  local ref="$2"
  local expected_sha="$3"
  local dir="$4"
  local origin_url
  local actual_sha

  mkdir -p "$(dirname "$dir")"

  if [ ! -d "$dir/.git" ]; then
    git init "$dir"
    git -C "$dir" remote add origin "$repo"
  else
    origin_url="$(git -C "$dir" config --get remote.origin.url || true)"
    if [ "$origin_url" != "$repo" ]; then
      echo "unexpected origin for $dir: $origin_url" >&2
      echo "expected: $repo" >&2
      exit 1
    fi
    if git -C "$dir" rev-parse --verify HEAD >/dev/null 2>&1; then
      if [ -n "$(git -C "$dir" status --porcelain)" ]; then
        echo "refusing to update dirty checkout: $dir" >&2
        exit 1
      fi
    fi
  fi

  git -C "$dir" fetch --depth=1 origin "$ref"
  git -C "$dir" checkout --detach --force FETCH_HEAD

  actual_sha="$(git -C "$dir" rev-parse HEAD)"
  if [ -n "$expected_sha" ] && [ "$actual_sha" != "$expected_sha" ]; then
    echo "unexpected revision for $dir: $actual_sha" >&2
    echo "expected: $expected_sha" >&2
    echo "set the *_SHA environment variable explicitly if this move is intended" >&2
    exit 1
  fi

  printf '%s %s\n' "$actual_sha" "$dir"
}

checkout_ref "$SDK_REPO" "$SDK_REF" "$SDK_EXPECTED_SHA" "$SDK_DIR"
checkout_ref "$HOST_TOOLS_REPO" "$HOST_TOOLS_REF" "$HOST_TOOLS_EXPECTED_SHA" "$HOST_TOOLS_DIR"

cat <<EOF

Vendor SDK is ready at:
  $SDK_DIR

Next stock-build commands:
  cd "$SDK_DIR"
  source build/cvisetup.sh
  defconfig sg2002_licheervnano_sd
  build_all

Use the stock image first. Add Hardened payloads only after the stock image
boots and video/HID/network match the current NanoKVM baseline.
EOF
