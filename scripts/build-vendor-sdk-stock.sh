#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_DIR="${LICHEERV_NANO_SDK_DIR:-$ROOT/build/vendor/LicheeRV-Nano-Build}"
BOARD="${LICHEERV_NANO_SDK_BOARD:-sg2002_licheervnano_sd}"
USER_HOME="${HOME:-/home/w0w}"
LOCAL_HOST_DEPS="$ROOT/build/host-deps/usr/sbin:$ROOT/build/host-deps/usr/bin"
CLEAN_PATH="${VENDOR_SDK_CLEAN_PATH:-$LOCAL_HOST_DEPS:$USER_HOME/.local/bin:$USER_HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/wsl/lib}"

if [ ! -f "$SDK_DIR/build/cvisetup.sh" ]; then
  echo "missing SDK checkout: $SDK_DIR" >&2
  echo "run: make vendor-sdk" >&2
  exit 1
fi

case "$CLEAN_PATH" in
  *[[:space:]]*)
    echo "VENDOR_SDK_CLEAN_PATH must not contain spaces, tabs, or newlines" >&2
    exit 1
    ;;
esac

missing_tools=()
for tool in cpio mkdosfs mcopy; do
  if ! PATH="$CLEAN_PATH" command -v "$tool" >/dev/null 2>&1; then
    missing_tools+=("$tool")
  fi
done

if [ "${#missing_tools[@]}" -ne 0 ]; then
  echo "missing required host tools in sanitized PATH: ${missing_tools[*]}" >&2
  echo "install them system-wide or unpack local packages under build/host-deps" >&2
  exit 1
fi

env -i \
  HOME="$USER_HOME" \
  USER="${USER:-$(id -un)}" \
  LOGNAME="${LOGNAME:-${USER:-$(id -un)}}" \
  SHELL=/bin/bash \
  TERM="${TERM:-xterm}" \
  PATH="$CLEAN_PATH" \
  SDK_DIR="$SDK_DIR" \
  BOARD="$BOARD" \
  bash -c 'set -eo pipefail; cd "$SDK_DIR" && source build/cvisetup.sh && defconfig "$BOARD" && build_all'

mapfile -t sd_images < <(find "$SDK_DIR/install" -maxdepth 3 -type f -name "*.img" -size +1M | sort)
if [ "${#sd_images[@]}" -eq 0 ]; then
  echo "vendor SDK build did not produce a full SD image (*.img)" >&2
  echo "partial artifacts found under $SDK_DIR/install:" >&2
  find "$SDK_DIR/install" -maxdepth 3 -type f \( -name "boot.sd" -o -name "rootfs.sd" -o -name "upgrade.zip" \) -printf "  %p\n" | sort >&2
  exit 1
fi

printf "vendor SDK stock SD images:\n"
printf "  %s\n" "${sd_images[@]}"
