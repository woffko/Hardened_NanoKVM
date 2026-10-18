#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/scripts/lib/build-security.sh"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build}"
STAGE_DIR="${STAGE_DIR:-$BUILD_DIR/kvmapp-rust}"
KVMAPP_STAGE="$STAGE_DIR/kvmapp"
OUT_DIR="${OUT_DIR:-$BUILD_DIR/artifacts}"
RUST_TARGET="${RUST_TARGET:-}"
RUST_BUILD_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/server-rust/target}"
case "$RUST_BUILD_DIR" in /*) ;; *) RUST_BUILD_DIR="$PWD/$RUST_BUILD_DIR" ;; esac
RUST_BINARY="${RUST_BINARY:-}"
HWMON_BINARY="${HWMON_BINARY:-}"
WEB_DIST="${WEB_DIST:-$ROOT_DIR/web/dist}"
APP_VERSION="${APP_VERSION:-}"
ARTIFACT_NAME="${ARTIFACT_NAME:-nanokvm-kvmapp-rust.tar.gz}"
BASE_ROOTFS_IMAGE="${BASE_ROOTFS_IMAGE:-$BUILD_DIR/sd-image/rootfs.ext}"
KVM_SYSTEM_SOURCE="${KVM_SYSTEM_SOURCE:-}"
KVM_SYSTEM_BUILD_SOURCE="${KVM_SYSTEM_BUILD_SOURCE:-$ROOT_DIR/support/sg2002/kvm_system/build/kvm_system}"
NATIVE_LIB_DIR="${NATIVE_LIB_DIR:-$ROOT_DIR/server-rust/native/dl_lib}"
EXTRA_NATIVE_LIB_DIR="${EXTRA_NATIVE_LIB_DIR:-}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1782723554}"

case "$SOURCE_DATE_EPOCH" in
  '' | *[!0-9]*)
    echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2
    exit 1
    ;;
esac

restore_kvm_system_helper() {
  dest="$KVMAPP_STAGE/kvm_system/kvm_system"
  tmp="$STAGE_DIR/kvm_system.orig"

  mkdir -p "$KVMAPP_STAGE/kvm_system"

  if [ -n "$KVM_SYSTEM_SOURCE" ] && [ -s "$KVM_SYSTEM_SOURCE" ]; then
    cp "$KVM_SYSTEM_SOURCE" "$dest"
    chmod 0755 "$dest"
    return
  fi

  if [ -s "$KVM_SYSTEM_BUILD_SOURCE" ]; then
    cp "$KVM_SYSTEM_BUILD_SOURCE" "$dest"
    chmod 0755 "$dest"
    return
  fi

  if [ -s "$dest" ]; then
    chmod 0755 "$dest"
    return
  fi

  if [ -d "$ROOT_DIR/support/sg2002/kvm_system/main" ]; then
    echo "missing built NanoKVM helper: $KVM_SYSTEM_BUILD_SOURCE" >&2
    echo "run: PATH=/tmp/codex-bin:\$PATH make -C support/sg2002/kvm_system/build -j16" >&2
    echo "or set KVM_SYSTEM_SOURCE=<path>" >&2
    exit 1
  fi

  if [ -f "$BASE_ROOTFS_IMAGE" ] && command -v debugfs >/dev/null 2>&1; then
    rm -f "$tmp"
    if debugfs -R "dump /kvmapp/kvm_system/kvm_system $tmp" "$BASE_ROOTFS_IMAGE" >/dev/null 2>&1 && [ -s "$tmp" ]; then
      cp "$tmp" "$dest"
      chmod 0755 "$dest"
      return
    fi
  fi

  echo "missing required NanoKVM helper: /kvmapp/kvm_system/kvm_system" >&2
  echo "set KVM_SYSTEM_SOURCE=<path> or BASE_ROOTFS_IMAGE=<rootfs.ext>" >&2
  exit 1
}

if [ -z "$RUST_BINARY" ]; then
  if [ -n "$RUST_TARGET" ]; then
    RUST_BINARY="$RUST_BUILD_DIR/$RUST_TARGET/release/nanokvm-rust-server"
  else
    RUST_BINARY="$RUST_BUILD_DIR/release/nanokvm-rust-server"
  fi
fi

if [ -z "$HWMON_BINARY" ]; then
  if [ -n "$RUST_TARGET" ]; then
    HWMON_BINARY="$RUST_BUILD_DIR/$RUST_TARGET/release/nanokvm-hwmon"
  else
    HWMON_BINARY="$RUST_BUILD_DIR/release/nanokvm-hwmon"
  fi
fi

if [ ! -x "$RUST_BINARY" ]; then
  echo "missing executable Rust backend: $RUST_BINARY" >&2
  echo "run: make rust-app RUST_TARGET=<target>" >&2
  exit 1
fi

if [ ! -x "$HWMON_BINARY" ]; then
  echo "missing executable Rust hwmon helper: $HWMON_BINARY" >&2
  echo "run: make rust-app RUST_TARGET=<target>" >&2
  exit 1
fi

if [ ! -f "$NATIVE_LIB_DIR/libkvm.so" ]; then
  echo "missing NanoKVM native runtime libraries: $NATIVE_LIB_DIR/libkvm.so" >&2
  exit 1
fi

STAGE_LOCK="$STAGE_DIR.lock"
mkdir -p "$(dirname "$STAGE_DIR")"
mkdir "$STAGE_LOCK" || { echo "application stage is already locked" >&2; exit 1; }
PACKAGE_WORK=
PACKAGE_LOCK=
trap '[ -z "$PACKAGE_WORK" ] || rm -rf "$PACKAGE_WORK"; [ -z "$PACKAGE_LOCK" ] || rmdir "$PACKAGE_LOCK"; rmdir "$STAGE_LOCK"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
rm -rf "$STAGE_DIR"
mkdir -p "$KVMAPP_STAGE/server" "$KVMAPP_STAGE/backends" "$KVMAPP_STAGE/hwmon" "$OUT_DIR"
cp -R "$ROOT_DIR/kvmapp/." "$KVMAPP_STAGE/"
rm -rf "$KVMAPP_STAGE/jpg_stream"
rm -f "$KVMAPP_STAGE/kvm_system/kvm_stream" \
  "$KVMAPP_STAGE/kvm_new_app" \
  "$KVMAPP_STAGE/kvm_new_img"
restore_kvm_system_helper

if readelf -d "$KVMAPP_STAGE/kvm_system/kvm_system" 2>/dev/null | grep -Eq '\((RPATH|RUNPATH)\)'; then
  echo "kvm_system must not contain RPATH/RUNPATH; Buildroot target sanitization corrupts this vendor v0p7 ELF" >&2
  exit 1
fi

if [ -n "$APP_VERSION" ]; then
  printf '%s\n' "$APP_VERSION" > "$KVMAPP_STAGE/version"
elif [ ! -f "$KVMAPP_STAGE/version" ]; then
  printf '0.1.0\n' > "$KVMAPP_STAGE/version"
fi

cp "$RUST_BINARY" "$KVMAPP_STAGE/server/NanoKVM-Server"
chmod 0755 "$KVMAPP_STAGE/server/NanoKVM-Server"
cp "$RUST_BINARY" "$KVMAPP_STAGE/backends/NanoKVM-Server.rust"
chmod 0755 "$KVMAPP_STAGE/backends/NanoKVM-Server.rust"
ssh_runtime=$(python3 "$ROOT_DIR/scripts/ssh-runtime-binding.py" inspect \
  --backend "$KVMAPP_STAGE/server/NanoKVM-Server")
ssh_runtime_sha256=${ssh_runtime% *}
ssh_runtime_size=${ssh_runtime#* }
app_recovery=$(python3 "$ROOT_DIR/scripts/app-recovery-binding.py" inspect \
  --backend "$KVMAPP_STAGE/server/NanoKVM-Server")
app_recovery_sha256=${app_recovery% *}
app_recovery_size=${app_recovery#* }
mkdir -p "$KVMAPP_STAGE/system/bin"
python3 "$ROOT_DIR/scripts/app-recovery-binding.py" extract \
  --backend "$KVMAPP_STAGE/server/NanoKVM-Server" \
  --destination "$KVMAPP_STAGE/system/bin/nanokvm-app-recovery"
chmod 0755 "$KVMAPP_STAGE/system/bin/nanokvm-app-recovery"
cp "$HWMON_BINARY" "$KVMAPP_STAGE/hwmon/nanokvm-hwmon"
chmod 0755 "$KVMAPP_STAGE/hwmon/nanokvm-hwmon"

rm -f "$KVMAPP_STAGE/backends/NanoKVM-Server.go" \
  "$KVMAPP_STAGE/server/NanoKVM-Server.go" \
  "$KVMAPP_STAGE/server/NanoKVM-Server.go.bak"

mkdir -p "$KVMAPP_STAGE/server/dl_lib"
cp -R "$NATIVE_LIB_DIR/." "$KVMAPP_STAGE/server/dl_lib/"
if [ -n "$EXTRA_NATIVE_LIB_DIR" ]; then
  [ -d "$EXTRA_NATIVE_LIB_DIR" ] || {
    echo "missing extra native runtime directory: $EXTRA_NATIVE_LIB_DIR" >&2
    exit 1
  }
  cp -R "$EXTRA_NATIVE_LIB_DIR/." "$KVMAPP_STAGE/server/dl_lib/"
  ln -sf libopencv_video.so.4.9.0 "$KVMAPP_STAGE/server/dl_lib/libopencv_video.so.409"
  ln -sf libopencv_dnn.so.4.9.0 "$KVMAPP_STAGE/server/dl_lib/libopencv_dnn.so.409"
  ln -sf libopencv_calib3d.so.4.9.0 "$KVMAPP_STAGE/server/dl_lib/libopencv_calib3d.so.409"
  ln -sf libopencv_features2d.so.4.9.0 "$KVMAPP_STAGE/server/dl_lib/libopencv_features2d.so.409"
  ln -sf libopencv_flann.so.4.9.0 "$KVMAPP_STAGE/server/dl_lib/libopencv_flann.so.409"
  ln -sf libprotobuf.so.32.0.12 "$KVMAPP_STAGE/server/dl_lib/libprotobuf.so.32"
  ln -sf libstdc++.so.6.0.28 "$KVMAPP_STAGE/server/dl_lib/libstdc++.so.6"
  ln -sf libgomp.so.1.0.0 "$KVMAPP_STAGE/server/dl_lib/libgomp.so.1"
  ln -sf libatomic.so.1.2.0 "$KVMAPP_STAGE/server/dl_lib/libatomic.so.1"
fi

# zlib is provided and maintained by Buildroot. Never shadow it with the
# older vendor copy in the application's private RPATH directory.
rm -f "$KVMAPP_STAGE/server/dl_lib/libz.so" \
  "$KVMAPP_STAGE/server/dl_lib/libz.so.1" \
  "$KVMAPP_STAGE/server/dl_lib/libz.so.1.3"

for library in libkvm.so libkvm_mmf.so; do
  if readelf -d "$KVMAPP_STAGE/server/dl_lib/$library" 2>/dev/null | grep -Eq '\((RPATH|RUNPATH)\)'; then
    echo "$library must not contain a build-host RPATH/RUNPATH" >&2
    exit 1
  fi
done

if [ -d "$WEB_DIST" ]; then
  mkdir -p "$KVMAPP_STAGE/server/web"
  cp -R "$WEB_DIST/." "$KVMAPP_STAGE/server/web/"
else
  echo "warning: frontend dist not found at $WEB_DIST; package has no server/web assets" >&2
fi

rust_binary_sha256=$(build_file_sha256 "$KVMAPP_STAGE/server/NanoKVM-Server")
hwmon_binary_sha256=$(build_file_sha256 "$KVMAPP_STAGE/hwmon/nanokvm-hwmon")
kvm_system_sha256=$(build_file_sha256 "$KVMAPP_STAGE/kvm_system/kvm_system")
{
  printf 'artifact: kvmapp-rust\n'
  printf 'source: %s\n' "$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf unknown)"
  printf 'rust_binary: kvmapp/server/NanoKVM-Server\n'
  printf 'rust_binary_sha256: %s\n' "$rust_binary_sha256"
  printf 'ssh_runtime: embedded-static-rv64-v1\n'
  printf 'ssh_runtime_sha256: %s\n' "$ssh_runtime_sha256"
  printf 'ssh_runtime_size: %s\n' "$ssh_runtime_size"
  printf 'app_recovery: embedded-static-rv64-v1\n'
  printf 'app_recovery_sha256: %s\n' "$app_recovery_sha256"
  printf 'app_recovery_size: %s\n' "$app_recovery_size"
  printf 'hwmon_binary: kvmapp/hwmon/nanokvm-hwmon\n'
  printf 'hwmon_binary_sha256: %s\n' "$hwmon_binary_sha256"
  printf 'rust_target: %s\n' "${RUST_TARGET:-host}"
  printf 'web_dist: kvmapp/server/web\n'
  printf 'app_version: %s\n' "$(cat "$KVMAPP_STAGE/version")"
  printf 'native_lib_dir: kvmapp/server/dl_lib\n'
  if [ -n "$EXTRA_NATIVE_LIB_DIR" ]; then
    printf 'extra_native_libs: merged\n'
  else
    printf 'extra_native_libs: none\n'
  fi
  printf 'kvm_system_helper: kvmapp/kvm_system/kvm_system\n'
  printf 'kvm_system_sha256: %s\n' "$kvm_system_sha256"
  printf 'source_date_epoch: %s\n' "$SOURCE_DATE_EPOCH"
} > "$STAGE_DIR/MANIFEST.txt"

if grep -Fq "$ROOT_DIR" "$STAGE_DIR/MANIFEST.txt"; then
  echo "application manifest leaks the build-host project path" >&2
  exit 1
fi

if find "$KVMAPP_STAGE" \( -name 'NanoKVM-Server.go' -o -name 'NanoKVM-Server.go.bak' -o -name 'switch-backend-go.sh' -o -name 'switch-backend-rust.sh' -o -name 'jpg_stream' -o -name 'kvm_stream' -o -name 'kvm_new_app' -o -name 'kvm_new_img' \) | grep -q .; then
  echo "legacy backend switch, Go backend, or legacy app migration artifact found in staged kvmapp" >&2
  exit 1
fi

ARCHIVE="$OUT_DIR/$ARTIFACT_NAME"
case "$ARTIFACT_NAME" in
  '' | *[!A-Za-z0-9._+-]*) echo "invalid artifact filename: $ARTIFACT_NAME" >&2; exit 1 ;;
esac
package_lock_candidate="$ARCHIVE.lock"
mkdir "$package_lock_candidate" || { echo "application artifact is already locked" >&2; exit 1; }
PACKAGE_LOCK=$package_lock_candidate
for artifact in "$ARCHIVE" "$ARCHIVE.sha256"; do
  if [ -e "$artifact" ] || [ -L "$artifact" ]; then
    echo "refusing to overwrite application artifact: $artifact" >&2
    exit 1
  fi
done
build_assert_no_private_keys "$KVMAPP_STAGE" || exit 1
PACKAGE_WORK=$(mktemp -d "$OUT_DIR/.nanokvm-package.XXXXXX")
# A regular intermediate tar makes both producer and compressor errors visible
# under POSIX sh; an unguarded tar | gzip pipeline only reports gzip's status.
tar -C "$STAGE_DIR" \
  --sort=name \
  --format=gnu \
  --mtime="@$SOURCE_DATE_EPOCH" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  --mode='u+rwX,go+rX,go-w' \
  --dereference \
  --hard-dereference \
  -cf "$PACKAGE_WORK/archive.tar" kvmapp MANIFEST.txt
gzip -n -9 -c "$PACKAGE_WORK/archive.tar" > "$PACKAGE_WORK/archive.tar.gz"
tar -tzvf "$PACKAGE_WORK/archive.tar.gz" > "$PACKAGE_WORK/entries"
[ -s "$PACKAGE_WORK/entries" ] || { echo "application archive inventory is empty" >&2; exit 1; }
if ! awk '
  substr($1, 1, 1) != "-" && substr($1, 1, 1) != "d" { bad = 1 }
  END { exit bad ? 1 : 0 }
' "$PACKAGE_WORK/entries"; then
  echo "application archive contains an entry type rejected by the hardened updater" >&2
  exit 1
fi
archive_sha256=$(build_file_sha256 "$PACKAGE_WORK/archive.tar.gz")
printf '%s  %s\n' "$archive_sha256" "$ARCHIVE" > "$PACKAGE_WORK/checksum"
mv "$PACKAGE_WORK/checksum" "$ARCHIVE.sha256"
mv "$PACKAGE_WORK/archive.tar.gz" "$ARCHIVE"

echo "$ARCHIVE"
