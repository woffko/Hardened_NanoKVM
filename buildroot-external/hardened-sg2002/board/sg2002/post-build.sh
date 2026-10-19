#!/bin/sh
set -eu

TARGET_DIR=$1
[ -d "$TARGET_DIR" ] || {
	echo "missing Buildroot target directory: $TARGET_DIR" >&2
	exit 1
}

ROOT="$(CDPATH= cd -- "$(dirname "$0")/../../../.." && pwd)"
KVMAPP_SOURCE="${NANOKVM_KVMAPP_SOURCE_DIR:-$ROOT/build/kvmapp-rust/kvmapp}"
PATCHELF="${HOST_DIR:-}/bin/patchelf"
EXPECTED_RUST_RUNPATH='/kvmapp/server/dl_lib'
RUNTIME_KERNEL_VERSION="${HARDENED_SG2002_RUNTIME_KERNEL_VERSION:-}"
RUNTIME_SECURITY_PATCH_LEVEL="${HARDENED_SG2002_RUNTIME_SECURITY_PATCH_LEVEL:-}"
RUNTIME_SYSTEM_VERSION="${HARDENED_SG2002_RUNTIME_SYSTEM_VERSION:-}"

# Buildroot's per-package accounting files live in package build directories.
# Local packages that copy their complete source root must never leak these
# host-specific snapshots into the appliance filesystem.
find "$TARGET_DIR" -type f -name '.files-list*' -delete

# GCC's target-side GDB auto-loader embeds the absolute HOST_DIR. NanoKVM ships
# neither GDB nor Python, so the helper is unusable and makes otherwise equal
# output directories differ byte-for-byte.
find "$TARGET_DIR" -type f -name '*-gdb.py' -delete

# Buildroot's generic target fix-rpath pass may rewrite an otherwise safe ELF.
# Restore the already-built Rust payload after that pass, but only when its
# RUNPATH is the single root-owned application library directory. Refuse /tmp,
# $ORIGIN, host paths, or any other source search location.
[ -x "$PATCHELF" ] || {
	echo "missing Buildroot host patchelf: $PATCHELF" >&2
	exit 1
}

restore_rust_elf() {
	source_path="$KVMAPP_SOURCE/$1"
	target_path="$TARGET_DIR/$2"
	[ -f "$source_path" ] || {
		echo "missing staged Rust payload: $source_path" >&2
		exit 1
	}
	runpath="$($PATCHELF --print-rpath "$source_path")"
	[ "$runpath" = "$EXPECTED_RUST_RUNPATH" ] || {
		echo "unexpected staged Rust RUNPATH in $source_path: $runpath" >&2
		exit 1
	}
	install -m 0755 "$source_path" "$target_path"
}

restore_rust_elf server/NanoKVM-Server kvmapp/server/NanoKVM-Server
restore_rust_elf backends/NanoKVM-Server.rust kvmapp/backends/NanoKVM-Server.rust
restore_rust_elf hwmon/nanokvm-hwmon kvmapp/hwmon/nanokvm-hwmon

# Recheck the final restored bytes, not just the package's earlier source tree.
# This is consistency only; signed release provenance is a separate gate.
cmp "$KVMAPP_SOURCE/server/NanoKVM-Server" "$TARGET_DIR/kvmapp/server/NanoKVM-Server"
cmp "$TARGET_DIR/kvmapp/server/NanoKVM-Server" "$TARGET_DIR/kvmapp/backends/NanoKVM-Server.rust"
"${HOST_DIR:-}/bin/python3" "$ROOT/scripts/ssh-runtime-binding.py" inspect \
	--backend "$TARGET_DIR/kvmapp/server/NanoKVM-Server" --quiet

# Restore the bundled static recovery after generic ELF fixups, then bind its
# final bytes to the final backend. Install the independent rootfs copy too;
# package-installed S02/consumer gates use this copy; target acceptance and
# trusted transaction production remain separate from installation/provenance.
"${HOST_DIR:-}/bin/python3" "$ROOT/scripts/app-recovery-binding.py" verify \
	--backend "$TARGET_DIR/kvmapp/server/NanoKVM-Server" \
	--helper "$KVMAPP_SOURCE/system/bin/nanokvm-app-recovery"
install -D -m 0755 "$KVMAPP_SOURCE/system/bin/nanokvm-app-recovery" \
	"$TARGET_DIR/kvmapp/system/bin/nanokvm-app-recovery"
"${HOST_DIR:-}/bin/python3" "$ROOT/scripts/app-recovery-binding.py" verify \
	--backend "$TARGET_DIR/kvmapp/server/NanoKVM-Server" \
	--helper "$TARGET_DIR/kvmapp/system/bin/nanokvm-app-recovery"
install -D -m 0755 "$KVMAPP_SOURCE/system/bin/nanokvm-app-recovery" \
	"$TARGET_DIR/usr/libexec/nanokvm-app-recovery"
"${HOST_DIR:-}/bin/python3" "$ROOT/scripts/app-recovery-binding.py" verify \
	--backend "$TARGET_DIR/kvmapp/server/NanoKVM-Server" \
	--helper "$TARGET_DIR/usr/libexec/nanokvm-app-recovery"

# Generic target fixups must not change compile-bound static native programs.
# Restore both copies from the stage, then verify the final bytes independently.
for role in owner broker ctl recovery; do
	helper="nanokvm-native-$role"
	"${HOST_DIR:-}/bin/python3" -B "$ROOT/scripts/native-runtime-binding.py" "$role" verify \
		--backend "$TARGET_DIR/kvmapp/server/NanoKVM-Server" \
		--helper "$KVMAPP_SOURCE/system/bin/$helper"
	for destination in "kvmapp/system/bin/$helper" "usr/libexec/$helper"; do
		install -D -m 0755 "$KVMAPP_SOURCE/system/bin/$helper" "$TARGET_DIR/$destination"
		"${HOST_DIR:-}/bin/python3" -B "$ROOT/scripts/native-runtime-binding.py" "$role" verify \
			--backend "$TARGET_DIR/kvmapp/server/NanoKVM-Server" \
			--helper "$TARGET_DIR/$destination"
	done
done

# Only an offline full-image producer may seed Factory. App installation only
# arms a new boot and must never synthesize an already-fresh installation.
"${HOST_DIR:-}/bin/python3" -B "$ROOT/scripts/native-boot-record.py" \
	"$TARGET_DIR/etc/kvm/native-runtime-boot/state"

if [ -n "$RUNTIME_SYSTEM_VERSION" ] || [ -n "$RUNTIME_KERNEL_VERSION" ] || [ -n "$RUNTIME_SECURITY_PATCH_LEVEL" ]; then
	case "$RUNTIME_SYSTEM_VERSION$RUNTIME_KERNEL_VERSION$RUNTIME_SECURITY_PATCH_LEVEL" in
		*['&|\\']*)
			echo "runtime metadata override contains unsupported sed characters" >&2
			exit 1
			;;
	esac
	SYSTEM_VERSION_FILE="$TARGET_DIR/etc/kvm/system-version.json"
	[ -f "$SYSTEM_VERSION_FILE" ] || {
		echo "missing system version metadata: $SYSTEM_VERSION_FILE" >&2
		exit 1
	}
	if [ -n "$RUNTIME_SYSTEM_VERSION" ]; then
		sed -i \
			-e "s|\"version\": \"[^\"]*\"|\"version\": \"$RUNTIME_SYSTEM_VERSION\"|" \
			"$SYSTEM_VERSION_FILE"
	fi
	if [ -n "$RUNTIME_KERNEL_VERSION" ] || [ -n "$RUNTIME_SECURITY_PATCH_LEVEL" ]; then
		[ -n "$RUNTIME_KERNEL_VERSION" ] && [ -n "$RUNTIME_SECURITY_PATCH_LEVEL" ] || {
			echo "kernel version and security patch level overrides must be set together" >&2
			exit 1
		}
		sed -i \
			-e "s|\"kernel_version\": \"[^\"]*\"|\"kernel_version\": \"$RUNTIME_KERNEL_VERSION\"|" \
			-e "s|\"security_patch_level\": \"[^\"]*\"|\"security_patch_level\": \"$RUNTIME_SECURITY_PATCH_LEVEL\"|" \
			"$SYSTEM_VERSION_FILE"
	fi
fi
