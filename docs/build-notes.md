# Hardened NanoKVM Build Notes

These notes are the known-good path for building a deployable Rust backend
package for real NanoKVM hardware.

## Important Rule

Do not deploy a plain `cargo build --target riscv64gc-unknown-linux-musl`
binary to the device. That binary starts the web server, but video capture will
fail with:

```text
load libkvm: Dynamic loading not supported
```

For hardware video, the Rust backend must be built with the `linked-libkvm`
feature through:

```sh
server-rust/scripts/build-linked-libkvm.sh
```

That script sets the NanoKVM dynamic loader, RPATH, sysroot libraries, and the
`linked-libkvm` feature expected by `server-rust/src/ffi/kvm.rs`.

## Prerequisites

Install the Rust target once:

```sh
rustup target add riscv64gc-unknown-linux-musl
```

The linked build needs NanoKVM runtime libraries in `server-rust/sysroot/lib`,
or `NANOKVM_SYSROOT_LIB` must point at a directory with at least:

```text
libc.so
libgcc_s.so or libgcc_s.so.1
```

If the active checkout does not have `server-rust/sysroot/lib`, point the build
at the known-good extracted NanoKVM sysroot explicitly:

```sh
NANOKVM_SYSROOT_LIB=/home/w0w/Hardened_NanoKVM/server-rust/sysroot/lib \
  server-rust/scripts/build-linked-libkvm.sh
```

Do not run `make rust-kvmapp` unless `RUST_TARGET` is explicitly set. Without
that environment variable it can package an x86-64 host binary that installs
successfully but fails on the device with `Exec format error`.

## Build And Package Kvmapp

From the repository root:

```sh
cargo test --manifest-path server-rust/Cargo.toml
corepack pnpm --dir web build
server-rust/scripts/build-linked-libkvm.sh
RUST_TARGET=riscv64gc-unknown-linux-musl \
  APP_VERSION="$(cat kvmapp/version)" \
  scripts/package-rust-kvmapp.sh
```

The package script writes:

```text
build/kvmapp-rust/kvmapp/
build/artifacts/nanokvm-kvmapp-rust.tar.gz
build/artifacts/nanokvm-kvmapp-rust.tar.gz.sha256
```

The binary should be a dynamic RISC-V executable using the NanoKVM loader:

```sh
file server-rust/target/riscv64gc-unknown-linux-musl/release/nanokvm-rust-server
file build/kvmapp-rust/kvmapp/server/NanoKVM-Server
```

Expected shape:

```text
ELF 64-bit LSB pie executable, UCB RISC-V, dynamically linked,
interpreter /lib/ld-musl-riscv64xthead.so.1
```

If `file build/kvmapp-rust/kvmapp/server/NanoKVM-Server` reports `x86-64`, stop
and rebuild before publishing or installing the archive.

## Manual Device Install

BusyBox `tar` on the NanoKVM image may not support `tar -xzf`, and `tar -a`
may not auto-detect gzip correctly. For manual SSH installs, create an
uncompressed tar on the host:

```sh
tar -C build/kvmapp-rust -cf build/artifacts/nanokvm-kvmapp-rust.tar kvmapp MANIFEST.txt
sha256sum build/artifacts/nanokvm-kvmapp-rust.tar
scp -O build/artifacts/nanokvm-kvmapp-rust.tar root@10.0.87.133:/tmp/
```

On the device:

```sh
sha256sum /tmp/nanokvm-kvmapp-rust.tar
tar xf /tmp/nanokvm-kvmapp-rust.tar -C /
cp /kvmapp/system/init.d/S95nanokvm /etc/init.d/S95nanokvm
chmod 0755 /etc/init.d/S95nanokvm \
  /kvmapp/system/init.d/S95nanokvm \
  /kvmapp/server/NanoKVM-Server \
  /kvmapp/backends/NanoKVM-Server.rust
mkdir -p /etc/kvm /kvmapp/kvm
printf 'rust\n' > /etc/kvm/backend
printf 'mjpeg\n' > /kvmapp/kvm/type
rm -f /etc/kvm/h264_safe_mode
sync
/etc/init.d/S95nanokvm restart
```

`/etc/init.d/S95nanokvm` is a separate file on tested devices, not a symlink to
`/kvmapp/system/init.d/S95nanokvm`. Always copy the updated init script there
after extracting a manual package.

## Smoke Checks

On the device:

```sh
cat /kvmapp/version
cat /etc/kvm/backend
cat /kvmapp/kvm/type
pidof NanoKVM-Server
curl -kfsS --max-time 6 https://127.0.0.1/api/health
tail -n 80 /tmp/nanokvm-server.log
```

The log must include:

```text
initialized NanoKVM video backend
starting HTTP to HTTPS redirect listener addr=0.0.0.0:80
starting NanoKVM Rust HTTPS backend addr=0.0.0.0:443
```

It must not include:

```text
Dynamic loading not supported
```

From the host:

```sh
curl -vk --connect-timeout 5 --max-time 8 https://10.0.87.133/api/health
curl -v --connect-timeout 5 --max-time 8 http://10.0.87.133/api/health
```

Expected behavior:

- HTTPS returns JSON with `backend: "rust"`.
- HTTP returns `307 Temporary Redirect` to HTTPS when `proto: https`.

## H.264 Hang Guard

After `Guard H.264 capture against backend hangs`, the runtime intentionally
boots into MJPEG and lets the user opt into H.264 from the UI. This prevents a
bad H.264/VENC startup from leaving the device with open TCP ports but no
HTTP/TLS responses.

The init script also starts a local health watchdog. If `/api/health` fails
repeatedly, it writes `/etc/kvm/h264_safe_mode`, forces `/kvmapp/kvm/type` to
`mjpeg`, and restarts only `NanoKVM-Server`.

## SD And Raw System Update Builds

The safe raw-system-update flow is:

```sh
cargo test --manifest-path server-rust/Cargo.toml
corepack pnpm --dir web build
server-rust/scripts/build-linked-libkvm.sh
RUST_TARGET=riscv64gc-unknown-linux-musl \
  APP_VERSION="$(cat kvmapp/version)" \
  scripts/package-rust-kvmapp.sh
make sd-image HARDENED_RELEASE_VERSION="$(cat kvmapp/version)"
make raw-system-update-images HARDENED_RELEASE_VERSION="$(cat kvmapp/version)"
make raw-system-update-bundle \
  HARDENED_RELEASE_VERSION="$(cat kvmapp/version)" \
  SYSTEM_UPDATE_VERSION="<system-version>" \
  RAW_IMAGE_COMPRESSION=gzip \
  REQUIRED_FREE_BYTES=671088640
```

`scripts/extract-sd-raw-images.sh` accepts either `.img` or `.img.xz`; compressed
images are decompressed to a temporary file before partition extraction.

`make raw-system-update-bundle` must package boot/rootfs images extracted from
the patched Hardened SD image. Do not point it at vendor SDK
`rawimages/rootfs.sd`; that is a stock Buildroot rootfs without `/kvmapp`,
`/etc/kvm`, NanoKVM init, or web assets.

Raw partition updates overwrite boot and rootfs. The app updater used to launch
them must preserve and restore user settings before reboot. Do not test or
publish a raw update path from an app older than `2.0.12` when the bundle uses
gzip payloads, because older app versions do not understand
`images/rootfs.sd.gz`. Do not publish a raw update path from an app older than
`2.0.11` even for uncompressed payloads, because those versions do not restore
`/boot` network settings, `/etc/kvm` account/config state, SSH host keys, root
password files, or extension state after the raw write.

Current raw bundles should use the default gzip payload mode. The updater keeps
`rootfs.sd.gz` and `boot.vfat.gz` compressed in the extracted staging tree and
streams them directly to `/dev/mmcblk0p2` and `/dev/mmcblk0p1`; this avoids
requiring enough `/data` or rootfs free space to hold an additional full 1.5GB
rootfs image.

The guard rail is:

```sh
scripts/validate-nanokvm-rootfs.sh <rootfs.sd>
```

The validator must pass before signing or uploading any raw system update.
`hardened-system-0.1.0-raw.1` failed this rule and is considered revoked.
