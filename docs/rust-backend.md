# Rust Backend Status

The Rust backend lives in `server-rust/`. It is an alpha replacement for the
privileged Go `NanoKVM-Server` process and keeps the existing NanoKVM runtime:
`kvm_system`, `libkvm.so`, USB gadget scripts, the Maix multimedia stack, and
the React frontend.

The backend is tested on real NanoKVM hardware at this stage. API parity is not
complete, but the main browser workflows are now implemented deeply enough for
interactive device testing.

## Build

Run the normal host checks from the repository root:

```sh
cargo test --manifest-path server-rust/Cargo.toml
make web-app
```

For a video-enabled NanoKVM RISC-V binary, use the linked `libkvm` build. Copy
the NanoKVM runtime libraries into `server-rust/sysroot/lib` or point
`NANOKVM_SYSROOT_LIB` at a directory containing `libc.so` and `libgcc_s.so.1`,
then run:

```sh
rustup target add riscv64gc-unknown-linux-musl
server-rust/scripts/build-linked-libkvm.sh
```

That script builds with feature `linked-libkvm`, uses the NanoKVM dynamic loader
`/lib/ld-musl-riscv64xthead.so.1`, and sets RPATH to `$ORIGIN/dl_lib`,
`/tmp/server/dl_lib`, and `/kvmapp/server/dl_lib`.

Package a deployable `kvmapp` layout with:

```sh
RUST_TARGET=riscv64gc-unknown-linux-musl scripts/package-rust-kvmapp.sh
```

The package is written to:

```text
build/kvmapp-rust/kvmapp/
build/artifacts/nanokvm-kvmapp-rust.tar.gz
```

## SD Image

The repository still does not build a full boot/rootfs image from SDK sources.
The `sd-image` target patches a trusted NanoKVM base image with the current
Rust `kvmapp` package:

```sh
make web-app
server-rust/scripts/build-linked-libkvm.sh
RUST_TARGET=riscv64gc-unknown-linux-musl scripts/package-rust-kvmapp.sh
make sd-image
```

By default, `make sd-image` uses:

```text
build/sd-image/20260123_NanoKVM_Rev1_4_2.img
```

Set `NANOKVM_BASE_IMAGE=/path/to/base.img` to patch a different trusted base
image. The output is written under `build/sd-image/` as `.img`, `.img.xz`, and
`.sha256`.

The generated image installs:

- Rust as the active `/kvmapp/server/NanoKVM-Server`.
- Original Go backend backup at `/kvmapp/backends/NanoKVM-Server.go`.
- Rust backend backup at `/kvmapp/backends/NanoKVM-Server.rust`.
- Backend switch scripts under `/etc/kvm/scripts/`.
- `/etc/kvm/backend` with initial value `rust`.

## Implemented

- Rust HTTP and HTTPS listeners, including HTTP-to-HTTPS redirect.
- Static frontend serving from configured `paths.web_root`.
- Existing `code/msg/data` API response envelope.
- Auth setup, login, logout, account, password check/change.
- Argon2id password hashing for new writes and legacy Go bcrypt verification.
- Generated per-device session secret at `/etc/kvm/session_secret`.
- Session cookies compatible with the current React auth guard.
- CSRF token binding, Origin checks, security headers, login lockout, and
  logout/password-change session revocation.
- VM info, hardware, hostname, web title, GPIO/ATX, OLED, HDMI, SSH, mDNS,
  swap, memory limit, TLS toggle, reboot, scripts, and autostart routes.
- MJPEG stream and frame-detect endpoints through `libkvm`.
- H.264 Direct and H.264 WebRTC routes are enabled. Direct streaming has been
  verified on hardware after switching from H.264 back to MJPEG. WebRTC
  websocket signaling is verified; full browser media validation still needs
  manual browser testing.
- Device startup uses an idempotent `S95nanokvm`: stale `S95nanokvm.*` backup
  scripts are moved out of boot autostart, old `kvm_system`/`NanoKVM-Server`
  processes are stopped before runtime copy/start, and port 443 is explicitly
  allowed for HTTPS.
- Keyboard and mouse HID websocket, queued HID writes, paste, shortcuts, HID
  mode/reset, and mouse jiggler.
- Storage image listing, browser ISO upload, mount, unmount, delete, and CD-ROM
  mode with path validation.
- WOL, DNS, Wi-Fi status/connect/AP verification, and Tailscale lifecycle
  routes.
- Terminal websocket.
- PicoClaw runtime routes and KVM bridge helpers.
- Safer command execution through argv-only allowlists and timeouts.
- Safe archive/path handling for script upload, autostart files, ISO upload,
  storage image paths, and update archives.
- UI branding for Hardened NanoKVM and version `alfa - 0.1`.
- Web UI backend switch in Settings > Device > Advanced.

## Intentionally Disabled

- Online firmware update and offline update archive application are blocked
  until signed update verification is designed and implemented.
- Remote ISO download is disabled in Rust. Browser ISO upload is the supported
  path for now.
- Default `admin/admin` bootstrap is disabled by default in Rust config. It can
  be enabled only for isolated compatibility test images.

## Known Issues And Remaining Work

- Full API parity against the Go backend still needs route-by-route validation.
- H.264 WebRTC needs more browser/ICE stress testing across reconnects and
  browser variants.
- Video setting changes need more route-by-route stress testing. One reproduced
  boot-time failure was caused by a stale backup init script starting a second
  `kvm_system`; the current `S95nanokvm` disables that stale autostart and was
  verified through reboot, login, and MJPEG streaming on the test device.
- First-boot/account setup UX needs product-level polishing.
- The Rust backend still runs with the same root privileges as the original
  service. Splitting privileged operations into a smaller helper is future work.
- A full SDK-sourced boot/rootfs build is still not included; current SD images
  are patched from a trusted upstream NanoKVM base image.

## Device Deployment

Manual deployment to a test device:

```sh
scp server-rust/target/riscv64gc-unknown-linux-musl/release/nanokvm-rust-server root@nanokvm:/tmp/NanoKVM-Server.rust
scp scripts/install-rust-backend.sh root@nanokvm:/tmp/install-rust-backend.sh
ssh root@nanokvm 'sh /tmp/install-rust-backend.sh /tmp/NanoKVM-Server.rust'
```

Backend switching after both binaries are installed:

```sh
ssh root@nanokvm 'sh /etc/kvm/scripts/switch-backend-rust.sh'
ssh root@nanokvm 'sh /etc/kvm/scripts/switch-backend-go.sh'
```
