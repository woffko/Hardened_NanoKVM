# Rust Backend Status

The Rust backend lives in `server-rust/`. It is a beta replacement for the
privileged Go `NanoKVM-Server` process and keeps the existing NanoKVM runtime:
`kvm_system`, `libkvm.so`, USB gadget scripts, the Maix multimedia stack, and
the React frontend.

The backend is tested on real NanoKVM hardware at this stage. API parity is not
complete, but the main browser workflows are now implemented deeply enough for
interactive device testing.

Current public beta release metadata points to `1.0.0` from
`woffko/Hardened_NanoKVM` GitHub Releases.

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
  swap, memory limit, TLS toggle, reboot, scripts, autostart, uptime, and
  session-lock routes.
- MJPEG stream and frame-detect endpoints through `libkvm`.
- H.264 Direct and H.264 WebRTC routes are enabled. Direct streaming is the
  preferred low-CPU mode and has been verified on hardware. WebRTC websocket
  signaling is verified; full browser media validation still needs manual
  browser testing.
- MJPEG and H.264 Direct use shared fanout producers, so multiple viewers do
  not multiply native capture reads. New browser sessions default to H.264
  Direct when HTTPS and WebCodecs are available, otherwise to H.264.
- Device startup uses an idempotent `S95nanokvm`: stale `S95nanokvm.*` backup
  scripts are moved out of boot autostart, old `kvm_system`/`NanoKVM-Server`
  processes are stopped before runtime copy/start, stale web backup directories
  are removed from `/kvmapp/server`, and port 443 is explicitly allowed for
  HTTPS.
- Keyboard and mouse HID websocket, queued HID writes, paste, shortcuts, HID
  mode/reset, and mouse jiggler.
- Storage image listing, browser ISO upload, mount, unmount, delete, and CD-ROM
  mode with path validation.
- Guarded remote ISO download by URL. It is disabled by default, controlled by
  Settings > Appearance, validates URL shape, filename, size, destination, and
  ISO9660 signature, and writes only under the configured image directory.
- WOL, DNS, Wi-Fi status/connect/AP verification, and Tailscale lifecycle
  routes.
- Terminal websocket, disabled by default and controlled by the existing
  Terminal menu toggle.
- PicoClaw runtime routes, gateway WebSocket relay, screenshot, HID actions,
  MCP, load-image bridge, and session-list compatibility routes. Real
  runtime/session/history validation is still ongoing.
- Safer command execution through argv-only allowlists and timeouts.
- Safe archive/path handling for script upload, autostart files, ISO upload,
  storage image paths, and update archives.
- Online and offline `kvmapp` updates through Hardened GitHub Releases:
  `/api/application/version` reads `latest.json`, `/api/application/update`
  downloads the release archive, verifies sha512, installs it under `/kvmapp`,
  and restarts `S95nanokvm`.
- UI branding for Hardened NanoKVM and version `beta - 1.0.0`.
- First-boot web setup for SD-card flashes without `/etc/kvm/pwd`.
- Web UI backend switch in Settings > Device > Advanced.
- SD-card release artifacts are published alongside GUI-installable `kvmapp`
  update archives.

## Intentionally Disabled

- Signed update verification is not finished yet. Current beta updates trust
  the Hardened GitHub release metadata over HTTPS plus sha512 verification of
  the downloaded `kvmapp` archive.
- GUI system updates for kernel, dtb, modules, boot files, or rootfs files are
  not implemented yet. See `docs/system-update-plan.md`.
- Default `admin/admin` bootstrap is disabled by default in Rust config. New
  SD-card flashes use the first-boot web setup screen instead. Lost credentials
  are recovered by reflashing the SD card.

## Known Issues And Remaining Work

- Full API parity against the Go backend still needs route-by-route validation.
- H.264 WebRTC needs more browser/ICE stress testing across reconnects and
  browser variants.
- Video setting changes need more route-by-route stress testing. Reproduced
  boot/runtime failures have been tied to stale runtime artifacts: duplicate
  init scripts and old `web.*` backup directories copied into `/tmp/server`.
  The current `S95nanokvm` disables stale autostarts, removes known stale web
  backup directories, and was verified through reboot, login, MJPEG, and H.264
  Direct streaming on the test device.
- First-boot/account setup needs continued product testing on fresh SD-card
  flashes.
- `kvmapp` update signature verification is still missing; current releases
  use trusted GitHub URLs plus sha512 verification.
- Remote ISO download needs a final production policy before it should be
  treated as broadly enabled functionality.
- PicoClaw needs end-to-end runtime/session/history validation against the real
  runtime.
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
