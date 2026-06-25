# Rust Backend Skeleton

The Rust backend lives in `server-rust/`. It is intentionally separate from the current Go backend until API parity is reached.

## Build

```sh
cd server-rust
cargo test
cargo build --release
```

For the NanoKVM RISC-V target, install the target/toolchain and build with the target linker from the existing builder environment:

```sh
rustup target add riscv64gc-unknown-linux-musl
cd server-rust
cargo build --release --target riscv64gc-unknown-linux-musl
```

The default RISC-V build is self-contained static musl. It is useful for API work, but it cannot use `dlopen` for `libkvm.so` on the device.

For a video-enabled device binary linked directly against `server/dl_lib/libkvm.so`, copy NanoKVM runtime libraries into `server-rust/sysroot/lib` or point `NANOKVM_SYSROOT_LIB` at a directory containing `libc.so` and `libgcc_s.so.1`, then run:

```sh
cd server-rust
./scripts/build-linked-libkvm.sh
```

That script builds with feature `linked-libkvm`, uses the NanoKVM dynamic loader `/lib/ld-musl-riscv64xthead.so.1`, and sets RPATH to `$ORIGIN/dl_lib`, `/tmp/server/dl_lib`, and `/kvmapp/server/dl_lib`.

The release profile is optimized for small binaries with LTO, one codegen unit, strip, and aborting panics.

From the repository root:

```sh
make rust-app
make rust-kvmapp
```

For the target device:

```sh
rustup target add riscv64gc-unknown-linux-musl
make rust-app RUST_TARGET=riscv64gc-unknown-linux-musl
make rust-kvmapp RUST_TARGET=riscv64gc-unknown-linux-musl
```

`make rust-kvmapp` writes a deployable application package to:

```text
build/kvmapp-rust/kvmapp/
build/artifacts/nanokvm-kvmapp-rust.tar.gz
```

If `web/dist` exists, it is copied to `kvmapp/server/web`. Build it with:

```sh
make web-app
```

## Current Implemented Slice

- Config loader compatible with `/etc/kvm/server.yaml` and additional hardening fields.
- Generated per-device session secret at `/etc/kvm/session_secret` with `0600`.
- Existing `code/msg/data` response envelope.
- Auth endpoints:
  - `POST /api/auth/setup`
  - `POST /api/auth/login`
  - `POST /api/auth/logout`
  - `GET /api/auth/account`
  - `GET /api/auth/password`
  - `POST /api/auth/password`
- Legacy `admin/admin` bootstrap is disabled by default. Set `security.allow_default_admin=true`
  only for temporary compatibility on isolated test devices.
- Argon2id password hashing.
- Opaque session tokens with CSRF token binding.
- Frontend-compatible readable `nano-kvm-token` cookie for the existing React auth guard.
- Logout and password-change session revocation.
- Login rate limiting with secure default lockout.
- Security headers middleware.
- CSRF middleware for protected state-changing routes.
- Static frontend serving from configured `paths.web_root`.
- Legacy Go bcrypt password hash verification; new writes remain Argon2id.
- Basic application endpoints:
  - `GET /api/application/version`
  - `GET /api/application/preview`
  - `POST /api/application/preview`
- Basic VM endpoints:
  - `GET /api/vm/info`
  - `GET /api/vm/hardware`
  - `GET /api/vm/hostname`
  - `POST /api/vm/hostname`
  - `GET /api/vm/web-title`
  - `POST /api/vm/web-title`
  - `GET /api/vm/screen`
  - `POST /api/vm/screen`
- HID websocket at `GET /api/ws` for keyboard and mouse reports.
- MJPEG stream at `GET /api/stream/mjpeg` plus frame-detect endpoints. Use the `linked-libkvm` build for real device video.
- Safe command wrapper with argv-only allowlist and timeout.
- Safe tar.gz member path validation and symlink-parent rejection.

Most storage/update/network/power routes are still registered as compatibility stubs. They return an implemented=false payload instead of silently pretending parity exists.

## Install On Test Device

Do not replace the production Go backend until the required module is ported and manually tested.

Manual test deployment once ready:

```sh
scp target/riscv64gc-unknown-linux-musl/release/nanokvm-rust-server root@nanokvm:/kvmapp/server/NanoKVM-Server.rust
ssh root@nanokvm 'cp /kvmapp/server/NanoKVM-Server /kvmapp/server/NanoKVM-Server.go.bak'
ssh root@nanokvm 'cp /kvmapp/server/NanoKVM-Server.rust /kvmapp/server/NanoKVM-Server && chmod 0755 /kvmapp/server/NanoKVM-Server && /etc/init.d/S95nanokvm restart'
```

Rollback:

```sh
ssh root@nanokvm 'cp /kvmapp/server/NanoKVM-Server.go.bak /kvmapp/server/NanoKVM-Server && chmod 0755 /kvmapp/server/NanoKVM-Server && /etc/init.d/S95nanokvm restart'
```

## Known Limitations

- H.264/WebRTC, storage, update, network, power, TLS, and extension routes are not ported yet.
- HTTPS listener is not implemented; config is parsed for compatibility.
- Session store is in memory; restart invalidates sessions rather than resurrecting revoked tokens.
- Existing frontend still needs a first-boot setup flow for `/api/auth/setup`; test devices can opt into
  `security.allow_default_admin=true` only when temporary compatibility is required.
- This repository does not contain the LicheeRV Nano SDK or Buildroot/rootfs flow needed for a full SD-card image. It can package `kvmapp`; a bootable `.img` must be generated from an SDK checkout or by patching a trusted base image.
