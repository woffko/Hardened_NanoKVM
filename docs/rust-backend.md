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

The repository `.cargo/config.toml` configures this target to use `rust-lld` with self-contained static linking. The release profile is optimized for small binaries with LTO, one codegen unit, strip, and aborting panics.

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
- Legacy `admin/admin` bootstrap is enabled for this alpha unless `security.allow_default_admin=false`.
- Argon2id password hashing.
- Opaque session tokens with CSRF token binding.
- Frontend-compatible readable `nano-kvm-token` cookie for the existing React auth guard.
- Logout and password-change session revocation.
- Login rate limiting with secure default lockout.
- Security headers middleware.
- CSRF middleware for protected state-changing routes.
- Static frontend serving from configured `paths.web_root`.
- Safe command wrapper with argv-only allowlist and timeout.
- Safe tar.gz member path validation and symlink-parent rejection.

Most hardware/video/storage/update routes are registered as compatibility stubs. They return an implemented=false payload instead of silently pretending parity exists.

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

- Hardware/video/HID/storage/update routes are not ported yet.
- Static frontend serving is wired through `tower_http::ServeDir`, but not device-tested.
- HTTPS listener is not implemented; config is parsed for compatibility.
- Session store is in memory; restart invalidates sessions rather than resurrecting revoked tokens.
- Existing frontend still needs a first-boot setup flow for `/api/auth/setup` and CSRF header propagation before disabling the legacy `admin/admin` bootstrap.
- This repository does not contain the LicheeRV Nano SDK or Buildroot/rootfs flow needed for a full SD-card image. It can package `kvmapp`; a bootable `.img` must be generated from an SDK checkout or by patching a trusted base image.
