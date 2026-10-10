# Rust Backend Status

The Rust backend lives in `server-rust/`. It is the shipped Hardened backend and
runs as `NanoKVM-Server` while keeping the existing NanoKVM runtime:
`kvm_system`, `libkvm.so`, USB gadget scripts, the Maix multimedia stack, and
the React frontend.

The backend is tested on real NanoKVM hardware. The main browser workflows are
implemented deeply enough for interactive device testing.

Current published channels:

- combined app update: `2.0.42 RC12`, tag
  `hardened-system-0.3.0-raw.12`;
- raw system-update: preview `0.3.0-raw.12`, Buildroot `2026.05.1`, Linux
  `5.10.265-tag-`, and metadata format 2 requiring app `2.0.42`. Existing
  devices install the manual `2.0.42` key-transition app first, then raw;
- SD-card image: app `2.0.42` / system `0.3.0-raw.12`; a manual flash already
  contains the matching application and production trust set.

## Build

Operational release and manual device deployment notes live in
[`docs/build-notes.md`](build-notes.md). Use those notes for real hardware
builds; in particular, deploy only the `linked-libkvm` RISC-V binary.

Run the normal host checks from the repository root:

```sh
cargo test --manifest-path server-rust/Cargo.toml
make web-app
```

For a video-enabled NanoKVM RISC-V binary, use the linked `libkvm` build. Copy
the NanoKVM runtime libraries into `server-rust/sysroot/lib` or point
`NANOKVM_SYSROOT_LIB` at a directory containing `libc.so` and `libgcc_s.so.1`,
then run. The NanoKVM native runtime libraries used for linking and packaging
are kept in `server-rust/native/dl_lib`.

```sh
rustup target add riscv64gc-unknown-linux-musl
server-rust/scripts/build-linked-libkvm.sh
```

That script builds with feature `linked-libkvm`, uses the NanoKVM dynamic loader
`/lib/ld-musl-riscv64xthead.so.1`, and sets RUNPATH only to the root-owned
`/kvmapp/server/dl_lib`. S95 may stage the executable itself in a root-created
`/tmp/server`, but never copies or loads shared libraries from `/tmp`.

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

The current Buildroot port produces a verified full boot/rootfs image while
retaining the proven vendor boot/kernel boundary. `make vendor-sdk` bootstraps
the pinned Sipeed/LicheeRV Nano SDK for provenance work, while the historical
`sd-image` target patches a trusted NanoKVM base image with the current Rust
`kvmapp` package:

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
- Rust backend backup at `/kvmapp/backends/NanoKVM-Server.rust`.
- `/etc/kvm/backend` compatibility marker with initial value `rust`.
- Release validation rejects stale backend artifacts and unexpected runtime
  files.

For end-user flashing instructions, see
[`docs/sd-card-flashing.md`](sd-card-flashing.md).

## Implemented

- Rust HTTP and HTTPS listeners, including HTTP-to-HTTPS redirect.
- Static frontend serving from configured `paths.web_root`.
- Existing `code/msg/data` API response envelope.
- Auth setup, login, logout, account, password check/change.
- Argon2id password hashing for new writes and existing bcrypt verification.
- Generated per-device session secret at `/etc/kvm/session_secret`.
- Session cookies compatible with the current React auth guard.
- CSRF token binding, Origin checks, security headers, login lockout, and
  logout/password-change session revocation.
- Optional TOTP (RFC 6238) second factor for web login, with single-use backup
  codes. See "Two-factor authentication" below. SSH is unaffected and remains
  password-only.
- VM info, hardware, hostname, web title, GPIO/ATX, OLED, HDMI, SSH, mDNS,
  swap, memory limit, TLS toggle, reboot, scripts, autostart, uptime, and
  session-lock routes.
- Managed firewall modes: Baseline compatibility, Moderate default local-only
  access, Restricted local-only service allowlist, and Paranoid local-only HTTPS
  with online updates intentionally blocked. Restricted and Paranoid block
  H.264 WebRTC; use H.264 Direct or MJPEG in those modes.
- MJPEG stream and frame-detect endpoints through `libkvm`.
- H.264 Direct and H.264 WebRTC routes are implemented. Direct streaming is the
  preferred low-CPU mode and has been verified on hardware. WebRTC websocket
  signaling is available only when the effective firewall mode permits it.
- MJPEG and H.264 Direct use shared fanout producers, so multiple viewers do
  not multiply native capture reads. New browser sessions default to H.264
  Direct when HTTPS and WebCodecs are available, otherwise to H.264.
- Device startup uses an idempotent `S95nanokvm`: stale `S95nanokvm.*` backup
  scripts are moved out of boot autostart, old `kvm_system`/`NanoKVM-Server`
  processes are stopped before runtime copy/start, stale web backup directories
  are removed from `/kvmapp/server`, and port 443 is explicitly allowed for
  HTTPS.
- Keyboard and mouse HID websocket, queued HID writes, paste, shortcuts, HID
  mode/reset, mouse jiggler, mobile TouchSync pointer mode, and relative
  pointer sensitivity controls.
- Storage image listing, browser ISO upload, mount, unmount, delete, and CD-ROM
  mode with path validation. Runtime media changes now eject and insert the
  mass-storage LUN; switching between CD-ROM and mass-storage mode also
  reconnects the USB gadget so BIOS/boot menus rescan the device type. An
  explicit reconnect endpoint remains available as a compatibility fallback.
- Guarded remote ISO download by URL. It is disabled by default, controlled by
  Settings > Appearance, validates URL shape, filename, size, destination, and
  ISO9660 signature, and writes only under the configured image directory.
  Completed browser uploads and remote downloads refresh the virtual-media image
  list without requiring logout.
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
  verifies signed release metadata, downloads the release archive, verifies
  sha512, installs it under `/kvmapp`, and restarts `S95nanokvm`.
- Read-only system-update version/check routes:
  `/api/system-update/version` reports the current base-system identity and
  `/api/system-update/check` validates GitHub-hosted `system-latest.json`
  metadata without installing the system archive.
- System-update download/status/install/rollback routes:
  `/api/system-update/download` downloads and verifies the system archive in
  the update cache, checks the archive digests and every manifest payload hash,
  and records `staged.json`; `/api/system-update/status` reports that staged
  bundle plus pending/boot-health/rollback state. `/api/system-update/install`
  re-verifies the staged archive, backs up touched files, applies payload files
  atomically, writes `/etc/kvm/system-version.json`, and records
  pending/backup markers. `/api/system-update/confirm` writes a boot-good
  marker after basic health checks. `/api/system-update/rollback` restores the
  latest backup manually. These routes do not reboot automatically.
- UI branding for Hardened NanoKVM, About-page app version display from
  `/kvmapp/version`, and an unauthenticated current-version endpoint used by
  the login screen.
- Guarded raw system-update switch in Check for Updates. Raw boot/rootfs writes
  stay disabled by default and require an explicit warning confirmation before
  `/api/system-update/install` can apply a destructive staged bundle.
- First-boot web setup for SD-card flashes without `/etc/kvm/pwd`.
- Rust-only release artifacts with package validation for the expected runtime
  layout.
- SD-card release artifacts are published alongside GUI-installable `kvmapp`
  update archives.

## Two-factor authentication

Opt-in TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30-second steps, +/-1 step of drift)
for the **web UI only**. SSH authenticates against the root Unix password on a
separate path and is not covered.

### Login flow

`POST /api/auth/login` behaves as before for accounts without enrolment. For an
enrolled account it verifies the password and then, instead of issuing a
session, returns `code: 0` with `{ "totpRequired": true }` and sets a
short-lived HttpOnly pending-ticket cookie. `POST /api/auth/login/totp`
exchanges that ticket plus a code for the real session.

The discriminator lives inside `data` rather than being a new error code
because the frontend treats any nonzero `code` as a hard failure.

The pending ticket is not a session: it is single-use, expires in five minutes,
is bound to the address that obtained it, and resolves only to a username, so
no route can mistake it for authentication. A wrong code does not spend it.

### The device clock

This board has no battery-backed RTC. It boots at the Unix epoch and reaches
real wall-clock time only once NTP succeeds. Two consequences:

- **TOTP codes are refused with an explicit "clock not synchronized" error**
  while the clock is implausible, rather than reported as invalid codes.
- **Backup codes are deliberately exempt from that check.** They are the
  recovery path *for* an unsynchronized clock, so gating them on the clock
  would make them unreachable in exactly the situation they exist for. This is
  the single most important invariant in this feature; it has a dedicated
  regression test.

Sync is detected from a plausibility floor (`MIN_PLAUSIBLE_UNIX_TIME` in
`auth/clock.rs`, currently 2026-01-01) plus a flag set when a sync through the
API succeeds. The floor is a source constant rather than a build timestamp
because a build timestamp would break reproducible builds. `ntpq`/`ntpdc` are
not built into the image, so querying the daemon is not an option.

### Recovery

Enrolment issues nine single-use backup codes, displayed once. They are stored
as **SHA-256 hashes, not Argon2**: they are server-generated with 50 bits of
entropy, so the slow-KDF rationale (resisting offline brute force of a
guessable human password) does not apply, and one Argon2 verification takes
seconds on this hardware while checking a backup code has to compare against
every remaining hash. Online guessing is capped by the existing login lockout.

If both the authenticator and the backup codes are lost, recovery means SSH
access and removing the `totp` object from `/etc/kvm/pwd`.

### Replay protection

The last accepted step is held **in memory**, not persisted, because persisting
it would mean a flash write on every login. Sessions are already in-memory, so
a reboot clears no more than it otherwise would, and replaying a captured code
across a power cycle means beating a boot that takes far longer than the
30-second window.

### `security.require_totp`

Requires a second factor for web login. It is switched from **Settings >
Account** once enrolled. Enabling it through
`POST /api/auth/totp/required` is refused until the account has confirmed an
enrolment, mirroring how `system_firewall` refuses restricted modes until HTTPS
is on.

If the flag is set some other way -- a hand-edited `server.yaml`, a restored
config, a reset `/etc/kvm/pwd` -- **login still succeeds**, because refusing
would leave a headless device with no way back in. But the session is
**confined**: while the policy is on and the account is unenrolled, the
`protected` middleware answers every route with `403 two-factor enrolment
required` except the ones needed to enrol or leave -- `GET /api/auth/account`,
`GET /api/auth/totp`, `POST /api/auth/totp/enroll`, `POST /api/auth/totp/confirm`
and `POST /api/auth/logout`. The policy toggle is deliberately not among them,
so a confined session cannot switch the policy off. The frontend turns that 403
into a redirect to enrolment.

The check runs per request rather than being stored on the session, so
completing enrolment lifts the restriction for the session that did it, and
clearing the policy lifts it immediately. When the policy is off it costs one
atomic load; when on, it reads the account file, and an unreadable file counts
as unenrolled so the policy fails closed.

### Changing the second factor

Every change to the second factor requires the account password: enrolling,
disabling and reissuing backup codes. Without it a stolen session could bind
its own authenticator, which would replace the secret, void the owner's backup
codes and -- because enrolment revokes other sessions -- log the owner out.

Note that `POST /api/auth/password` does not yet require the current password,
so a stolen session can still change the password itself. That predates
two-factor support and is the remaining gap in this model.

## Intentionally Disabled

- Signed application update metadata enforcement is implemented. Releases must
  include `latest.json.sig`; unsigned metadata is accepted only when
  `security.allow_unsigned_updates=true`.
- Signed system-update metadata enforcement is implemented. Stable/preview
  metadata must verify against `paths.system_update_public_key`; unsigned
  metadata is accepted only when `security.allow_unsigned_updates=true`.
  `S95nanokvm` installs the bundled default public key from
  `/kvmapp/system/keys/system-update-signing.pub.pem` into `/etc/kvm` before
  the backend starts. The system-update installer also generates an init-time
  rollback script, and
  `S95nanokvm` runs a boot watchdog that rolls back pending system updates when
  local health checks fail after boot.
- Default `admin/admin` bootstrap is disabled by default in Rust config. New
  SD-card flashes use the first-boot web setup screen instead. Lost credentials
  are recovered by reflashing the SD card.

## Known Issues And Remaining Work

- Rust still depends on native `libkvm`/CVI-MMF code for video. The 2026-07-11
  audit found unresolved camera restart/deinit races, VENC error-lifetime bugs,
  definite native bounds errors, unchecked I2C/encoder failures, and retained
  `kvm_system` reliability issues. Treat native video lifecycle remediation on
  device 133 as the highest-priority backend work; see
  [`docs/native-code-audit.md`](native-code-audit.md).
- Less common settings and exact error semantics still need route-by-route
  validation.
- H.264 WebRTC remains available for Baseline/Moderate testing only; Restricted
  and Paranoid intentionally disable it.
- Video setting changes need more route-by-route stress testing. The current
  app preserves the selected MJPEG/H.264 Direct/H.264 WebRTC mode across page
  loads where that mode is allowed. Restricted/Paranoid switch away from H.264
  WebRTC because the backend route and firewall policy block it. Protocol
  changes intentionally reboot the device instead of partially restarting the
  video stack.
- First-boot/account setup needs continued product testing on fresh SD-card
  flashes.
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

The manual installer also removes stale backend backups and development helper
scripts left by older test builds.
