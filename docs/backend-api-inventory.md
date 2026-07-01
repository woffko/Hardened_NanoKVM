# NanoKVM Backend API Inventory

This document maps the current Rust backend surface in `server-rust/`. It is a
living compatibility checklist against the historical upstream Go
`NanoKVM-Server` API shape. The Go backend is not shipped in current Hardened
release artifacts.

## Runtime And Serving Model

- Active backend binary on device: `/kvmapp/server/NanoKVM-Server`.
- Rust backend source: `server-rust/`.
- Legacy upstream Go source: `server/`, retained for reference only.
- Static frontend path: configured `paths.web_root`, normally
  `/kvmapp/server/web`.
- Config file: `/etc/kvm/server.yaml`.
- Default HTTP bind: `host: ""`, port `80`, effectively all interfaces.
- Optional HTTPS: `proto: https`, `port.https`, and configured cert/key.
- HTTPS mode keeps a restricted loopback HTTP surface for PicoClaw internal
  routes and redirects normal HTTP clients to HTTPS.

## Response Envelope

Most REST handlers preserve the existing NanoKVM envelope:

```json
{ "code": 0, "msg": "success", "data": {} }
```

The Rust backend may use HTTP status codes for transport/security failures such
as authentication, CSRF, origin, malformed uploads, or internal errors.

## Public Routes

| Method | Path | Rust Status |
|---|---|---|
| GET | `/api/health` | Implemented; returns Rust backend health. |
| POST | `/api/auth/login` | Implemented with opaque session token, CSRF token, login lockout, and configurable session duration. |
| GET/POST | `/api/auth/setup` | Implemented for first-account setup flow; GET reports whether setup is required, POST creates the first account only while `/etc/kvm/pwd` is missing. |
| POST | `/api/network/wifi` | Implemented for AP-mode no-auth Wi-Fi flow with AP key verification. |
| POST | `/api/network/wifi/verify` | Implemented for AP-mode verification. |

## Authenticated REST Routes

### Auth And Account

| Method | Path | Rust Status |
|---|---|---|
| POST | `/api/auth/logout` | Implemented; revokes current session. |
| GET | `/api/auth/account` | Implemented. |
| GET/POST | `/api/auth/password` | Implemented; Argon2id writes, legacy verification, password-change session revocation, and root password sync. |

### Application Updates

| Method | Path | Rust Status |
|---|---|---|
| GET | `/api/application/version` | Implemented; reads `/kvmapp/version` and validates signed Hardened GitHub release `latest.json` metadata. |
| POST | `/api/application/update` | Implemented beta release path; verifies signed metadata, downloads the Hardened GitHub release archive, validates source URL, verifies sha512, safely extracts, rejects symlinks and legacy Go backend files, installs `/kvmapp`, and restarts service. |
| POST | `/api/application/update/offline` | Implemented for `nanokvm_*.tar.gz` and `hardened-nanokvm-kvmapp-*.tar.gz` with safe extraction. |
| GET/POST | `/api/application/preview` | Implemented; selects stable latest metadata or preview tag metadata with stable fallback. |

### System Updates

| Method | Path | Rust Status |
|---|---|---|
| GET | `/api/system-update/version` | Implemented read-only; reports persisted `/etc/kvm/system-version.json` when present, otherwise falls back to `/boot/ver`, kernel release, Buildroot version, hardware marker, and target `sg2002-licheervnano-sd`. |
| GET | `/api/system-update/check` | Implemented read-only; reads GitHub `hardened-system-stable/system-latest.json`, validates metadata shape, trusted URLs, archive name, size, sha256, sha512, and reports update availability. |
| GET | `/api/system-update/status` | Implemented read-only; reports the verified staged system bundle, pending installed update marker, boot-health summary, and latest rollback backup when present. |
| POST | `/api/system-update/download` | Implemented staging-only; downloads the GitHub release asset, checks size, sha256, sha512, extracts it safely, verifies `manifest.json`, verifies every payload file hash/size/path, and writes `staged.json`. It does not install or reboot. |
| POST | `/api/system-update/install` | Implemented guarded install; re-verifies staged archive, backs up each target file, applies payload files atomically, writes `/etc/kvm/system-version.json`, writes pending/backup markers, generates `/etc/kvm/system-update-rollback.sh` for init-time recovery, and returns without rebooting. |
| POST | `/api/system-update/rollback` | Implemented manual rollback; restores files from the latest backup marker, clears pending/boot-good/rollback-attempt markers, and returns without rebooting. |
| POST | `/api/system-update/confirm` | Implemented manual boot-good confirmation; validates pending version/target against current system identity and basic boot/web-root markers, writes `/etc/kvm/system-update-boot-good.json`, and clears pending marker. |

### System Log

| Method | Path | Rust Status |
|---|---|---|
| GET/POST | `/api/system-log/config` | Implemented in app `2.0.20`; persists `/etc/kvm/syslog.json`, renders `/etc/default/syslogd` and `/etc/default/klogd`, restarts BusyBox `syslogd`/`klogd`, keeps local logs in tmpfs at `/tmp/hardened-syslog/messages`, and supports UDP remote syslog forwarding. |
| GET | `/api/system-log/messages` | Implemented; returns bounded tail output for `kind=system` from the tmpfs syslog file, `kind=kernel` from the current `dmesg` ring buffer, or `kind=backend` from `/tmp/nanokvm-server.log`, with line count clamped to 1-1000. |
| POST | `/api/system-log/test` | Implemented; emits a test syslog message through `/dev/log` so local and remote forwarding paths can be verified. |

### VM, Device, And Settings

| Method | Path | Rust Status |
|---|---|---|
| GET | `/api/vm/info` | Implemented; includes image version, application version, hostname, IP, mDNS, and uptime. |
| GET | `/api/vm/hardware` | Implemented. |
| GET/POST | `/api/vm/hostname` | Implemented. |
| GET/POST | `/api/vm/web-title` | Implemented. |
| GET/POST | `/api/vm/gpio` | Implemented. |
| POST | `/api/vm/screen` | Implemented; writes legacy-compatible video mode/resolution/quality/FPS files and coordinates stream mode changes. |
| GET/POST | `/api/vm/device/virtual` | Implemented. |
| GET/POST | `/api/vm/oled` | Implemented. |
| GET | `/api/vm/hdmi` | Implemented. |
| POST | `/api/vm/hdmi/reset` | Implemented. |
| POST | `/api/vm/hdmi/enable` | Implemented. |
| POST | `/api/vm/hdmi/disable` | Implemented. |
| GET | `/api/vm/ssh` | Implemented. |
| POST | `/api/vm/ssh/enable` | Implemented. |
| POST | `/api/vm/ssh/disable` | Implemented. |
| GET | `/api/vm/mdns` | Implemented. |
| POST | `/api/vm/mdns/enable` | Implemented. |
| POST | `/api/vm/mdns/disable` | Implemented. |
| POST | `/api/vm/system/reboot` | Implemented. |
| GET/POST | `/api/vm/terminal/enabled` | Implemented; also controls whether the terminal WebSocket is available. |
| GET/POST | `/api/vm/session-lock` | Implemented; supports 5, 15, 30, and 60 minute durations and retimes current session. |
| GET/POST | `/api/vm/memory/limit` | Implemented. |
| GET/POST | `/api/vm/swap` | Implemented. |
| GET/POST | `/api/vm/mouse-jiggler` | Implemented. |
| POST | `/api/vm/tls` | Implemented; generates self-signed certs when needed and restarts service. |
| GET/POST/DELETE | `/api/vm/autostart*` | Implemented with basename/path validation and size limits. |
| GET/POST/DELETE | `/api/vm/script*` | Implemented with basename/path validation and allowlisted execution. |

### Video And HID

| Method | Path | Rust Status |
|---|---|---|
| GET | `/api/ws` | Implemented HID keyboard/mouse WebSocket plus capture-status events. |
| GET | `/api/stream/mjpeg` | Implemented through `libkvm` with shared fanout. |
| POST | `/api/stream/mjpeg/detect` | Implemented. |
| POST | `/api/stream/mjpeg/detect/stop` | Implemented. |
| GET | `/api/stream/h264/direct` | Implemented NanoKVM-compatible direct H.264 binary frame WebSocket. |
| GET | `/api/stream/h264` | Implemented H.264 WebRTC signaling and RTP sample streaming; needs more browser/ICE soak testing. |
| GET | `/api/hid/shortcuts` | Implemented. |
| POST/DELETE | `/api/hid/shortcut` | Implemented. |
| GET/POST | `/api/hid/shortcut/leader-key` | Implemented. |
| GET/POST | `/api/hid/mode` | Implemented. |
| POST | `/api/hid/reset` | Implemented. |
| POST | `/api/hid/paste` | Implemented. |

### Storage And Image Download

| Method | Path | Rust Status |
|---|---|---|
| GET | `/api/storage/image` | Implemented. |
| GET | `/api/storage/image/mounted` | Implemented. |
| POST | `/api/storage/image/mount` | Implemented with `/data` path validation. |
| GET | `/api/storage/cdrom` | Implemented. |
| POST | `/api/storage/image/delete` | Implemented with containment checks. |
| GET | `/api/download/image/enabled` | Implemented. |
| GET | `/api/download/image/status` | Implemented. |
| POST | `/api/download/file` | Implemented browser ISO upload with size and path validation. |
| GET/POST | `/api/download/image/remote/enabled` | Implemented disabled-by-default remote ISO toggle. |
| POST | `/api/download/image` | Implemented guarded remote ISO download with protocol, filename, destination, size, redirect, and ISO signature checks. |

### Network And Tailscale

| Method | Path | Rust Status |
|---|---|---|
| POST | `/api/network/wol` | Implemented. |
| GET/DELETE | `/api/network/wol/mac` | Implemented. |
| POST | `/api/network/wol/mac/name` | Implemented. |
| GET/POST | `/api/network/dns` | Implemented. |
| GET | `/api/network/wifi` | Implemented. |
| POST | `/api/network/wifi/connect` | Implemented. |
| POST | `/api/network/wifi/disconnect` | Implemented. |
| GET/POST | `/api/extensions/tailscale/*` | Implemented lifecycle/status/login/install flow with safer command execution. |

### PicoClaw

| Method | Path | Rust Status |
|---|---|---|
| GET/POST | `/api/picoclaw/model/config` | Implemented compatibility route. |
| POST | `/api/picoclaw/agent/profile` | Implemented compatibility route. |
| GET | `/api/picoclaw/sessions` | Implemented session list compatibility; full real-history validation remains. |
| GET/DELETE | `/api/picoclaw/sessions/{id}` | Implemented compatibility shape; real session history behavior needs validation. |
| GET/POST/DELETE | `/api/picoclaw/runtime/*` | Implemented runtime status/session/install/uninstall/start/stop flows. |
| GET | `/api/picoclaw/gateway/ws` | Implemented gateway WebSocket relay. |
| GET | `/api/picoclaw/screenshot` | Implemented loopback-only internal route. |
| POST | `/api/picoclaw/actions` | Implemented loopback-only HID action route. |
| POST | `/api/picoclaw/mcp` | Implemented loopback-only MCP bridge. |
| POST | `/api/picoclaw/load-image` | Implemented loopback-only load-image bridge. |

## WebSocket Controls

| Path | Purpose | Rust Control |
|---|---|---|
| `/api/ws` | HID keyboard/mouse control and capture status | Authenticated session, Origin validation, bounded message size, queued HID writes. |
| `/api/vm/terminal` | PTY shell | Disabled by default, controlled by Terminal menu toggle, authenticated session, Origin validation. |
| `/api/stream/h264` | WebRTC H.264 signaling | Authenticated session, Origin validation, slow-client handling. |
| `/api/stream/h264/direct` | Direct H.264 stream | Authenticated session, Origin validation, shared producer/fanout. |
| `/api/picoclaw/gateway/ws` | PicoClaw runtime gateway | Authenticated session, session lock, upstream timeout/message limits. |

## Config Fields

Preserved fields include `proto`, `host`, `port.http`, `port.https`,
`cert.crt`, `cert.key`, `logger.level`, `logger.file`, `authentication`,
`jwt.secretKey`, `jwt.refreshTokenDuration`, `jwt.revokeTokensOnLogout`, `stun`,
and `turn.*`.

Rust hardening fields under `security` include `require_csrf`,
`websocket_origin_check`, `access_token_duration`, `refresh_token_duration`,
`revoke_tokens_on_password_change`, `allow_unsigned_updates`, `allow_terminal`,
`allow_remote_image_download`, `allow_auth_disable`, `allow_default_admin`, and
`allowed_origins`.

Rust-only path fields include `paths.system_update_public_key`, defaulting to
`/etc/kvm/system-update-signing.pub.pem`, for detached application-update and
system-update metadata signature verification. The default key is synchronized from
`/kvmapp/system/keys/system-update-signing.pub.pem` by `S95nanokvm` on service
start.

## External Components To Preserve

- `kvm_system` and `kvm_vision` remain external components.
- `libkvm.so` and `libkvm_mmf.so` remain the native hardware/video boundary.
- Init scripts under `/etc/init.d/` remain service-control boundaries until
  privileged helper work is split out.
- Video capture/encoder pipeline is not rewritten in Rust.

## Current Gaps

- Full route-by-route parity against historical upstream behavior still needs
  systematic regression testing, especially uncommon settings and exact error
  semantics.
- H.264 WebRTC needs longer browser/ICE validation.
- `kvmapp` update metadata is signed; release publishing must upload
  `latest.json` and `latest.json.sig`.
- System-update API/GUI exists, including signed metadata enforcement and
  rollback, but real vendor-kernel/security-backport bundles still need device
  testing and release assets.
