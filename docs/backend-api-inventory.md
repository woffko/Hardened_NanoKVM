# NanoKVM Backend API Inventory

Source inventory for the Rust backend rewrite. This document maps the current Go backend surface that `server-rust/` must preserve or intentionally replace with a documented security change.

## Runtime And Serving Model

- Current backend binary: `server/NanoKVM-Server`, deployed under `/kvmapp/server/`.
- Static frontend path: current Go server serves `web/` from the executable directory.
- Config file: `/etc/kvm/server.yaml`.
- Default HTTP bind: `host: ""`, port `80`, effectively all interfaces.
- Optional HTTPS: `proto: https`, cert/key from config.
- Loopback HTTP behavior: HTTPS mode may still expose selected loopback paths for internal APIs.

## Response Envelope

All current API handlers return HTTP 200 for application-level success and most application-level errors:

```json
{ "code": 0, "msg": "success", "data": {} }
```

The Rust skeleton preserves this envelope through `ApiResponse<T>`.

## Public Routes

| Method | Path | Current Handler | Notes |
|---|---|---|---|
| POST | `/api/auth/login` | `auth.Login` | Public login. Rust rewrite removes default `admin/admin`. |
| POST | `/api/network/wifi` | `network.ConnectWifiNoAuth` | AP-mode only, guarded by AP key in current code. |
| POST | `/api/network/wifi/verify` | `network.VerifyApLogin` | AP-mode only, guarded by AP key in current code. |

## Authenticated Routes

| Method | Path | Current Handler | Migration Status |
|---|---|---|---|
| GET | `/api/auth/password` | `auth.IsPasswordUpdated` | Implemented in Rust skeleton. |
| GET | `/api/auth/account` | `auth.GetAccount` | Implemented in Rust skeleton. |
| POST | `/api/auth/password` | `auth.ChangePassword` | Implemented in Rust skeleton with Argon2id and session revocation. |
| POST | `/api/auth/logout` | `auth.Logout` | Implemented in Rust skeleton with active-session revocation. |
| GET | `/api/application/version` | `application.GetVersion` | Stubbed. |
| POST | `/api/application/update` | `application.Update` | Stubbed; must use signed updates. |
| POST | `/api/application/update/offline` | `application.OfflineUpdate` | Stubbed; safe archive helper added. |
| GET/POST | `/api/application/preview` | preview get/set | Stubbed. |
| GET | `/api/storage/image` | `storage.GetImages` | Stubbed. |
| GET | `/api/storage/image/mounted` | `storage.GetMountedImage` | Stubbed. |
| POST | `/api/storage/image/mount` | `storage.MountImage` | Stubbed; must enforce `/data` allowlist. |
| GET | `/api/storage/cdrom` | `storage.GetCdRom` | Stubbed. |
| POST | `/api/storage/image/delete` | `storage.DeleteImage` | Stubbed; must enforce resolved containment. |
| POST | `/api/hid/paste` | `hid.Paste` | Stubbed. |
| GET/POST/DELETE | `/api/hid/shortcut*` | shortcut handlers | Stubbed. |
| GET/POST | `/api/hid/mode` | HID mode handlers | Stubbed. |
| POST | `/api/hid/reset` | `hid.ResetHid` | Stubbed. |
| GET | `/api/stream/mjpeg` | `mjpeg.Connect` | Stubbed. |
| POST | `/api/stream/mjpeg/detect` | `mjpeg.UpdateFrameDetect` | Stubbed. |
| POST | `/api/stream/mjpeg/detect/stop` | `mjpeg.StopFrameDetect` | Stubbed. |
| GET | `/api/stream/h264` | `webrtc.Connect` | Stubbed. |
| GET | `/api/stream/h264/direct` | `direct.Connect` | Stubbed. |
| POST | `/api/download/image` | `download.DownloadImage` | Stubbed; must add SSRF controls. |
| GET | `/api/download/image/status` | `download.StatusImage` | Stubbed. |
| GET | `/api/download/image/enabled` | `download.ImageEnabled` | Stubbed. |
| POST | `/api/download/file` | `download.DownloadImageFile` | Stubbed. |
| POST | `/api/network/wol` | `network.WakeOnLAN` | Stubbed. |
| GET/DELETE | `/api/network/wol/mac` | MAC list/delete | Stubbed. |
| POST | `/api/network/wol/mac/name` | `network.SetMacName` | Stubbed. |
| GET | `/api/network/wifi` | `network.GetWifi` | Stubbed. |
| POST | `/api/network/wifi/connect` | `network.ConnectWifi` | Stubbed. |
| POST | `/api/network/wifi/disconnect` | `network.DisconnectWifi` | Stubbed. |
| GET/POST | `/api/network/dns` | DNS get/set | Stubbed. |
| GET | `/api/vm/info` | `vm.GetInfo` | Stubbed. |
| GET | `/api/vm/hardware` | `vm.GetHardware` | Stubbed. |
| GET/POST | `/api/vm/gpio` | GPIO get/set | Stubbed. |
| POST | `/api/vm/screen` | `vm.SetScreen` | Stubbed. |
| GET | `/api/vm/terminal` | `vm.Terminal` | Stubbed; must remain disabled by default. |
| GET/POST/DELETE | `/api/vm/script*` | script handlers | Stubbed; must use safe command/path wrappers. |
| GET/POST | `/api/vm/device/virtual` | virtual media toggle | Stubbed. |
| GET/POST | `/api/vm/memory/limit` | memory limit | Stubbed. |
| GET/POST | `/api/vm/oled` | OLED sleep | Stubbed. |
| GET/POST | `/api/vm/hdmi/*` | HDMI state/reset/enable/disable | Stubbed. |
| GET/POST | `/api/vm/ssh*` | SSH state/enable/disable | Stubbed. |
| GET/POST | `/api/vm/swap` | swap get/set | Stubbed. |
| GET/POST | `/api/vm/mouse-jiggler*` | mouse jiggler | Stubbed. |
| GET/POST | `/api/vm/hostname` | hostname get/set | Stubbed. |
| GET/POST | `/api/vm/web-title` | web title get/set | Stubbed. |
| GET/POST | `/api/vm/mdns*` | mDNS state/enable/disable | Stubbed. |
| POST | `/api/vm/tls` | TLS enable/disable | Stubbed. |
| GET/POST/DELETE | `/api/vm/autostart*` | autostart handlers | Stubbed; must validate path names. |
| POST | `/api/vm/system/reboot` | `vm.Reboot` | Stubbed. |
| POST/GET | `/api/extensions/tailscale/*` | Tailscale handlers | Stubbed; must use command wrapper. |

## WebSocket Endpoints

| Path | Current Purpose | Required Rust Control |
|---|---|---|
| `/api/ws` | HID keyboard/mouse control and capture status | Authenticated session, Origin validation, bounded message size, bounded queues. |
| `/api/vm/terminal` | PTY shell | Disabled by default, fresh auth, Origin validation, optional re-auth, audit logs. |
| `/api/stream/h264` | WebRTC H.264 signaling | Authenticated session, Origin validation, slow-client handling. |
| `/api/stream/h264/direct` | Direct H.264 stream | Authenticated session, Origin validation, bounded/drop-old frame handling. |
| `/api/picoclaw/gateway/ws` | Picoclaw runtime gateway | Authenticated session, Origin validation, session nonce binding. |

## Config Fields

Current fields preserved: `proto`, `host`, `port.http`, `port.https`, `cert.crt`, `cert.key`, `logger.level`, `logger.file`, `authentication`, `jwt.secretKey`, `jwt.refreshTokenDuration`, `jwt.revokeTokensOnLogout`, `stun`, `turn.turnAddr`, `turn.turnUser`, `turn.turnCred`, `security.loginLockoutDuration`, and `security.loginMaxFailures`.

Rust-only hardening fields introduced under `security`: `require_csrf`, `websocket_origin_check`, `access_token_duration`, `refresh_token_duration`, `revoke_tokens_on_password_change`, `allow_unsigned_updates`, `allow_terminal`, `allow_auth_disable`, and `allowed_origins`.

## External Components To Preserve

- `kvm_system` and `kvm_vision` remain external components.
- `libkvm.so` and `libkvm_mmf.so` remain the native hardware/video boundary.
- Init scripts under `/etc/init.d/` remain service-control boundaries until privileged helper work is split out.
- Video capture/encoder pipeline is not rewritten in Rust.
