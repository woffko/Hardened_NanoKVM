# NanoKVM Backend Security Risk Inventory

This inventory drives the Rust rewrite hardening work. It combines the Go backend route review with the completed security scan artifacts under `/tmp/codex-security-scans/Hardened_NanoKVM/3de4a18eb42f_20260606T132630+0300`.

## Required Security Changes

| Area | Existing Risk | Rust Rewrite Requirement | Initial Rust Status |
|---|---|---|---|
| First boot auth | Missing `/etc/kvm/pwd` falls back to `admin/admin`. | No default credential; require explicit setup or device-unique initial secret. | Implemented: login refuses missing account; `/api/auth/setup` creates first Argon2id account. |
| Password storage | Go stores bcrypt or legacy encrypted compatibility values. | Argon2id, unique salt, no plaintext. | Implemented in `auth/password.rs`. |
| Session revocation | JWT is self-contained; logout rotates secret globally. | Opaque/session-id or JWT with jti revocation; logout revokes active session; password change revokes all user sessions. | Implemented in-memory opaque sessions. Persistence policy still needs device decision. |
| CSRF | Cookie auth without CSRF token. | CSRF token for state-changing browser endpoints plus Origin/Referer checks. | Middleware enforces `x-csrf-token` on protected POST/PUT/PATCH/DELETE. Origin/Referer HTTP checks still TODO. |
| WebSocket Origin | Existing upgraders return true for every Origin. | Reject unexpected Origins for every WebSocket. | Helper implemented in `ws/origin.rs`; route handlers still stubs. |
| Login brute force | Lockout exists but defaults to disabled. | Safe default lockout enabled per IP and username. | Implemented in `security/rate_limit.rs`; default 5 failures, 10 min lockout. |
| Offline update extraction | Tar member traversal writes outside cache. | Safe temp extraction, no traversal, no symlink overwrite. | Safe path helper and safe tar.gz extraction added in `update/archive.rs`. |
| Update integrity | Same-origin checksum and legacy content-type-only updater. | Signed update metadata/artifacts; reject unsigned by default. | Config default `allow_unsigned_updates=false`; full verifier TODO. |
| Shell commands | Many `sh -c` command strings. | Central allowlisted argv-only wrapper with timeout and bounded output. | Implemented in `system/command.rs`; API migration TODO. |
| Storage paths | Image mount/delete accept unsafe paths. | Enforce resolved `/data` containment and known image inventory. | API stubbed; helper patterns documented. |
| SSRF | Image downloader fetches arbitrary URLs. | Destination allowlist/denylist, redirect checks, content validation. | API stubbed; TODO. |
| Privilege model | Backend effectively root for all operations. | Prefer unprivileged backend plus helper; otherwise mark root-required operations. | First phase keeps root-compatible model; docs list root-required operations. |

## Root-Required Operations

These operations must remain behind narrow wrappers or a future privileged helper:

- HID device writes: `/dev/hidg0`, `/dev/hidg1`, `/dev/hidg2`.
- USB mass-storage gadget sysfs writes under `/sys/kernel/config/usb_gadget/...`.
- GPIO/ATX writes under hardware-specific device paths.
- Network writes under `/etc/kvm`, DNS hooks, Wi-Fi files, and service restarts.
- Application update promotion under `/kvmapp`.
- Reboot and init-script service control.
- Terminal PTY shell, if enabled.

## Command Execution Inventory

Current Go code contains shell or process execution in these areas:

- `server/service/vm/script.go`: script run via `sh -c`.
- `server/service/vm/terminal.go`: `/bin/sh` PTY.
- `server/service/application/update.go` and `update_offline.go`: service restart via `sh -c`.
- `server/service/storage/image.go`: USB reset commands through `sh -c`.
- `server/service/extensions/tailscale/cli.go`: Tailscale operations through `sh -c`.
- `server/service/network/wifi.go`: init script invocation through `sh -c`.
- `server/service/vm/ssh.go`, `mdns.go`, `swap.go`, `tls.go`, `virtual-device.go`, `hid/status.go`: fixed service/control commands.
- `server/service/network/wol.go`: `ether-wake`.

Rust migration rule: API modules must not spawn commands directly. They must call `system::command::run_allowed` or a narrower service helper.

## File And Archive Risk Inventory

- Account file: `/etc/kvm/pwd`, now must be `0600`.
- Session secret: `/etc/kvm/session_secret`, now generated and written `0600`.
- Update cache: `/root/.kvmcache`, must extract into temp dir and atomically promote.
- Image directory: `/data`, must use resolved containment and reject symlinks.
- Script directory: `/etc/kvm/scripts`, must use basename inventory and argv execution only.
- Autostart directory: `/etc/kvm/autostart`, must reject slash-bearing names and traversal.
- DNS/Wi-Fi files: require strict value validation and atomic writes.

## Follow-Up For API Porting

1. Port read-only status/info endpoints first.
2. Port auth frontend flow for `/api/auth/setup` or add a temporary setup token flow that avoids default credentials.
3. Port HID and storage only after safe path and command wrappers are integrated.
4. Port WebSockets only after Origin checks and bounded queue design are in place.
5. Port update last, after signature verifier is implemented.
