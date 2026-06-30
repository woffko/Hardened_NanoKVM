# NanoKVM Backend Security Risk Inventory

This inventory started as the Rust rewrite hardening checklist. It combines a
historical review of the upstream Go backend with the completed security scan
artifacts under
`/tmp/codex-security-scans/Hardened_NanoKVM/3de4a18eb42f_20260606T132630+0300`.

Scope note: Go backend findings in this file are historical threat-model input
for the rewrite. Current Hardened release artifacts are Rust-only: the legacy
Go backend, backend switch scripts, and web backend selector are not shipped in
`kvmapp` packages or generated SD-card images. Release validation rejects
`NanoKVM-Server.go` and `switch-backend-go.sh`. The `server/` tree remains in
the repository only as an upstream reference while compatibility is audited.

## Required Security Changes

| Area | Historical / Upstream Risk | Rust Rewrite Requirement | Current Rust Status |
|---|---|---|---|
| First boot auth | Missing `/etc/kvm/pwd` falls back to `admin/admin`. | No default credential; require explicit setup or device-unique initial secret. | Rust default is hardened: `security.allow_default_admin=false`. Fresh SD-card flashes expose a one-shot first-boot web setup flow while `/etc/kvm/pwd` is missing. Temporary isolated test devices can explicitly set `allow_default_admin=true` to seed `admin/admin` as an Argon2id hash. |
| Password storage | The legacy Go/upstream implementation stores bcrypt or legacy encrypted compatibility values. | Argon2id, unique salt, no plaintext. | Implemented in `auth/password.rs`; Rust still verifies legacy bcrypt during migration. |
| Session revocation | JWT is self-contained; logout rotates secret globally. | Opaque/session-id or JWT with jti revocation; logout revokes active session; password change revokes all user sessions. | Implemented in-memory opaque sessions. Persistence policy still needs device decision. |
| CSRF | Cookie auth without CSRF token. | CSRF token for state-changing browser endpoints plus Origin/Referer checks. | Implemented. Middleware enforces `x-csrf-token` on protected POST/PUT/PATCH/DELETE and validates Origin/Referer when present. |
| WebSocket Origin | Existing upgraders return true for every Origin. | Reject unexpected Origins for every WebSocket. | Implemented for HID, H.264 Direct, H.264 WebRTC, and terminal WebSockets. |
| Login brute force | Lockout exists but defaults to disabled. | Safe default lockout enabled per IP and username. | Implemented in `security/rate_limit.rs`; default 5 failures, 10 min lockout. |
| Offline update extraction | Tar member traversal writes outside cache. | Safe temp extraction, no traversal, no symlink overwrite. | Safe path helper and safe tar.gz extraction added in `update/archive.rs`. |
| Update integrity | Same-origin checksum and legacy content-type-only updater. | Signed update metadata/artifacts. | Application and system update metadata signature verification is implemented with detached `latest.json.sig` / `system-latest.json.sig`; archives are still verified by sha512/sha256 as applicable. |
| Shell commands | Many `sh -c` command strings. | Central allowlisted argv-only wrapper with timeout and bounded output. | Implemented in `system/command.rs` and used by migrated routes; continued audit required for new routes. |
| Storage paths | Image mount/delete accept unsafe paths. | Enforce resolved `/data` containment and known image inventory. | Implemented for Rust storage and upload/delete/mount routes. |
| SSRF | Image downloader fetches arbitrary URLs. | Destination allowlist/denylist, redirect checks, content validation. | Remote ISO download is disabled by default and guarded by URL, protocol, filename, size, redirect, destination, and ISO signature checks. Final production policy still needed. |
| System updates | Kernel/rootfs updates can brick the device without rollback. | Separate signed system-update bundles with staging, backup, rollback, and boot health confirmation. | Artifact contract, GitHub channel metadata tooling, signed metadata enforcement, staging, guarded install, generated init-time rollback script, boot watchdog rollback, manual boot-good confirmation, and manual rollback are implemented. Current raw channel is lab-only `0.2.5-raw.1`, built from a validated Hardened SD image; `0.1.0-raw.1` is revoked because it used a stock SDK rootfs. Real kernel/rootfs security-backport payloads and production key management are still pending. Current application updater replaces `kvmapp`, not kernel/rootfs. |
| Privilege model | Backend effectively root for all operations. | Prefer unprivileged backend plus helper; otherwise mark root-required operations. | First phase keeps root-compatible model; docs list root-required operations. |

## Root-Required Operations

These operations must remain behind narrow wrappers or a future privileged helper:

- HID device writes: `/dev/hidg0`, `/dev/hidg1`, `/dev/hidg2`.
- USB mass-storage gadget sysfs writes under `/sys/kernel/config/usb_gadget/...`.
- GPIO/ATX writes under hardware-specific device paths.
- Network writes under `/etc/kvm`, DNS hooks, Wi-Fi files, and service restarts.
- Application update promotion under `/kvmapp`.
- Future system update promotion for kernel, dtb, modules, and rootfs files.
- Reboot and init-script service control.
- Terminal PTY shell, if enabled.

## Command Execution Inventory

The historical upstream Go backend contained shell or process execution in
these areas. They are retained here as reference points for Rust compatibility
and hardening review; they are not an active shipped Go attack surface in
current Hardened releases.

- `server/service/vm/script.go`: script run via `sh -c`.
- `server/service/vm/terminal.go`: `/bin/sh` PTY.
- `server/service/application/update.go` and `update_offline.go`: service restart via `sh -c`.
- `server/service/storage/image.go`: USB reset commands through `sh -c`.
- `server/service/extensions/tailscale/cli.go`: Tailscale operations through `sh -c`.
- `server/service/network/wifi.go`: init script invocation through `sh -c`.
- `server/service/vm/ssh.go`, `mdns.go`, `swap.go`, `tls.go`, `virtual-device.go`, `hid/status.go`: fixed service/control commands.
- `server/service/network/wol.go`: `ether-wake`.

Rust rule: API modules must not spawn commands directly. They must call
`system::command::run_allowed` or a narrower service helper.

## File And Archive Risk Inventory

- Account file: `/etc/kvm/pwd`, now must be `0600`.
- Session secret: `/etc/kvm/session_secret`, now generated and written `0600`.
- Update cache: `/data/.hardened-kvmcache`. Application updates use
  `/data/.hardened-kvmcache/application-update`; system updates use
  `/data/.hardened-kvmcache/system-update` with backups below that directory.
  The legacy `/root/.kvmcache` path is migrated in memory when old configs are
  loaded. System-update archives are constrained to `payload/boot/*` and
  `payload/rootfs/*` by the packaging contract, and runtime/device/cache roots
  such as `/dev`, `/proc`, `/sys`, `/run`, `/tmp`, `/data`, `/kvmapp`, and
  `/root/.kvmcache` are rejected.
- Image directory: `/data`, must use resolved containment and reject symlinks.
- Script directory: `/etc/kvm/scripts`, must use basename inventory and argv execution only.
- Autostart directory: `/etc/kvm/autostart`, must reject slash-bearing names and traversal.
- DNS/Wi-Fi files: require strict value validation and atomic writes.

## Follow-Up For Hardening

1. Keep `security.allow_default_admin=false` for production use and rely on
   first-boot setup for fresh SD-card flashes.
2. Finish systematic compatibility and error-semantics audit against historical
   upstream behavior where that behavior still matters to the UI or device
   workflows.
3. Keep remote ISO download disabled by default until final allowlist/content
   policy is accepted.
4. Test real kernel/rootfs security-backport payloads through the implemented
   system-update path before publishing them outside lab devices.
5. Define production release-key custody and rotation for application and
   system-update metadata signing.
6. Split root-required operations into a smaller privileged helper when the
   Rust backend behavior is stable enough.
