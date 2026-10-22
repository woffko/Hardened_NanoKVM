# NanoKVM Backend Security Risk Inventory

This document tracks the current security requirements and remaining hardening
work for the Hardened Rust backend.

## Required Security Controls

| Area                     | Requirement                                                                                                     | Current Status                                                                                                                                                                           |
| ------------------------ | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| First boot auth          | No default production credential; require first-account setup when `/etc/kvm/pwd` is missing.                   | Implemented. `security.allow_default_admin=false` by default; isolated lab devices can opt into explicit seeded credentials.                                                             |
| Password storage         | Argon2id for new writes, unique salt, no plaintext.                                                             | Implemented in `auth/password.rs`; existing bcrypt password files are still accepted for migration.                                                                                      |
| Session revocation       | Opaque sessions, logout revokes the active session, password change revokes user sessions.                      | Implemented in memory. Persistent session policy remains a product decision.                                                                                                             |
| CSRF                     | State-changing browser endpoints require CSRF binding plus Origin/Referer checks.                               | Implemented for protected POST/PUT/PATCH/DELETE routes.                                                                                                                                  |
| WebSocket Origin         | WebSockets must reject unexpected Origins.                                                                      | Implemented for HID, H.264 Direct, H.264 WebRTC, terminal and PicoClaw gateway sockets.                                                                                                  |
| Login brute force        | Lockout enabled by default per source (IPv4 address or IPv6 /64) and username.                                  | Implemented; default is 5 failures and 10 minute lockout. One off-runtime verification at a time.                                                                                        |
| Archive extraction       | No tar traversal, no symlink overwrite, bounded install paths.                                                  | Implemented for application, offline, and system-update archives.                                                                                                                        |
| Update integrity         | Signed metadata plus archive hashes before install.                                                             | Implemented for application and system-update metadata with detached signatures.                                                                                                         |
| Shell commands           | Privileged commands must use allowlisted argv-only wrappers with timeout and bounded output.                    | Implemented in `system/command.rs`; continued audit is required for new routes.                                                                                                          |
| Storage paths            | Image operations must remain inside resolved `/data` inventory and reject unsupported media types.              | Implemented for upload, delete, and mount. ISO media can be mounted as CD-ROM or mass storage for hybrid images; IMG media is limited to mass storage.                                   |
| Remote ISO download      | Disabled by default; validate protocol, redirects, filename, destination, size, and ISO signature.              | Implemented. Final production allowlist policy is still open.                                                                                                                            |
| Firewall/WebRTC boundary | Restrictive firewall modes must not expose WebRTC/ICE UDP.                                                      | Implemented. Restricted and Paranoid block H.264 WebRTC in firewall rules, backend route guard, and UI mode selection.                                                                   |
| System updates           | Signed bundles, staging, backup, rollback, boot health confirmation, and lab-only raw partition flashing guard. | Implemented for current lab raw channel. Production key custody and real kernel/rootfs payload validation are still pending.                                                             |
| Native video lifecycle   | Native capture restart/read/deinit and encoder resources must have one synchronized owner with bounded cleanup. | Open, high priority. The 2026-07-11 audit found camera restart/deinit races, VENC lifetime errors, bounds bugs, and unchecked hardware failures in the Rust backend's native dependency. |
| Privilege model          | Prefer narrow wrappers now; split privileged helper later.                                                      | Current backend remains root-compatible for device control.                                                                                                                              |

## Root-Required Operations

These operations must remain behind narrow wrappers or a future privileged
helper:

- HID device writes: `/dev/hidg0`, `/dev/hidg1`, `/dev/hidg2`.
- USB mass-storage gadget sysfs writes under `/sys/kernel/config/usb_gadget/...`.
  Normal virtual-media changes should be limited to removable-LUN eject/insert
  and flag updates. USB gadget reconnect is allowed when switching the media
  type between CD-ROM and mass storage because many BIOS/boot menus cache the
  previous LUN type; otherwise it remains an explicit compatibility fallback.
- USB HID configfs topology changes must not be performed live from the web
  backend. A live UDC detach plus HID unlink/relink test on device 133 caused a
  kernel oops; only direct attribute writes or reboot-time config changes are
  acceptable.
- GPIO/ATX writes under hardware-specific device paths.
- Network writes under `/etc/kvm`, DNS hooks, Wi-Fi files, and service restarts.
- Application update promotion under `/kvmapp`.
- System update promotion for boot/rootfs files and raw partition payloads.
- Reboot and init-script service control.
- Terminal PTY shell, when explicitly enabled.

## Command Execution Inventory

Rust API modules should not spawn shell command strings directly. Normal
service control and utility execution goes through
`system::command::run_allowed`, which provides an allowlisted argv-only wrapper
with timeouts and bounded output.

Main command call sites:

- `server-rust/src/api/application.rs`: app metadata/download and service restart.
- `server-rust/src/api/system_update.rs`: signed system-update metadata,
  staging, and guarded loader execution.
- `server-rust/src/api/download.rs`: guarded remote ISO downloader.
- `server-rust/src/api/network.rs`: WOL, Wi-Fi service control, Ethernet
  restart, and IPv6 route inspection.
- `server-rust/src/api/system_firewall.rs`, `system_log.rs`, `system_time.rs`,
  `tailscale.rs`, `vm.rs`, `hid.rs`, and `account.rs`: allowlisted service or
  system utility calls.

Known exceptions:

- `server-rust/src/api/script.rs` runs user-managed scripts from the configured
  script inventory and remains a root-required administrative feature.
- `server-rust/src/ws/hid.rs` invokes the fixed USB gadget init script for HID
  recovery.
- `server-rust/src/api/system_update.rs` runs a staged, generated loader from
  the signed system-update cache after path validation.
- Native SG2002 C/C++ support code contains fixed `system(...)` calls for
  hardware initialization and factory-compatible control paths. Its unresolved
  memory/thread/resource risks are tracked in
  [`native-code-audit.md`](native-code-audit.md).

## File And Archive Risk Inventory

- Account file: `/etc/kvm/pwd`, mode `0600`.
- Session secret: `/etc/kvm/session_secret`, generated and written `0600`.
- System-update public cache: `/data/.hardened-kvmcache/system-update`.
  Remediation source stages app updates in fresh private rootfs directories
  under `/etc/kvm/application-update`, with anonymous readonly-bound archives;
  it no longer trusts or cleans the old p3 application cache. This is not yet a
  released/fully accepted app transaction: durable slot swap/recovery and C1
  integration remain open. See [update ownership](security-update-ownership.md#private-application-staging).
- System-update archives are constrained to declared payload roots and reject
  runtime/cache roots such as `/dev`, `/proc`, `/sys`, `/run`, `/tmp`, `/data`,
  `/kvmapp`, and `/root/.kvmcache`.
- Image directory: `/data`, with resolved containment and symlink rejection.
- Script directory: `/etc/kvm/scripts`, with basename inventory and explicit
  execution only. Scripts run as root, so upload and run pass the terminal's
  gate: terminal access is enabled, and each operation consumes a fresh unlock
  ticket of the same session (header `X-NanoKVM-Terminal-Ticket`), issued after
  its password was entered again. Listing and deleting need only the session.
- Autostart directory: `/etc/kvm/autostart`, with traversal rejection. Nothing
  executes these files; historical autostart uploads are never activated.
- DNS/Wi-Fi files: strict value validation and atomic writes. A Wi-Fi SSID is
  1–32 bytes and a passphrase 8–63 bytes, as the supplicant accepts, and both
  are rejected before anything is written.
- AP provisioning key: its few possible values are guarded by a lockout of 5
  failures per source and 20 shared by all sources, each for 10 minutes. The key
  generator (native `kvm_system`), the `ap.pass` mode and hostapd's cipher
  choice live in native code and boot scripts and are still open.

## Follow-Up For Hardening

1. Fix and device-test the Priority 0 native lifecycle, VENC, bounds, and I2C
   findings in [`native-code-audit.md`](native-code-audit.md) before the next
   release.
2. Keep `security.allow_default_admin=false` for production use and rely on
   first-boot setup for fresh SD-card flashes.
3. Keep remote ISO download disabled by default until final allowlist/content
   policy is accepted.
4. Test real kernel/rootfs security-backport payloads through the implemented
   system-update path before publishing them outside lab devices.
5. Define production release-key custody and rotation for application and
   system-update metadata signing.
6. Split root-required operations into a smaller privileged helper when the
   Rust backend behavior is stable enough.
