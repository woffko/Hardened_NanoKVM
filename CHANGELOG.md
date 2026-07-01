## Hardened NanoKVM Beta 2.0.20 (unreleased)

### Features

* Added `Settings > System Log` with UDP remote syslog forwarding, local
  tmpfs-backed log viewing, kernel log viewing, and a test log action.
* Added web login audit events to syslog for successful logins, failed
  credentials, and lockout events.
* Added `Settings > System` as the home for system-level controls. `System Log`
  now lives inside this section.
* Added `Settings > System > Time` with timezone selection, NTP enable/disable,
  editable NTP servers, router/default server shortcuts, and manual sync.
* Added `Settings > System > Firewall` with a read-only iptables/ip6tables/nft
  rules viewer and guarded Restricted/Paranoid modes.
* Added managed baseline firewall initialization through `S40firewall`, replacing
  the older hardcoded iptables setup in `S95nanokvm`.
* Added online-update blocking notices when Paranoid mode is active, because
  outbound traffic to GitHub is intentionally blocked in that mode.
* Made Paranoid mode exit explicit in the GUI: the firewall page now always
  shows a visible **Disable Paranoid** action while Paranoid is configured or
  active.
* Added Restricted Firewall mode, allowing HTTPS, SSH, NTP, remote syslog,
  DHCP, established connections, and essential IPv6 control traffic while
  blocking other inbound/outbound traffic.

### Bug Fixes

* Disabling HTTPS now forces the managed firewall back to `baseline` before the
  backend is restarted, so HTTP access is not stranded behind Restricted or
  Paranoid rules.
* HTTPS enable/disable now restarts only the Rust web backend. The video helper
  process stays running, avoiding the HDMI capture loss that could appear until
  a full device reboot.

### Notes

* The local log viewer keeps the active log buffer under `/tmp` to avoid
  steady SD-card writes. Only syslog configuration is persisted.
* Remote forwarding uses BusyBox `syslogd -R`, so the initial transport is UDP.
* NTP remains enabled by default and uses public `pool.ntp.org` servers unless
  the user changes the server list.
* Paranoid firewall mode is available only after HTTPS is enabled and verified
  locally. It allows inbound HTTPS plus loopback, established traffic, DHCP, and
  essential IPv6 control traffic; other inbound and outbound traffic is dropped.
* Restricted firewall mode also requires HTTPS. Unlike Paranoid, it keeps
  outbound HTTPS available for online updates and permits SSH/NTP/syslog
  operation.

## Hardened NanoKVM Beta 2.0.19 (2026-07-01)

### Bug Fixes

* Fixed raw system-update reboot after writing the rootfs and boot partitions.
  The raw writer no longer relies on launching `reboot` from the overwritten
  live rootfs; it requests reboot through kernel sysrq after sync/remount.
* Fixed first-boot raw restore for preserved files located directly under `/`,
  including `/device_key`.
* Supersedes `2.0.18` / `0.2.14-raw.1`, where live testing showed the device
  could keep responding to ICMP with SSH/HTTP stopped if reboot did not happen
  after raw writes.

## Hardened NanoKVM Beta 2.0.18 (2026-07-01)

### Bug Fixes

* Fixed raw system-update root configuration restore. The raw writer no longer
  tries to mount the newly written rootfs while the old rootfs is still mounted
  as `/`; preserved root configuration is restored by `S01fs` on the first boot
  after the raw update, before SSH and the web backend start.
* Restored preserved file permissions after copying root configuration back
  from the exFAT `/data` staging area, including `/etc/shadow`, `/etc/kvm/pwd`,
  session secrets, and SSH host private keys.
* Added automatic system-update confirmation after boot health succeeds. This
  handles both file-based pending updates and raw update pending markers stored
  under `/data`.

### Notes

* Live raw update `0.2.13-raw.1` on `10.0.87.132` successfully wrote rootfs and
  boot and rebooted, but showed the old restore bug in
  `/data/hardened-system-raw-update.log`: `mount ... Resource busy`. This
  release fixes that path for the next raw build.

## Hardened NanoKVM Beta 2.0.17 (2026-07-01)

### Bug Fixes

* Avoided forcing `sync_all()` on large raw system-update payload files while
  staging archives on `/data`. This prevents the NanoKVM from rebooting or
  dropping the backend during the `download/verifying` phase on exFAT-backed
  staging storage.

### Notes

* Raw system release `0.2.12-raw.1` contained app `2.0.16`, but live testing on
  `10.0.87.132` showed the app updater could reboot during staging before raw
  install started. It is superseded by the matching `2.0.17` / `0.2.13-raw.1`
  build.

## Hardened NanoKVM Beta 2.0.16 (2026-06-30)

### Bug Fixes

* Fixed the raw system-update writer so it no longer depends on the rootfs
  loader/libc after it starts overwriting `/dev/mmcblk0p2`. The writer now
  copies BusyBox, the musl loader, and libc into its tmpfs run directory and
  launches BusyBox through the copied loader with a local library path.
* Moved raw-update preserved boot/rootfs state from `/tmp` to the `/data`
  staging directory, avoiding tmpfs exhaustion while preserving optional large
  runtime files.
* Hid a stale staged raw-system cache from the GUI when its version already
  matches the installed system and there is no pending install or active
  progress record.

### Notes

* This fix was installed manually on `10.0.87.132` for live validation after
  raw `0.2.11-raw.1` required a manual power-cycle.

## Hardened NanoKVM Beta 2.0.15 (2026-06-30)

### Bug Fixes

* Made data-partition initialization idempotent after raw rootfs writes.
  `S01fs` now checks for an existing `/dev/mmcblk0p3` before creating or
  formatting p3, then only restores `/etc/kvm.disk0` and mounts `/data`.
* Preserved `/etc/kvm.disk0` during raw system updates so an updated rootfs
  does not look like a first boot when a data partition already exists.

### Changed

* Rebuilt and published matching app, raw system-update, and SD-card artifacts:
  app `2.0.15`, raw system `0.2.11-raw.1`.
* Added explicit system-update metadata fields in the GUI: System update
  version, Base image, Buildroot release, and Security backport level.
* Published `0.2.11-raw.1` with security patch level
  `Buildroot 2023.11.3 package backports` while keeping the proven vendor
  Buildroot `2023.11.2` base label separate.

## Hardened NanoKVM Beta 2.0.14 (2026-06-30)

### Bug Fixes

* Mounted `/dev/mmcblk0p3` on `/data` from `S01fs` before raw update staging.
* Refused raw partition installs when the staged payload is on the same
  filesystem as `/`, avoiding writes that would read from the partition being
  overwritten.
* Normalized failed raw-install progress records so the GUI no longer leaves a
  stale reboot-required state after a writer stops before reboot.

### Notes

* Raw release `0.2.10-raw.1` is a lab/broken release. It staged correctly on a
  device with `/data` mounted, but it still lacked the later idempotent p3 init
  guard from `2.0.15` and must not be retried.

## Hardened NanoKVM Beta 2.0.13 (2026-06-30)

### Notes

* Internal app-only lab snapshot during raw-staging hardening. It was
  superseded by `2.0.14` and is preserved only in the release archive.

## Hardened NanoKVM Beta 2.0.12 (2026-06-30)

### Bug Fixes

* Added gzip-compressed raw boot/rootfs payload support for system updates.
  The updater now validates compressed payloads and streams `gzip -dc`
  directly to `/dev/mmcblk0p1` and `/dev/mmcblk0p2`.
* Reduced raw staging free-space requirements by keeping raw images compressed
  in `/data/.hardened-kvmcache/system-update`.

## Hardened NanoKVM Beta 2.0.11 (2026-06-30)

### Bug Fixes

* Preserved user/device state before raw partition writes and restored it onto
  the new rootfs/boot partition before reboot.
* Preserved static IPv4/DNS, IPv6 files, stable MAC, hostname, SSH host keys,
  web account/session state, TLS files, device key, and optional
  Tailscale/PicoClaw runtime state.
* Excluded old sysupgrade state files from restore so the newly installed raw
  system keeps its own version metadata and update public key.

## Hardened NanoKVM Beta 2.0.10 (2026-06-30)

### Bug Fixes

* Rebuilt the raw rootfs with the stock-compatible boot init script set.
  `2.0.9 / 0.2.5-raw.1` missed required scripts such as `S00kmod`, `S01fs`,
  and `S15kvmhwd`, which could leave video hardware devices unavailable after
  boot.
* Added release validation that rejects raw/SD rootfs images missing the
  required boot-safe init scripts.

## Hardened NanoKVM Beta 2.0.9 (2026-06-30)

### Features

* Added explicit IPv6 controls under Settings > Network. The wired interface
  now supports Disabled, SLAAC, DHCPv6, and Manual IPv6 modes from the GUI.
* IPv6 is disabled by default when no Hardened IPv6 mode has been configured,
  preventing hidden IPv6 exposure on networks that advertise IPv6 automatically.
* Bundled a small `udhcpc6` client for DHCPv6 mode. The DHCPv6 client uses a
  Hardened hook script that only manages IPv6/DNS state and does not reset the
  active IPv4 web/SSH connection.

### Bug Fixes

* The IPv6 panel now shows an Apply action when the desired mode is already
  Disabled but IPv6 is still active, so app-updated devices can apply the new
  default without toggling through another mode.

## Hardened NanoKVM Beta 2.0.8 (2026-06-29)

### Bug Fixes

* Fixed OLED sleep timers of 5 minutes and higher by shipping a rebuilt
  `kvm_system` helper with 32-bit timeout parsing. Earlier builds parsed the
  configured timeout into an 8-bit value, causing larger timer values to wrap
  and turn the display off too early.

## Hardened NanoKVM Beta 2.0.7 (2026-06-29)

### Bug Fixes

* Fixed a login-loop after IP/protocol changes or stale browser cookies. The
  web UI can now recover its CSRF cookie from the protected account endpoint
  when the HttpOnly session cookie is still valid.
* The CSRF cookie is now written and removed explicitly at path `/`, avoiding
  route-specific cookie state after hash-route navigation.

## Hardened NanoKVM Beta 2.0.6 (2026-06-29)

### Bug Fixes

* Made Manual network Apply schedule the browser redirect before waiting for
  the network-setting POST to finish, so changing the device IP still moves the
  browser to the target address if the request is interrupted by the Ethernet
  restart.
* Added `Cache-Control: no-store` to the HTML shell responses. This avoids old
  browsers reusing a stale React bundle after an application update, which can
  leave the UI stuck on the login screen until site data or cache is cleared.

## Hardened NanoKVM Beta 2.0.5 (2026-06-29)

### Features

* Added full Manual network editing in Settings > Network > DNS. Manual mode
  now edits wired IP address, subnet mask, router, and DNS servers, applies the
  settings through the existing `S30eth` boot mechanism, and redirects the
  browser to the configured address after apply.

### Bug Fixes

* Added a stable wired `eth0` MAC address mechanism. `S30eth` now creates and
  reuses `/boot/eth.mac`, derived from the device key, before DHCP/static
  configuration so DHCP leases do not move after every reboot.
* App startup and `S95nanokvm` now sync the bundled `S30eth` into
  `/etc/init.d`, and SD/raw-system validation now requires `S30eth` in both
  `/kvmapp/system/init.d` and `/etc/init.d`.

## Hardened NanoKVM Beta 2.0.4 (2026-06-29)

### Bug Fixes

* Cleared legacy `install/failed` system-update progress records without a
  staged version. These records were left by older app builds after pressing
  Install while raw system updates were disabled.
* Hid stale failed-progress messages when a newer system update is available
  for Download and Verify.

## Hardened NanoKVM Beta 2.0.3 (2026-06-29)

### Bug Fixes

* Fixed the system-update UI after failed raw installs. A stale staged raw
  update can no longer keep showing `Install` when a newer GitHub system update
  is available.
* System-update install progress now records the staged version, so old failed
  progress from previous builds is easier to distinguish from the current
  staged update.

## Hardened NanoKVM Beta 2.0.2 (2026-06-29)

### Bug Fixes

* Added Rust-backend startup synchronization for `/etc/init.d/S03usbdev` and
  `/etc/init.d/S95nanokvm`. This lets ordinary application updates install the
  stable USB gadget MAC fix on already-flashed devices before the next reboot.

## Hardened NanoKVM Beta 2.0.1 (2026-06-29)

### Bug Fixes

* Fixed update checks when Preview Updates is enabled. A stale preview channel
  can no longer hide a newer stable application or system update.
* Added stable locally-administered MAC addresses for USB NCM/RNDIS gadget
  functions, derived from the device key. `S95nanokvm` also syncs the bundled
  `S03usbdev` boot script into `/etc/init.d` after app updates so the MAC fix
  takes effect after the next reboot.

## Hardened NanoKVM Beta 2 (2026-06-29)

### Features

* Added a guarded **Allow raw system updates** switch directly to the
  Check for Updates screen. Enabling it shows a recovery warning before raw
  boot/rootfs writes are allowed.
* Prepared the beta 2 release line to ship the latest Rust-only application,
  SD-card image, and GUI-installable raw system-update bundle from the same
  integrated sysupgrade build.

### Changed

* Raised the application update version to `2.0.0`; the web UI displays this
  release as `beta 2`.
* System raw update installs now re-read `/etc/kvm/server.yaml` immediately
  before install, so enabling raw updates in the GUI works without restarting
  the backend.

## Hardened NanoKVM 1.0.5 Beta Security (2026-06-29)

### Security

* Removed the legacy Go backend from shipped `kvmapp` and SD-card artifacts.
  Release validation now rejects `NanoKVM-Server.go` and
  `switch-backend-go.sh` if they reappear.
* Hardened web sessions by moving the session token to an HttpOnly cookie.
  The frontend keeps only the CSRF token in JavaScript-readable storage.
* Added signed application update metadata verification. Online app updates now
  require `latest.json.sig` unless `security.allow_unsigned_updates=true`.
* Hardened application update archives by rejecting symlinks and forbidden
  legacy backend files before `/kvmapp` is replaced.
* Made `/etc/kvm/server.yaml` writes atomic, mode `0600`, and symlink-safe.
* Updated frontend dependencies and lockfile; `pnpm audit --audit-level low`
  reports no known vulnerabilities.

### Changed

* Removed the Settings > Device > Advanced backend switch from the web UI.
* Raised the displayed application version to `beta - 1.0.5`.

## Hardened NanoKVM 1.0.4 Beta Sysupgrade (2026-06-29)

### Bug Fixes

* Added rootfs content validation for experimental raw system-update releases so
  stock vendor SDK rootfs images without Hardened NanoKVM files are rejected
  before packaging.
* Changed raw system-update build defaults to extract boot/rootfs from the
  patched Hardened SD image instead of vendor SDK stock artifacts.
* Made the SSH setting idempotent and state-based. Re-enabling an already
  running SSH service now reports `enabled: true` instead of letting the GUI
  switch appear to bounce back to disabled.
* Hardened raw partition install diagnostics and failure handling around
  read-only rootfs remounts.
* Fixed system-update preview channel handling. System update check/download
  now respects the same Preview Updates flag as application updates.

### Documentation

* Marked `hardened-system-0.1.0-raw.1` as a revoked experimental raw release
  and documented the correct SD/raw release build flow.
* Recorded that SDK-derived raw images should be tested only after a fresh
  known-good Hardened SD image from this sysupgrade branch passes end-to-end.

## Hardened NanoKVM 1.0.2 Beta (2026-06-28)

### Bug Fixes

* Added H.264 capture safe mode and a startup health watchdog. Devices now boot
  into MJPEG by default, can opt into H.264 from the UI, and recover to MJPEG if
  H.264/VENC leaves the Rust backend unhealthy.
* Prevented saved browser H.264 mode from repeatedly re-triggering a bad H.264
  startup loop after a page reload.

### Documentation

* Added build notes for real hardware releases, including the required
  `linked-libkvm` build path and BusyBox-compatible manual install steps.

## Hardened NanoKVM 1.0.1 Beta (2026-06-28)

### Features

* Added password unlock for terminal sessions. Opening the web terminal now
  requires the current account password and uses a one-time ticket bound to the
  active web session.

### Bug Fixes

* Added automatic USB HID gadget recovery when keyboard, mouse, or paste writes
  hit a timeout while the USB controller is not configured. The backend now
  performs a soft gadget restart, waits for `configured`, reopens HID devices,
  and retries the write once.

### Security

* Terminal websocket access no longer opens a root shell from the web session
  alone; the terminal session must be unlocked with the account password and
  expires with the web session.

## Hardened NanoKVM 1.0.0 Beta (2026-06-28)

### Features

* Added a first-boot web setup flow: if `/etc/kvm/pwd` is missing, the login
  page now prompts the user to create the first administrator account instead
  of relying on a default web password.
* Added public `GET /api/auth/setup` status for the setup screen and kept
  `POST /api/auth/setup` one-shot: after the account file exists, setup returns
  conflict.

### Security

* Kept default `admin/admin` web bootstrap disabled for SD-card images.
* Updated password recovery text to reflect the Hardened policy: lost web/root
  credentials are recovered by reflashing the SD card.

## Hardened NanoKVM 0.1.9 (2026-06-27)

### Bug Fixes

* Added default `/kvmapp/kvm` state files to the update package so clean
  updates keep `kvm_system` from crashing when it reads HDMI width/height
  before the native video stack has refreshed them.
* Hardened `S95nanokvm` startup to recreate missing stream state files before
  launching `kvm_system` and `NanoKVM-Server`.
* Verified five consecutive device reboots on hardware with Rust backend,
  `kvm_system`, HDMI capture, and H.264 Direct streaming alive after each boot.

## Hardened NanoKVM 0.1.8 (2026-06-27)

### UI

* Replaced the temporary Rust gear branding with the Hardened NanoKVM wordmark
  in the web UI.
* Added the Hardened NanoKVM logo to the top of the project README.
* Updated the login screen fallback version label to `alfa - 0.1.8`.

## Hardened NanoKVM 0.1.7 (2026-06-27)

### Features

* Added device uptime to the About page.
* Added a Settings > Device session lock duration selector with 5, 15, 30, and 60 minute options.

### Bug Fixes

* Fixed the About page application version display to show the actual Hardened app version from `/kvmapp/version`.
* Matched frontend auth cookie expiry to the Rust backend session expiry when the backend returns `expiresAt`.

## Hardened NanoKVM 0.1.6 (2026-06-27)

### Bug Fixes

* Fixed the GUI update package so it includes the original `/kvmapp/kvm_system/kvm_system` helper from the base NanoKVM image.
* Prevented future release packaging from producing an update archive that would remove `kvm_system` and leave the web UI showing `No HDMI signal detected` after updating.

## Hardened NanoKVM 0.1.5 (2026-06-27)

### Features

* Added a disabled-by-default Remote ISO Download security toggle in Settings > Appearance.
* Restored guarded remote ISO download by URL in the Rust backend with safe filename validation, protocol restrictions, size limits, and ISO9660 validation.

### Bug Fixes

* Restored Go-compatible HDMI capture status websocket events for MJPEG, H.264 Direct, and H.264 WebRTC in the Rust backend.
* Restored the old Go behavior where setting or changing the web account password also updates the system `root` password.

### Security

* Kept remote ISO download disabled until explicitly enabled from the GUI.
* Downloaded remote ISO files are written only under the configured image directory and reject unsafe paths, symlink destinations, and non-ISO files.

## Hardened NanoKVM 0.1.4 (2026-06-27)

### Bug Fixes

* Fixed a Rust H.264 Direct crash after updating when the saved resolution is `Automatic`.
* Stopped passing `0x0` capture dimensions into libkvm from the Rust streaming path; automatic resolution now uses a safe native capture size before calling the native camera layer.

## Hardened NanoKVM 0.1.3 (2026-06-27)

### Release Notes

* Added Hardened-specific changelog entries and kept the Check for Updates changelog link pointed at `woffko/Hardened_NanoKVM`.
* No backend behavior changes from `0.1.2`; this release exists to validate the GitHub-backed update flow after changelog cleanup.

## Hardened NanoKVM 0.1.2 (2026-06-27)

### Features

* Added GitHub Releases-backed online update checks for `woffko/Hardened_NanoKVM`.
* Added GUI-installable `hardened-nanokvm-kvmapp-*.tar.gz` update archives with `latest.json` metadata.
* Added release packaging support for semver `/kvmapp/version` values and generated release metadata.
* Published SD-card image artifacts alongside GUI update archives.

### Bug Fixes

* Fixed update checks when the Preview Updates toggle is enabled but no preview metadata release exists by falling back to stable release metadata.

### Security

* Restricted online update downloads to Hardened NanoKVM GitHub release URLs.
* Verified downloaded update archives with sha512 from `latest.json` before installation.
* Kept safe tar extraction for online and offline application updates.

### UI

* Updated Check for Updates links to the Hardened repository changelog and releases.
* Accepted Hardened update archive names in the offline update picker.

## Hardened NanoKVM 0.1.1 (2026-06-27)

### Release Notes

* First public test release for GitHub-backed application updates.
* Superseded by `0.1.2` because preview-update mode needed a stable metadata fallback.

## Hardened NanoKVM 0.1.0 (2026-06-27)

### Features

* Added the Rust backend as a drop-in `NanoKVM-Server` replacement while keeping the original Go backend as a switchable fallback.
* Added Hardened branding on the login screen, toolbar, and About page.
* Added the Settings > Device > Advanced backend switch for Rust/Go testing.
* Added HTTPS support, Rust auth/session hardening, CSRF protection, Origin checks, H.264 Direct, H.264 WebRTC signaling, MJPEG, HID, storage, network, Tailscale, terminal gating, scripts, autostart, and core VM settings routes.

### Performance

* Added MJPEG and H.264 Direct fanout so multiple viewers do not multiply native capture reads.
* Defaulted new browser sessions to H.264 Direct when HTTPS and WebCodecs are available.

### Bug Fixes

* Hardened HID writes against stale USB gadget handles and transient `ENXIO` errors.
* Fixed Rust resolution changes, FPS changes, 0x0 capture fallback handling, and backend startup cleanup issues found during device testing.
* Fixed invalid-login responses to use the expected wrong-password message instead of a generic unexpected error.

### Security

* Added safer path handling for scripts, autostart files, ISO upload, storage paths, and update archive extraction.
* Disabled remote ISO download in the Rust backend until allowlist and redirect checks are complete.
* Gated web terminal access behind the existing Terminal menu toggle with a warning.

## 2.4.3 (2026-06-09)

### Features

* Added LT6911D support

### Bug Fixes

* Improved USB network adapter compatibility on Windows

## 2.4.2 (2026-05-20)

### Features

* Added HDMI capture status detection with localized warning and error overlays on the desktop screen

### Bug Fixes

* Fixed left-button touch cancellation and context menu cleanup for mouse input
* Improved the WebRTC loading indicator
* Added Wi-Fi password field validation
* Hardened Wake-on-LAN MAC handling by normalizing stored addresses, avoiding shell execution, handling missing history gracefully, and improving named MAC display
* Stabilized PicoClaw session switching by waiting for gateway release, refreshing runtime status before reconnecting, rendering structured thought messages, and preventing history row overflow

### Performance

* Improved H.264 streaming client handling by reducing frame queue latency, using client snapshots for fanout, applying backend ICE server configuration, and cleaning up disconnected WebRTC clients more aggressively

### UI Improvements

* Refreshed desktop menu ordering and community links, including replacing the Discussion link with Discord

### Chores

* Removed the legacy H.264 stream package
* Updated PostCSS, refreshed the MSW worker, and added pnpm workspace build approvals

## 2.4.1 (2026-05-08)

### Features

* Added DNS management to Network settings, including DHCP/manual modes, effective DNS display, network details, IPv4/IPv6 server validation, and persistent udhcpc hook support
* Added a configurable server `host` option for binding NanoKVM to a specific listen address (thanks to [@allmazz](https://github.com/allmazz))
* Added French keyboard layout support and language options (thanks to [@ilyesAj](https://github.com/ilyesAj))

### Bug Fixes

* Hardened HID recovery and cleanup by adding non-blocking HID writes, bounded reopen retries, stale event draining, and release reports after write failures
* Fixed the `kvm_vision` project name and build output message in the SG2002 build script (thanks to [@Voranto](https://github.com/Voranto))

### UI Improvements

* Moved TLS and Wi-Fi settings into the Network settings section
* Optimized the Settings scrollbar style

### Localization

* Updated Korean translations (thanks to [@kmw0410](https://github.com/kmw0410))
* Synchronized translations of other languages according to English

### Security

* Upgraded vulnerable web dependencies

## 2.4.0 (2026-04-10)

### Features

* **Introduced [PicoClaw](https://github.com/sipeed/picoclaw) support** — an AI-powered remote desktop assistant for NanoKVM. PicoClaw seamlessly integrates a lightweight AI agent with NanoKVM's underlying hardware capabilities. Key highlights include:
  * **Zero-Agent Architecture:** Operates entirely through HDMI video capture (vision) and USB HID emulation (keyboard/mouse). No SSH access, network connection to the host, or OS-level software installation is required.
  * **Natural Language Control:** Features a built-in chat interface allowing users to issue complex instructions in plain text.
  * **Autonomous GUI Operation:** The AI agent can autonomously observe the remote host's screen, understand UI elements, reason about the task, and execute operations mimicking human behavior.
  * **Installation Note:** PicoClaw is not built into the NanoKVM device or firmware. Install it separately when needed.

### Bug Fixes

* Added a default subnet mask for static IP configurations
* Fixed an issue where the IP address would occasionally not display

## 2.3.6 (2026-03-12)

### Features

* Implemented AP password authentication for the WiFi configuration page
* Added Korean and Japanese virtual keyboard layouts (thanks to [@klim4-bot](https://github.com/klim4-bot))
* Enabled support for 640x480 resolution (thanks to [@Voranto](https://github.com/Voranto))
* Added encryption parameters for OLED distribution network
* Added custom logo function and logo generation tools
* Added update mechanism for tailscale startup script

### Localization

* Updated Japanese translation (thanks to [@tkmsst](https://github.com/tkmsst))

## 2.3.5 (2026-02-28)

### Features

* Implemented login brute-force protection with lockout mechanism

### Bug Fixes

* Improved Tailscale error handling in UI components and refined backend state mapping

### Chores

* Updated server and web dependencies

## 2.3.4 (2026-01-26)

### Features

* Introduced `Leader Key` functionality to bypass local browser shortcut interception

### Bug Fixes

* Fixed an issue where the Right Shift key was not being recognized on Windows system
* Fixed a bug where the menu bar would fail to close correctly

### Localization

* Updated Traditional Chinese translations (thanks to [@j796160836](https://github.com/j796160836))
* Updated Korean translations (thanks to [@kmw0410](https://github.com/kmw0410))

## 2.3.3 (2026-01-16)

### Features

* Added support for setting the display mode of the menu bar

### Bug Fixes

* Fixed a keyboard issue where IME composition events were not handled correctly
* Resolved an issue where the `AltGr` key was not recognized on the Windows system
* Fixed a bug where `Command` key combinations were not fully released on the macOS system
* Fixed input issues with the `IntlBackslash` key on the German virtual keyboard

### Localization

* Updated Korean translations (thanks to [@kmw0410](https://github.com/kmw0410))

### Chores

* Bump react-router-dom from 6.27.0 to 6.30.3
* Updated eslint

## 2.3.2 (2026-01-08)

### Features

* Added support for custom keyboard shortcuts
* Added support for mouse Forward and Back buttons (reboot required)
* Added support for touchscreen mouse operation
* The menu bar now supports auto-hide and drag

### Bug Fixes

* Fixed an issue where the previous IP address was not released after configuring a static IP

### Performance

* Refactored the keyboard to support simultaneous keystrokes and a wider range of international layouts (reboot required)
* Refactored the mouse to improve response latency
* Refactored the WebSocket module to transmit keyboard and mouse data using the standard HID format

## 2.3.1 (2025-12-26)

### Features

* Added support for offline application updates (thanks to [@Alexander-Ger-Reich](https://github.com/Alexander-Ger-Reich))
* Implemented support for uploading ISO images (thanks to [@Alexander-Ger-Reich](https://github.com/Alexander-Ger-Reich))
* Extended clipboard compatibility to support Russian characters (thanks to [@pekishev](https://github.com/pekishev))
* Added configuration options for video scaling
* Added support for configuring mouse scroll wheel direction

### Bug Fixes

* Resolved an issue where custom port may not be accessible
* Fixed a bug where Web Terminal and Serial Terminal may not disconnect when the page is closed

### Security

* Enhanced validation logic on the Wi-Fi configuration page. Requests are now rejected when the device is not in AP mode to prevent unauthorized changes

### Chore

* Added a Docker image environment to support building `libkvm.so` and `NanoKVM-Server` (thanks to [@lowtech-guy](https://github.com/lowtech-guy))
* Optimized the Settings UI

### Localization

* Updated Korean translation (thanks to [@kmw0410](https://github.com/kmw0410))
* Updated Swedish translation (thanks to [@acidflash](https://github.com/acidflash))
* Updated Spanish translation (thanks to [@Deses](https://github.com/Deses))

## 2.3.0 [0e30a26](https://github.com/sipeed/NanoKVM/commit/0e30a26db42cbc08416662b49a88a5d16ad93424) (2025-11-26)

### Features

* Added an EDID editor in the terminal with a built-in 1080P EDID template
* Added German virtual keyboard and German clipboard support (thanks to [@Alexander-Ger-Reich](https://github.com/Alexander-Ger-Reich))
* Resetting the HID also resets the USB hardware
* Added support for deleting ISO images

### Refactoring & Improvements

* Video (H.264 WebRTC): Refactored the module to significantly reduce video latency
* Video (H.264 Direct): Refactored to optimize data transmission and support data parsing even when the page is in the background
* Video (MJPEG): Refactored and ensure correct data length transmission
* Added locking before resetting USB to prevent HID deadlock (thanks to [@scpcom](https://github.com/scpcom))
* Optimized HID writing logic
* Made HDMI toggle state persist across reboots (thanks to [@tpretz](https://github.com/tpretz))
* Enhanced the paste feature with browser clipboard API integration (thanks to [@patrickpilon](https://github.com/patrickpilon))
* Set the inquiry string for the virtual storage device (thanks to [@scpcom](https://github.com/scpcom))
* Hostname now updates `/etc/hosts` simultaneously and takes effect immediately (thanks to [@scpcom](https://github.com/scpcom))
* Improved compatibility for static IP configuration on Windows
* Optimized the web page title update logic
* Added a confirmation dialog when uninstalling Tailscale
* Improved UI for Clipboard, Image Mounting, and settings pages

### Bug Fixes

* Tailscale: Fixed an issue where Tailscale would turn the device into a router
* Tailscale: Fixed an issue where Tailscale would disable IPv6
* Tailscale: Added a swap memory option to prevent Tailscale Out-Of-Memory errors
* Tailscale: Fixed Tailscale accept-dns configuration (thanks to [@lazydba247](https://github.com/lazydba247))
* Fixed an issue where certain modifier keys were not recognized
* Fixed vertical mouse drift when the page is zoomed in or out

### Localization

* Update Korean translation (thanks to [@xenix4845](https://github.com/xenix4845))
* Update Traditional Chinese translation (thanks to [@protonchang](https://github.com/protonchang))
* Add Brazilian Portuguese translation (thanks to [@chiconws](https://github.com/chiconws) and [@Luccas-LF](https://github.com/Luccas-LF))
* Add Swedish translation (thanks to [@acidflash](https://github.com/acidflash))
* Add Catalan translation (thanks to [@Zagur](https://github.com/Zagur))
* Add Turkish translation (thanks to [@Keylem](https://github.com/Keylem))

### Security

* Implemented a delay after failed login attempts to mitigate brute-force attacks
* Upgraded dependencies to fix known security vulnerabilities

## 2.2.9 [c77981c](https://github.com/sipeed/NanoKVM/commit/c77981cc0ceebd8f6705b6c5d8c3cf4edf4f6717) (2025-06-13)

* fix(security): resolve parameter injection in serial port terminal

## 2.2.8 [01e28f1](https://github.com/sipeed/NanoKVM/commit/01e28f10ae8b581d484bb6077ddfe7bbe4e57919) (2025-05-22)

* feat: add AZERTY virtual keyboard Layout (thanks to [@felix068](https://github.com/felix068))
* feat: add support for enabling/disabling HDMI output (PCIe version only) (thanks to [@tpretz](https://github.com/tpretz))
* feat: add support for custom mouse wheel speed
* fix: prevent direct H.264 stream buffer overflow and replay issues
* perf: improve keyboard paste performance (thanks to [@ethanperrine](https://github.com/ethanperrine))
* Localization
  * update Korean translation (thanks to [@kmw0410](https://github.com/kmw0410))
  * update Ukrainian translation (thanks to [@arbdevml](https://github.com/arbdevml))
  * update Russian translation (thanks to [@arbdevml](https://github.com/arbdevml))

## 2.2.7 [e18ec22](https://github.com/sipeed/NanoKVM/commit/e18ec2219d22886529575d1fdaad5c320e05f5b2) (2025-05-08)

* feat: add HTTPS support
* feat: support direct H.264 streaming over HTTP
* Localization
  * update Russian translation (thanks to [polyzium](https://github.com/polyzium))
  * update Dutch translation (thanks to [LeonStraathof](https://github.com/LeonStraathof))
  * update Ukrainian translation (thanks to [click0](https://github.com/click0))
  * update German translation (thanks to [3limin4tor](https://github.com/3limin4tor))

## 2.2.6 [c83dc55](https://github.com/sipeed/NanoKVM/commit/c83dc5565c9dbed22336661a8832edbd93a06d11) (2025-04-17)

* feat: add mouse jiggler to prevent system sleep
* feat: add support for swap memory
* feat: add support for customizing the device hostname
* feat: add support for customizing the web page title
* feat: add support for assigning custom names to Wake-on-LAN MAC addresses
* feat: add confirmation prompts for power operations
* feat: add logo to the login page (thanks to [S33G](https://github.com/S33G))
* fix: fix possible privacy issues with MIC drivers. [Repair Record](https://github.com/sipeed/NanoKVM/commit/f9244b36df090a05cd59ba11ea4fd01e9b638995)
* fix: fix iptables rule that could interfere with SSH connections (thanks to [scpcom](https://github.com/scpcom))
* fix: fix the static IP gateway configuration might not apply correctly (thanks to [xitation](https://github.com/xitation))
* perf: optimized OLED display handling and sleep logic
* perf: improve H.264 streaming reliability by adding a heartbeat mechanism
* perf: set the minimum screen size to 640x480
* perf: add display of both wired and wireless IPv4 addresses in the settings page
* perf: update the Thai language translations (thanks to [ChokunPlayZ](https://github.com/ChokunPlayZ))
* chore: bump axios to 1.8.4
* chore: bump golang.org/x/net to v0.39.0
* chore: bump github.com/golang-jwt/jwt/v5 to to v5.2.2

## 2.2.5 [3286cc2](https://github.com/sipeed/NanoKVM/commit/3286cc2f85a14133d65935cb476c833dcf151459) (2025-03-26)

* fix: server crash caused by MJPEG frame detection error
* feat: add HID-Only mode
* feat: support preview updates
* perf: improve image reading performance by optimizing screen parameters

## 2.2.4 [1bf986d](https://github.com/sipeed/NanoKVM/commit/1bf986d41b34d568c1ffee5df90ce61b6b08456b) (2025-03-21)

* fix: resolve USB initialization issue
* fix: correct abnormal updates in certain models
* perf: add version restrictions for production testing

## 2.2.3 [6ef83cb](https://github.com/sipeed/NanoKVM/commit/6ef83cb22fcd77f721d32c97c85d12f2bfc3035a) (2025-03-21)

* feat: add support for setting H.264 GOP
* fix: resolve deadlock caused by HDMI resolution errors
* perf: merge H.264 SPS and PPS into I-frame
* perf: refactor MJPEG frame detection
* perf: added more configuration options to the serial port terminal (thanks to [@mekaris](https://github.com/mekaris))
* perf: improve the `update-nanokvm.py` script (thanks to [@reishoku](https://github.com/reishoku))
* perf: disable mDNS by default in new products
* perf: update log timestamp to millisecond precision
* chore: bump Go to 1.23
* chore: bump `golang.org/x/net` to v0.37.0

## 2.2.2 [58d5ab2](https://github.com/sipeed/NanoKVM/commit/58d5ab2d37244b1e1a68b925a5c23c324c489ad3) (2025-03-11)

* feat: add watchdog for NanoKVM-Server
* feat: add support for UE chip
* feat: support system reboot
* feat: support enable/disable mDNS
* fix: resolve UE chip cannot start server
* perf: refactor automatic resolution detection
* perf: add output prompt for unsupported resolutions
* perf: add lock to kvmv_read_img
* perf: configurable VENC automatic recycling feature
* perf: add maximum limit for vi
* perf: add tooltips to menu bar (thanks to [@S33G](https://github.com/S33G))
* perf: menu bar is now draggable (thanks to [@forumi0721](https://github.com/forumi0721))
* perf: image list support auto-refresh (thanks to [@forumi0721](https://github.com/forumi0721))
* perf: update translations

## 2.2.1 [b5e48a0](https://github.com/sipeed/NanoKVM/commit/b5e48a07e82df3aedd60442342ae50b95684a697) (2025-02-21)

* fix: mounted image were not being detected correctly
* perf: add support for CD-ROM mode when mounting image (thanks to [@scpcom](https://github.com/scpcom))
* perf: add a loading state during login
* perf: add changelog link in settings
* perf: update translation and cleanup the code (thanks to [@ChokunPlayZ](https://github.com/ChokunPlayZ) [@Stoufiler](https://github.com/Stoufiler) [@polyzium](https://github.com/polyzium) [@Jonher937](https://github.com/Jonher937) [@S33G](https://github.com/S33G))

## 2.2.0 [0dbf8c0](https://github.com/sipeed/NanoKVM/commit/0dbf8c007f2d0183d0f0601c3da6d3c3fccd8b31) (2025-02-17)

NanoKVM [Image v1.4.0](https://github.com/sipeed/NanoKVM/releases/tag/v1.4.0) has been released!

> Please refer to the [wiki](https://wiki.sipeed.com/hardware/en/kvm/NanoKVM/system/introduction.html) for more details about the image and application.

* fix: improve password update notification logic (thanks to [@li20034](https://github.com/li20034))
* perf: increase update wait time to 10s (from 6s)
* perf: update Korean translation (thanks to [@forumi0721](https://github.com/forumi0721))
* perf: update Traditional Chinese translation (thanks to [@protonchang](https://github.com/protonchang))
* refactor: update `libkvm.so` and `libkvm_mmf.so` libraries

## 2.1.6 [6eb4a4e](https://github.com/sipeed/NanoKVM/commit/6eb4a4ea6254f465a47f9881d13934c686649061) (2025-02-14)

* feat: support downloading image from online URL (thanks to [@Itxaka](https://github.com/Itxaka))
* feat: add keyboard shortcut `Ctrl+Alt+Del` (thanks to [@CaffeeLake](https://github.com/CaffeeLake))
* fix: fix the CSRF issue
* perf: add an option to configure custom ICE servers (thanks to [@VMFortress](https://github.com/VMFortress))
* perf: removed unnecessary modifications to DNS configuration
* perf: add an SSH enable/disable toggle in the web UI
* perf: add a Tailscale enable/disable toggle in the web UI
* perf: download Tailscale installation package from the official source
* perf: automatic enable/disable GOMEMLIMIT on tailscale start/stop
* perf: add JWT configuration
  * secretKey: customize secret key. If empty, generated a random 64-byte secret key by default
  * refreshTokenDuration: customize token expiration time
  * revokeTokensOnLogout: invalidate all JWT tokens on logout
* perf: implement secure password storage using bcrypt hashing
* perf: implement integrity checks for online updates
* refactor: refactor HDMI module and remove the dependency `libmaixcam_lib.so`
* refactor: web terminal use pty instead of SSH
* refactor: move Tailscale APIs from the `network` module to the `extensions` module

## 2.1.5 [85f6447](https://github.com/sipeed/NanoKVM/commit/85f6447a16cc2591c6459b7d3dfda4d4cb75e98c) (2025-01-14)

* feat: add HDMI reset for NanoKVM-PCIe
* fix: remove unnecessary lock acquisition during HID reset
* refactor: refactor Tailscale

## 2.1.4 [d7ca7c4](https://github.com/sipeed/NanoKVM/commit/d7ca7c453d821ad099bf79b463969419041279cb) (2025-01-10)

* feat: support configuring OLED sleep settings
* feat: support setting the `GOMEMLIMIT` environment variable
* fix: fix Wi-Fi configuration
* perf: password changes now update both the web user and the system root user
* perf: add MAC address verification for Wake-on-LAN
* refactor: a lot update to web UI
* refactor: refactor Tailscale

## 2.1.3 [26078fe](https://github.com/sipeed/NanoKVM/commit/26078fe46e43d4543d7b09901b4992e4fbe4f01f) (2024-12-27)

* feat: add API to retrieve Wi-Fi information
* fix: fix keyboard modifier keys
* fix: update keyboard and mouse HID codes
* fix: update hardware version information

## 2.1.2 [5a39562](https://github.com/sipeed/NanoKVM/commit/5a39562f2d32695933f4e7e86866136236cc9903) (2024-12-04)

* feat: add hardware version to configuration
* feat: add Wi-Fi configuration support for NanoKVM-PCIe
* perf: update web UI
* chore: add dependency libraries

## 2.1.1 [74a303b](https://github.com/sipeed/NanoKVM/commit/74a303bd5cbb58f9d8ddd81abaaf4919dbbfb71b) （2024-11-06）

* feat: support h264
