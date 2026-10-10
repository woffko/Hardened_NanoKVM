# Hardened NanoKVM

<p align="center">
  <img src="web/public/hardened-logo.png" alt="Hardened NanoKVM logo" width="720">
</p>

<div align="center">
  <br>
  <img src="https://wiki.sipeed.com/hardware/assets/NanoKVM/introduce/NanoKVM_3.png" alt="NanoKVM" style="margin: 20px 0;">
  <h3>
    <a href="https://wiki.sipeed.com/hardware/en/kvm/NanoKVM/introduction.html">🚀 Quick Start</a>
     |
    <a href="https://cn.dl.sipeed.com/shareURL/KVM/nanoKVM">🛠️ Hardware Details</a>
     |
    <a href="https://github.com/woffko/Hardened_NanoKVM/releases/latest">💾 Hardened Releases</a>
  </h3>
  <br>
</div>

## Hardened NanoKVM

Hardened NanoKVM is a beta security-focused fork of Sipeed NanoKVM. It ships a
Rust web backend while keeping the existing NanoKVM hardware, web UI, native
video pipeline, and service layout.

The project goal is not to rewrite the whole firmware. The Rust backend remains
a drop-in `NanoKVM-Server` and continues to use the existing `kvm_system`,
`libkvm.so`, USB gadget setup, Maix multimedia stack, and frontend. Native
runtime libraries used by the Rust backend live under `server-rust/native/`.

The web UI currently brands this fork as **Hardened NanoKVM**. The current
combined GitHub release is **2.0.42 RC12** with system `0.3.0-raw.12`.

The combined application/raw/SD release is available from the `woffko` fork at
[`hardened-system-0.3.0-raw.12`](https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.3.0-raw.12).

> [!NOTE]
> RC12 was released from [`security/kernel-5.10.265`](https://github.com/woffko/Hardened_NanoKVM/tree/security/kernel-5.10.265),
> not from the older default-branch code baseline. Use the immutable release
> tag or that maintenance branch when reviewing or rebuilding RC12 source.

Detailed RC12 changes and limitations are in
[the combined release notes](docs/releases/rc12-2.0.42-raw.12.md). Existing
installations should also read the
[manual key-transition notes](docs/releases/2.0.42-key-transition.md) before
installing raw.12.

The latest preview raw system-update and SD-card artifacts are the
**0.3.0-raw.12** Buildroot `2026.05.1` / Linux `5.10.265-tag-` builds. Existing
devices must manually install the app `2.0.42` trust bridge first and only then
start the raw update. A manually flashed SD image already contains the matching
app.

## Installing System 0.3.0-raw.12

> [!IMPORTANT]
> Existing installations cannot receive the new production trust key through
> the lost legacy signing key. Download app `2.0.42` from the manual
> [`key-transition prerelease`](https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-2.0.42-key-transition),
> require SHA-256
> `aa0cd78c1b2e9951f216826c44b4b7ff2fb211fc1980540366f8f5b1f7e0dd20`,
> and install it through authenticated **Offline Update** before raw.12. The
> system stable channel intentionally remains on `0.2.23-raw.1`; raw.12 is on
> the **system preview** channel.

### Upgrade an existing installation

Keep a working recovery SD card or a full image backup and provide continuous
power before beginning. Then use this exact order:

1. Download `hardened-nanokvm-kvmapp-2.0.42.tar.gz` from the exact transition
   prerelease above and verify its SHA-256.
2. Open **Settings > Update > Offline Update**, upload the complete archive,
   wait for the backend to restart, log in again, and confirm application
   `2.0.42`.
3. At the top of the same page, enable **Preview Updates**. This is one shared
   preview switch: it controls both application-preview metadata and
   system-preview metadata.
4. In the **System Update** section, press **Refresh**. Until it is pressed, the
   screen can continue to show the stable target `0.2.23-raw.1` even though
   preview mode is enabled.
5. Confirm that the offered transition ends at `0.3.0-raw.12` and that the
   latest target is `sg2002-licheervnano-sd`. Do not install an unexpected
   version or target.
6. Enable **Allow raw system updates**. This is separate from Preview Updates:
   Preview selects the channel, while Allow raw system updates authorizes the
   destructive boot/rootfs write.
7. Select **Download and Verify** and wait for the signed archive to finish
   downloading and staging. Do not start installation if verification fails.
8. Install the staged update. Keep power connected and do not reboot or close
   the update flow while it writes `/dev/mmcblk0p2` and `/dev/mmcblk0p1`. The
   device reboots automatically after the raw writes.
9. Allow the first boot and configuration restore to finish. After the web UI
   returns, verify app `2.0.42`, system `0.3.0-raw.12`, Buildroot `2026.05.1`,
   target `sg2002-licheervnano-sd`, and kernel `5.10.265-tag-`.
10. Disable **Allow raw system updates** again unless another explicitly
    planned raw update is being staged.

If the System Update card still offers `0.2.23-raw.1`, first confirm that
**Preview Updates** remains enabled and then press the System Update
**Refresh** button. Updating app to `2.0.42` alone does not promote the system
stable channel and therefore does not make raw.12 appear without preview mode.

### Flash the complete SD image instead

The RC12 `.img.xz` asset already contains app `2.0.42` and system
`0.3.0-raw.12`, so a separately installed app update or Preview Updates toggle
is not required for a clean manual flash. Download the image and
`SHA256SUMS` from the
[`hardened-system-0.3.0-raw.12`](https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.3.0-raw.12)
release, verify the checksum, and write it to a recoverable SD card of at least
16 GiB. Keep the original card unchanged until the new card has booted, obtained
network configuration, and passed the required hardware checks. See
[docs/sd-card-flashing.md](docs/sd-card-flashing.md) for platform-specific
flashing instructions.

Raw partition updates do not provide automatic recovery when the device cannot
boot. RC12 updates both Buildroot userspace and the reviewed SG2002 port of
Linux `5.10.265`; it does not claim that every retained vendor delta is free of
all upstream CVEs.

## Current Highlights

Hardened NanoKVM keeps the upstream hardware stack and web UI shape, but changes
the security, update, and administration model substantially:

- **Rust web backend:** shipped artifacts run the Hardened Rust
  `NanoKVM-Server` with the existing native video and hardware stack.
- **Hardened login and sessions:** first-boot account setup, per-device session
  secret, CSRF binding, Origin checks, login rate limiting/lockout, explicit
  session revocation, Argon2id for new passwords, and compatibility with
  existing bcrypt password files.
- **Optional two-factor auth:** per-account TOTP (RFC 6238) for web login, with
  single-use backup codes for recovery. Because the board has no
  battery-backed RTC, backup codes are deliberately exempt from the
  clock-synchronization check, so recovery still works on a device that booted
  without a network.
- **Safer terminal access:** the web terminal is guarded by the authenticated
  web session instead of being merely hidden by a toolbar toggle.
- **Signed application updates:** GitHub-hosted app updates use signed
  `latest.json` metadata, sha512 archive verification, source URL validation,
  safe extraction, and package validation before installation.
- **Guarded raw system updates:** separate system-update channel metadata,
  staged download/verify, raw SD partition writer, first-boot configuration
  restore, automatic boot-good confirmation, manual rollback hooks, and
  boot-watchdog rollback support.
- **System settings in GUI:** added System Log, remote UDP syslog forwarding,
  local tmpfs log viewing, Time/NTP/timezone controls, and Firewall controls.
- **Mobile view:** narrow phone screens and touch tablets get a mobile-focused
  settings/menu/KVM view with reachable submenus, native mobile keyboard
  controls, the separate on-screen HID keyboard, TouchSync pointer control,
  automatic KVM screen fitting, pinch-to-zoom for the video surface, and
  touch-drag panning of the scaled KVM viewport. Appearance settings can also
  force Mobile view when a browser is not detected correctly. This mobile view
  is a Hardened fork addition and is not present in the original NanoKVM
  project.
- **Managed firewall modes:** Moderate is the default local-only profile:
  baseline services remain reachable, but new inbound connections are accepted
  only from private IPv4, IPv4 link-local/loopback, IPv6 ULA, IPv6 link-local,
  and IPv6 loopback source ranges. Baseline remains available as an open
  compatibility profile. Restricted keeps HTTPS/SSH access local-only while
  preserving needed outbound DNS/NTP/syslog/update traffic; H.264 WebRTC is
  disabled in both Restricted and Paranoid. Paranoid leaves only local-only
  HTTPS and blocks online updates intentionally.
- **HTTPS/firewall recovery:** disabling HTTPS forces firewall mode back to
  Moderate so HTTP access is not stranded behind HTTPS-only rules while still
  keeping public source ranges blocked.
- **Video pipeline stability:** H.264 Direct/WebRTC mode selection is persisted
  across reloads, HTTP/HTTPS toggles now warn and reboot the device instead of
  partially restarting the video stack, and the UI redirects to the new
  protocol after the reboot window.
- **Network hardening and control:** full wired DHCP/manual IP/DNS editing,
  stable `eth0` MAC persistence, explicit IPv6 Disabled/SLAAC/DHCPv6/Manual
  modes, and DHCPv6 client integration where available.
- **Lower video CPU load path:** H.264 Direct is the preferred low-CPU mode when
  HTTPS and WebCodecs are available; MJPEG remains as fallback.
- **Input reliability fixes:** queued HID writes, paste support, shortcut
  handling, HID reset/recovery, mouse jiggler support, mobile TouchSync pointer
  mode, and relative pointer sensitivity controls in the Rust path.
- **Device fixes from testing:** wrong-password errors, resolution changes,
  OLED timers of 5 minutes and higher, browser auth-state recovery after
  protocol/IP changes, and update reboot/restore edge cases were fixed.
- **Hardened branding and observability:** login/toolbar/About branding, login
  screen version from the local `/kvmapp/version`, device uptime, and web login
  audit events in syslog.

## Current Status

This fork is usable for active device testing, but it is not a finished firmware
release. The current development flow is to run the Rust backend on a real
NanoKVM device and harden one subsystem at a time.

| Area                  | Status                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rust backend          | Runs on the device as a replacement `NanoKVM-Server`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Web UI                | Existing React UI is retained with Hardened branding and System settings pages.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| HTTPS                 | Implemented in Rust with HTTP-to-HTTPS redirect and existing cert config support.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Authentication        | First-boot web account setup, Rust sessions, CSRF protection, Origin checks, rate limiting, security headers, Argon2id for new passwords, legacy bcrypt verification. Optional TOTP second factor with single-use backup codes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Video                 | H.264 Direct is the preferred low-CPU mode and is verified on hardware. MJPEG remains available as a fallback. H.264 WebRTC is available in Baseline/Moderate modes, but is disabled by Restricted/Paranoid firewall policy.                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Native video boundary | Rust still calls `libkvm` and the CVI/MMF C/C++ stack. RC10 remediates the 2026-07-11 native audit findings, including lifecycle races, VENC ownership/rollback, bounds and parser bugs, MMF mapping lifetime, signal safety, and retained helper defects. Rebuilt libraries passed MJPEG, H.264 Direct, reboot, and controlled stop/start testing on device 133.                                                                                                                                                                                                                                                                                    |
| HID                   | Keyboard/mouse websocket, queued HID writes, paste, shortcuts, HID mode, reset, and mouse jiggler are implemented.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Device settings       | Hostname, web title, GPIO/ATX, OLED, HDMI, SSH, mDNS, swap, memory limit, TLS toggle, reboot, scripts, and autostart have Rust endpoints.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Storage               | ISO/IMG listing, upload, mount, delete, and CD-ROM/mass-storage mode are implemented with path validation. Mount changes use LUN eject/insert; switching between CD-ROM and mass-storage mode also reconnects the USB gadget so BIOS/boot menus rescan the device type. A confirmed USB reconnect fallback remains available when a host does not notice media changes. Remote ISO download exists behind a disabled-by-default safety toggle and validates URL, filename, size, destination, and ISO format. Completed downloads now reset the picker state and refresh the virtual-media image list without logout.                                                 |
| Network               | WOL, full wired DHCP/manual IP/DNS settings, explicit IPv6 Disabled/SLAAC/DHCPv6/Manual controls, Wi-Fi status/connect/AP verification, and Tailscale lifecycle endpoints are implemented.                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Updates               | Online/offline `kvmapp` updates are implemented through GitHub Releases with signed `latest.json` metadata and sha512 archive verification. Current combined app channel: `2.0.42 RC12`; older installations use the authenticated manual transition prerelease first.                                                                                                                                                                                                                                                                                                                                                                                                       |
| SD image              | Current preview SD image is app `2.0.42` / system `0.3.0-raw.12`, built from Buildroot `2026.05.1` and Linux `5.10.265-tag-`. It passed exact initial boot, partition expansion, authenticated browser/runtime, two reboot cycles, raw.10 recovery, and final RC12 return on recoverable media.                                                                                                                                                                                                                                                         |
| System updates        | Separate GitHub channel metadata, production-signature enforcement, staging download/verify, guarded raw install, first-boot root configuration restore, automatic boot-good confirmation, manual rollback, and boot-watchdog rollback are implemented. Current preview raw channel: `0.3.0-raw.12`, metadata format 2 requires app `2.0.42`, and the full SD image already includes it. Payloads remain gzip-compressed and stream directly to the SD partitions. The userspace is Buildroot `2026.05.1`; the kernel is `5.10.265-tag-`. |

## How Updates Work

Hardened NanoKVM has two separate update paths. They are intentionally split
because the application can usually be replaced safely, while system updates
write raw SD-card partitions and can make the device unbootable if interrupted
or if the wrong image is installed.

### Application Updates

Application updates replace only the Hardened `kvmapp` payload:

- Rust backend binaries: `/kvmapp/server/NanoKVM-Server` and
  `/kvmapp/backends/NanoKVM-Server.rust`.
- Web UI assets under `/kvmapp/server/web`.
- Hardened helper scripts, init scripts, keys, version files, and app-side
  configuration defaults shipped in `kvmapp`.

They do not rewrite the boot partition, rootfs partition, kernel, bootloader, or
base Buildroot system. This is the normal update path for backend fixes, UI
fixes, auth/session changes, H.264/HID/storage/network endpoint changes, and
branding.

The GUI checks GitHub Releases in the `woffko/Hardened_NanoKVM` fork. Stable
application metadata is published as `latest.json` on the latest release, for
example:

```text
https://github.com/woffko/Hardened_NanoKVM/releases/latest/download/latest.json
```

The metadata points to a versioned app archive such as
`hardened-nanokvm-kvmapp-2.0.42.tar.gz` on the combined
`hardened-system-0.3.0-raw.12` release tag.
The device verifies signed metadata and the archive sha512 before
installing. The preview toggle uses the `hardened-rust-preview` channel
metadata, but it still installs the versioned archive named by that metadata.

Offline application updates use the same archive format, but the archive is
uploaded from the browser instead of downloaded from GitHub.

### Raw System Updates

Raw system updates are different. They are full partition-image updates for the
SD card and currently target the NanoKVM SD layout:

- raw rootfs image for `/dev/mmcblk0p2`, currently stored as
  `payload/images/rootfs.sd.gz`;
- raw boot image for `/dev/mmcblk0p1`, currently stored as
  `payload/images/boot.vfat.gz`;
- metadata describing the target board, expected image hashes, base image,
  kernel string, required free space, and source commit.

These updates can change the base Buildroot rootfs, boot files, kernel-side
payloads, bundled `kvmapp`, init scripts installed in rootfs, and system
version metadata. They are intended for system/security work that cannot be
done by replacing `kvmapp` alone.

Because raw updates write SD-card partitions, the GUI keeps them behind an
explicit **Allow raw system updates** switch on the Check for Updates screen.
Enabling it means the device may require SD-card reflash recovery if the update
is interrupted or the image is bad.

System update metadata is published through a stable channel release:

```text
https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-stable/system-latest.json
```

When **Preview Updates** is enabled, the backend also reads the independently
signed system preview channel and chooses the newer valid system version:

```text
https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-preview/system-latest.json
```

The Preview Updates switch is shared with application updates, but it does not
replace the separate **Allow raw system updates** safety switch.

That channel metadata points to a versioned raw-system tag such as
`hardened-system-0.2.23-raw.1`, which contains:

- `hardened-nanokvm-system-<version>.tar.gz`;
- `system-latest.json` and signature files;
- matching SD-card image artifacts for manual flashing or recovery;
- the matching application archive for traceability.

The device downloads the raw archive into `/data/.hardened-kvmcache`, verifies
the signed metadata and payload shape, stages the update, and then runs the
guarded install step. For current raw releases, the rootfs and boot images stay
gzip-compressed while staged and are streamed directly to `/dev/mmcblk0p2` and
`/dev/mmcblk0p1` during install. After raw writes, the updater requests reboot
through kernel sysrq so it does not depend on the overwritten live rootfs.
Preserved root configuration is restored on the first boot from the new rootfs,
before SSH and the web backend start. Once backend health is good, the
boot-watchdog automatically confirms the system update and clears the pending
state.

### Current Published Channels

The channels can intentionally move independently:

- Application stable/latest: `2.0.42 RC12`, combined tag
  `hardened-system-0.3.0-raw.12`.
- Application preview: `hardened-rust-preview`, when populated, points to a
  versioned application archive independently from the stable latest release.
- Raw system stable remains `0.2.23-raw.1`, published on companion tag
  `hardened-system-0.2.23-raw.1` and advertised through the
  `hardened-system-stable` channel metadata. The `hardened-rust-rc9` release
  carries the matching raw bundle and SD-card image.
- Raw system preview: `hardened-system-preview`, points to `0.3.0-raw.12` on
  the combined RC12 release and requires app `2.0.42`.
- Latest preview SD image: app `2.0.42`, matching raw system `0.3.0-raw.12`.

The RC9 `2.0.32` application, raw system update, and SD image were rebuilt
together after the RC8 mobile/tablet follow-up work. RC9 keeps the Hardened
mobile view for phones and touch tablets, native mobile keyboard controls, a
separate on-screen HID keyboard, TouchSync pointer control, automatic screen
fitting, pinch-to-zoom, touch-drag panning, and an Appearance option to force
Mobile view when browser detection is wrong. It also carries the post-RC8
mobile Settings segmented-control fixes. The mobile view is a Hardened fork
addition and is not present in the original NanoKVM project.
The raw rootfs also keeps the RC6 security baseline: no web/API password reset
path, Rust-side `kvm_system` watchdog/network responsibilities, USB
mass-storage image validation for virtual media, startup NTP sync, H.264 WebRTC
HDMI hotplug recovery, opt-in USB HID wake-on-write, compressed raw-update
support, setting-preserving raw install, IPv6 controls, DHCPv6 client, browser
auth-state recovery, deferred first-boot root configuration restore, automatic
post-boot confirm, and sysrq reboot after raw partition writes. The GUI
separates system-update metadata into System update version, Base image,
Buildroot release, and Security backport level to avoid confusing the raw
channel version with the base Buildroot version.

### Which Update Should Be Used?

Use an application update for normal Hardened backend and UI changes. It is the
preferred path for routine testing.

Use a raw system update only when the change must modify the base SD-card
system: boot/rootfs contents, kernel-side payloads, rootfs-installed init
scripts, or a full system security image. Keep a recovery SD-card image
available before testing raw updates.

The channels publish both update paths, but they do not have to advance at the
same time. A test device should normally install the latest app update first,
then install a raw system update only when the raw channel offers a newer system
payload and SD-card recovery is available.

For full SD-card recovery or first-time flashing, use
[docs/sd-card-flashing.md](docs/sd-card-flashing.md). It covers Windows with
Balena Etcher plus Linux, macOS, and FreeBSD command-line workflows.

## What This Fork Adds

- Added `server-rust/`, a Rust backend that preserves the existing API envelope
  and device runtime layout.
- Added hardened auth/session handling: generated per-device secret, CSRF token
  binding, Origin checks, login lockout, explicit session revocation, and safer
  password storage.
- Added optional TOTP (RFC 6238) two-factor authentication for web login,
  enrolled from **Settings > Account** with a QR code and confirmed by a live
  code before it activates, so a misconfigured authenticator cannot lock the
  account out. Enrolling, disabling and reissuing backup codes all require the
  account password. Enrolment issues nine single-use backup codes, displayed
  once. A `security.require_totp` flag, switched from the same page, can
  require a second factor device-wide; it refuses to enable until the account
  has enrolled. If the flag is set some other way, login still succeeds -- so a
  headless device cannot lock itself out -- but the session is confined
  server-side to the enrolment endpoints until a second factor is set up. SSH
  is unaffected and remains password-only. See
  [`docs/rust-backend.md`](docs/rust-backend.md) for the clock, recovery, and
  replay-protection details.
- Added browser auth-state recovery for IP/protocol changes: if the HttpOnly
  session cookie is still valid but the JS-readable CSRF cookie is missing, the
  web UI restores CSRF state through `/api/auth/account` instead of returning
  immediately to the login screen.
- Added a first-boot setup screen for new SD-card flashes. If `/etc/kvm/pwd`
  does not exist, the web UI requires creating the first administrator account
  before normal login is available. Lost credentials are recovered by reflashing
  the SD card.
- Added Rust implementations for the main browser workflows: login, static UI,
  MJPEG, H.264 Direct, H.264 WebRTC signaling, HID, terminal, storage, network,
  Tailscale, scripts, and many VM settings routes.
- Added full wired network editing from the web UI. Manual mode persists IP,
  subnet mask, router, and DNS through the existing `S30eth` boot path and
  keeps a stable `eth0` MAC in `/boot/eth.mac` so DHCP leases survive reboot.
- Added shared video fanout for MJPEG and H.264 Direct, so multiple viewers do
  not multiply native capture reads. The web UI now defaults new sessions to
  H.264 Direct when HTTPS and WebCodecs are available, otherwise to H.264.
- Added safer file and command handling for script upload/run, autostart files,
  ISO upload and remote download, storage image paths, GitHub update archives,
  and privileged shell calls.
- Added guarded remote ISO download by URL, disabled by default and controlled
  from Settings > Appearance. Completed downloads now clear the active
  filename, show completion state, and refresh the virtual-media image list
  without requiring logout.
- Added package validation so application and SD-card artifacts contain only
  the expected Hardened runtime layout.
- Added device uptime to About and a Settings > Device session lock selector
  for 5, 15, 30, and 60 minute sessions.
- Fixed OLED sleep timers of 5 minutes and higher by rebuilding `kvm_system`
  with 32-bit sleep timeout parsing instead of the overflowing 8-bit helper
  value.
- Added signed application update metadata verification for `latest.json`.
- Added persistent Rust backend binary under `/kvmapp/backends/NanoKVM-Server.rust`.
- Made `S95nanokvm` startup idempotent for testing: stale `S95nanokvm.*`
  backup scripts are removed from boot autostart, existing runtime processes
  are stopped before copy/start, stale web backup directories are removed from
  `/kvmapp/server`, and HTTPS port 443 is explicitly allowed.
- Updated branding: login screen, toolbar, and About page identify the Hardened
  build, and the login screen and toolbar use the Hardened NanoKVM wordmark.

## Rust Backend Health

When the Rust backend is active,
`GET /api/health` returns:

```json
{
  "code": 0,
  "msg": "success",
  "data": { "backend": "rust", "phase": "skeleton", "status": "ok" }
}
```

## Still Not Finished

- The native `libkvm`/CVI-MMF audit findings are remediated in RC10/RC11. The
  original findings and completed hardware checks are recorded in
  [docs/native-code-audit.md](docs/native-code-audit.md). Repeated HDMI
  hotplug/resolution stress, physical OLED/button coverage, and a long-running
  dmesg/syslog endurance passed; visible OLED/button and remaining physical
  source/host interactions remain follow-up work.
- Full API parity is not complete. Some routes are implemented for compatibility
  but still need deeper behavior and edge-case testing.
- H.264 WebRTC needs more browser/ICE stress testing across reconnects and
  browser variants in Baseline/Moderate firewall modes. Restricted/Paranoid
  intentionally disable it. H.264 Direct has been verified against the Rust
  backend on hardware.
- Online update checks read Hardened release metadata from
  `github.com/woffko/Hardened_NanoKVM` and install versioned release archives
  after signed metadata and payload hash verification.
- GUI system updates can stage, verify, install, and confirm boot-good. The
  `0.3.0-raw.10` preview carries the Buildroot `2026.05.1` userspace port while
  retaining vendor kernel `5.10.4-tag-`; the future `5.10.265` kernel merge is
  still pending recoverable-media validation.
- Remote ISO download remains disabled by default and needs a final production
  policy before it should be treated as generally safe.
- First-boot/account setup is implemented for Rust/Hardened images. Existing
  test devices can keep their current account file; new default `admin/admin`
  bootstrap is disabled unless explicitly enabled for isolated compatibility
  testing.
- The repository does not yet ship a verified full boot/rootfs image from SDK
  sources. `make vendor-sdk` bootstraps the pinned Sipeed/LicheeRV Nano SDK
  checkout for stock-image work, while the current SD-card image flow patches a
  trusted upstream NanoKVM base image.
- API inventory, recovery docs, rollback docs, and long-run test reports still
  need to be kept in sync with active device testing.

## 🌟 What is NanoKVM?

NanoKVM is a series of compact, open-source IP-KVM devices based on the LicheeRV Nano (RISC-V). It lets you remotely access and control computers as if you were sitting in front of them, making it useful for servers, embedded systems, and other headless machines.

## 📦 Product Family

Choose the NanoKVM model that best fits your deployment:

- **NanoKVM-Cube Lite:** A barebones kit for DIY users and bulk deployments.
- **NanoKVM-Cube Full:** A ready-to-use kit with a case, accessories, and a pre-flashed system SD card.
- **NanoKVM-PCIe:** A PCIe-bracket form factor for internal chassis mounting. It draws power from the PCIe slot and supports optional Wi-Fi and PoE.
- **[NanoKVM-Pro](https://github.com/sipeed/NanoKVM-Pro):** A higher-performance version with major upgrades:
  - **Resolution:** Up to **4K@30fps / 2K@60fps**.
  - **Network:** **1Gbps Ethernet + PoE + Wi-Fi 6**, upgraded from 100Mbps Ethernet.
  - **Latency:** Hardware-accelerated encoding reduces latency from 100-150ms to **50-100ms**.

<div align="center">
  <img src="https://cdn.sipeed.com/public/nanokvm-products-v2.jpg" alt="NanoKVM Product Family" width="100%" style="margin: 20px 0;">
</div>

> If you are looking for a USB-based KVM solution, check out [NanoKVM-USB](https://github.com/sipeed/NanoKVM-USB).

## 🛠️ Technical Specifications

| Feature                       | NanoKVM-Pro                           | NanoKVM (Cube/PCIe)     | GxxKVM              | JxxKVM               |
| ----------------------------- | ------------------------------------- | ----------------------- | ------------------- | -------------------- |
| Core                          | AX630C 2xA53 1.2G                     | SG2002 1xC906 1.0G      | RV1126 4xA7 1.5G    | RV1106 1xA7 1.2G     |
| Memory & Storage              | 1G LPDDR4X + 32G eMMC                 | 256M DDR3 + 32G microSD | 1G DDR3 + 8G eMMC   | 256M DDR3 + 16G eMMC |
| System                        | NanoKVM / PiKVM                       | NanoKVM                 | GxxKVM              | JxxKVM               |
| Resolution                    | 4K@30fps / 2K@60fps                   | 1080P@60fps             | 4K@30fps / 2K@60fps | 1080P@60fps          |
| HDMI Loopout                  | 4K loopout                            | —                       | —                   | —                    |
| Video Encoding                | MJPEG / H.264 / H.265                 | MJPEG / H.264           | MJPEG / H.264       | MJPEG / H.264        |
| Audio Transmit                | ✓                                     | —                       | ✓                   | —                    |
| UEFI / BIOS                   | ✓                                     | ✓                       | ✓                   | ✓                    |
| Emulated USB Keyboard & Mouse | ✓                                     | ✓                       | ✓                   | ✓                    |
| Emulated USB ISO              | ✓                                     | ✓                       | ✓                   | ✓                    |
| IPMI                          | ✓                                     | ✓                       | ✓                   | —                    |
| Wake-on-LAN                   | ✓                                     | ✓                       | ✓                   | ✓                    |
| Web Terminal                  | ✓                                     | ✓                       | ✓                   | ✓                    |
| Serial Terminal               | 2 channels                            | 2 channels              | —                   | 1 channel            |
| Custom Scripts                | ✓                                     | ✓                       | —                   | —                    |
| Storage                       | 32G eMMC 300MB/s                      | 32G MicroSD 12MB/s      | 8G eMMC 120MB/s     | 8G eMMC 60MB/s       |
| Ethernet                      | 1000M                                 | 100M                    | 1000M               | 100M                 |
| PoE                           | Optional                              | Optional                | —                   | —                    |
| Wi-Fi                         | Optional Wi-Fi 6                      | Optional Wi-Fi 6        | —                   | —                    |
| ATX Power Control             | ✓                                     | ✓                       | Extra $15           | Extra $10            |
| Display                       | 1.47" 320x172 LCD / 0.96" 128x64 OLED | 0.96" 128x64 OLED       | —                   | 1.68" 280x240        |
| More Features                 | Sync LED Strip / Smart Assistant      | —                       | —                   | —                    |
| Power Consumption             | 0.6A@5V                               | 0.2A@5V                 | 0.4A@5V             | 0.2A@5V              |
| Power Input                   | USB-C or PoE                          | USB-C                   | USB-C               | USB-C                |
| Dimensions                    | 65x65x26mm                            | 40x36x36mm              | 80x60x17.5mm        | 60x43x(24~31)mm      |

## 📂 Project Structure

```text
├── kvmapp          # APP update package
│   ├── jpg_stream  # Legacy support for direct updates from older versions
│   ├── kvm_new_app # Triggers components for kvm_system updates
│   ├── kvm_system  # Core KVM application
│   ├── server      # Front-end and back-end integration
│   └── system      # Essential system components
├── web             # NanoKVM Front-end (UI)
├── server-rust     # Hardened Rust backend replacement and native runtime assets
├── scripts/nanokvm # Device-side helper scripts used while testing this fork
├── docs            # Public build, update, release, and security notes
├── support         # Auxiliary modules (Image subsystem, status, updates, OLED, HID, etc.)
├── ...
```

## 💻 Development

Start with the guide that matches the part of NanoKVM you want to work on:

- **Documentation index:** Start with [docs/README.md](docs/README.md) for current install, recovery, security, and development guides.
- **System support modules:** Build and update the low-level hardware support components in [support/sg2002/README.md](support/sg2002/README.md).
- **Hardened Rust backend:** Build, package, and test the Rust replacement in [docs/rust-backend.md](docs/rust-backend.md). Native runtime assets are kept in [server-rust/native/](server-rust/native/).
- **System update plan:** Track planned GUI system updates for vendor-kernel security backports in [docs/system-update-plan.md](docs/system-update-plan.md).
- **System update releases:** Package future kernel/rootfs update bundles for GitHub-hosted channels with [docs/system-update-github-releases.md](docs/system-update-github-releases.md).
- **SD-card flashing:** Prepare recovery or first-boot media on Windows, Linux, macOS, and FreeBSD with [docs/sd-card-flashing.md](docs/sd-card-flashing.md).
- **Release channels:** Current visible release/channel policy is documented in [docs/release-archive.md](docs/release-archive.md).
- **RC12 release notes:** Review install order, exact artifacts, validation, and limitations in [docs/releases/rc12-2.0.42-raw.12.md](docs/releases/rc12-2.0.42-raw.12.md).
- **Key transition:** Existing installations use the manual bridge described in [docs/releases/2.0.42-key-transition.md](docs/releases/2.0.42-key-transition.md); engineering details are in [docs/key-transition-2026q3.md](docs/key-transition-2026q3.md).
- **Physical acceptance:** Exact raw.10 bridge, full-SD, recovery-round-trip, and off-host backup evidence is indexed in [docs/rc12-final-physical-gates.md](docs/rc12-final-physical-gates.md).
- **Vendor SDK build path:** Bootstrap and validate the Sipeed/LicheeRV Nano SDK for future full base-system images in [docs/vendor-sdk-build.md](docs/vendor-sdk-build.md).
- **New Buildroot study:** Track feasibility of newer SDK/newer Buildroot sysupgrade images in [docs/new-buildroot-sysupgrade-study.md](docs/new-buildroot-sysupgrade-study.md).
- **Buildroot 2023 security backports:** Evaluate critical userspace backports for the proven vendor SDK baseline in [docs/buildroot-2023-security-backport-plan.md](docs/buildroot-2023-security-backport-plan.md).
- **Security status:** Review hardening scope and remaining risk in [docs/security-risk-inventory.md](docs/security-risk-inventory.md).
- **Native code audit:** Review current C/C++ crash, resource-lifetime, and
  retained-helper findings in
  [docs/native-code-audit.md](docs/native-code-audit.md).
- **Frontend UI:** Develop, lint, and build the React interface in [web/README.md](web/README.md).

> Backend compilation and runtime validation require the target toolchain or a NanoKVM device. See the module-specific guides above for the latest development workflow.

## 🔩 Hardware Platform (NanoKVM Cube/PCIe)

NanoKVM is based on Sipeed [LicheeRV Nano](https://wiki.sipeed.com/hardware/zh/lichee/RV_Nano/1_intro.html). You can find specifications, schematics, and dimensional drawings in the [download station](https://dl.sipeed.com/shareURL/LICHEE/LicheeRV_Nano).

The NanoKVM Cube/PCIe hardware is built from these components:

- **NanoKVM Lite:** LicheeRV Nano plus the HDMI-to-CSI board.
- **NanoKVM Full:** NanoKVM Lite plus the NanoKVM-A/B boards and enclosure.
- **HDMI-to-CSI board:** Converts the HDMI input signal.
- **NanoKVM-A board:** Provides OLED, ATX control output through USB-C, auxiliary power, and physical ATX power/reset buttons.
- **NanoKVM-B board:** Connects NanoKVM-A to the host computer's ATX pins for remote power control.

The NanoKVM image is built with the LicheeRV Nano SDK and MaixCDK. It is intended for NanoKVM hardware and is not a general-purpose KVM software package for other LicheeRV Nano or SG2002 products. If you want to build an HDMI input application on LicheeRV Nano or MaixCam, please contact us for technical support.

> Note: Of the 256MB memory on SG2002, 158MB is currently allocated to the multimedia subsystem for video capture and processing.

- [NanoKVM-A Schematic](https://cn.dl.sipeed.com/fileList/KVM/nanoKVM/HDK/02_Schematic/SCH_RV_Nano_KVM_A_30111.pdf)
- [NanoKVM-B Schematic](https://cn.dl.sipeed.com/fileList/KVM/nanoKVM/HDK/02_Schematic/SCH_RV_Nano_KVM_B_30131.pdf)
- [NanoKVM-PCIe Schematic](https://cn.dl.sipeed.com/fileList/KVM/KVM_PCIE/HDK/01_Schematic/SCH_nanoKVM_PCIE_3105D_2025-12-19.pdf)
- [NanoKVM image](https://github.com/sipeed/NanoKVM/releases/tag/NanoKVM)

<div align="center">
  <img src="https://wiki.sipeed.com/hardware/zh/kvm/assets/NanoKVM/1_intro/NanoKVM_2.jpg" alt="NanoKVM PCB Pinout" width="80%" style="margin: 20px 0;">
</div>

## 🤝 Contributing

We welcome contributions. To get started:

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Push to the branch.
5. Open a Pull Request.

Please keep your pull requests small and focused to facilitate easier review and merging.

> 🎁 **Contributors who submit high-quality Pull Requests may receive a NanoKVM Cube, PCIe, or Pro as a token of our appreciation!**

## 🛒 Where to Buy

- [AliExpress (global, except USA and Russia)](https://www.aliexpress.com/item/1005007369816019.html)
- [Taobao](https://item.taobao.com/item.htm?id=811206560480)
- [Preorder for other regions](https://sipeed.com/nanokvm)

## 💬 Community & Support

- [Discord](https://discord.gg/V4sAZ9XWpN)
- QQ group: 703230713
- Email: [support@sipeed.com](mailto:support@sipeed.com)
- [FAQ](https://wiki.sipeed.com/hardware/en/kvm/NanoKVM/faq.html)

## 📜 License

This project is licensed under the GPL-3.0 License. See [LICENSE](LICENSE) for details.
