# Changelog

From RC11 on, each release has its own notes file under `docs/releases/`; the
entries below summarise them.

## Hardened NanoKVM 2.1.7 RC16 + System 0.4.0-raw.6 (2026-11-12)

Replaces RC15. Full notes: [docs/releases/rc16-2.1.7-raw.6.md](docs/releases/rc16-2.1.7-raw.6.md).

- Video works again on a device with an HDMI source: the size of a captured
  frame is computed without rounding its bytes-per-pixel factor.
- Installing the application locks the SSH service accounts within seconds,
  without a reboot.
- SSH is started again after an application update on a device that serves the
  web interface without TLS.

## Hardened NanoKVM 2.1.5 RC15 + System 0.4.0-raw.4 (2026-11-11)

Superseded by RC16 and not to be installed. Full notes: [docs/releases/rc15-2.1.5-raw.4.md](docs/releases/rc15-2.1.5-raw.4.md).

- Fixes the SSH authentication bypass CVE-2026-123158: OpenSSH 10.6p2, locked
  service accounts, and `sshd` barriers for accounts without a password hash.
- Only the production update key is trusted; the stable system channel carries
  the current release.
- `/tmp` and `/dev/shm` are mounted `nosuid,nodev,noexec`; script uploads need a
  fresh terminal unlock; the login limiter counts failures per source address.
- Known defects, corrected in RC16: the backend ends on the first video frame
  on a device with an HDMI source, and an application-only update does not lock
  the service accounts until the next boot.

## Hardened NanoKVM 2.1.0 RC13 + System 0.4.0-raw.1 (2026-11-01)

Full notes: [docs/releases/rc13-2.1.0-raw.1.md](docs/releases/rc13-2.1.0-raw.1.md).

- Fixes what a full security audit of RC12 found and moves the kernel to Linux
  5.10.272.
- Affected by CVE-2026-123158 while SSH is enabled; update to RC16.

## Hardened NanoKVM 2.0.42 RC12 + System 0.3.0-raw.12 (2026-08-28)

Full notes: [docs/releases/rc12-2.0.42-raw.12.md](docs/releases/rc12-2.0.42-raw.12.md) and
[docs/releases/2.0.42-key-transition.md](docs/releases/2.0.42-key-transition.md).

- Production update key and the manual trust bridge for existing installations.
- Buildroot 2026.05.1 and the reviewed SG2002 port of Linux 5.10.265.

## Hardened NanoKVM 2.0.33 RC9.1 (2026-07-11)

Application-only update for the RC9 raw/system baseline. Raw system-update
`0.2.23-raw.1` and the RC9 SD-card image are unchanged.

### Changed

- Extends automatic KVM screen fitting to desktop, tablet, and normal browser
  windows at 100% scale while preserving scroll/pan behavior at higher manual
  scales.
- Aligns the Appearance `Interface layout` and `Display Mode` segmented
  controls with matching desktop widths and full-width mobile behavior.

### Verified

- The RC9.1 changes were installed as a pre-release app payload on NanoKVM Cube
  devices `10.0.87.133` and `10.0.87.132` through the authenticated offline
  update API.
- Playwright checks passed desktop `1200x800` and phone `393x873` layouts on
  both devices with fitted KVM dimensions, aligned controls, and no page
  errors.

## Hardened NanoKVM 2.0.32 RC9 (2026-07-10)

Full application, raw system-update, and SD-card release candidate with app
`2.0.32`, raw system-update `0.2.23-raw.1`, and matching SD-card image.

### Changed

- Carries the RC8 mobile/tablet baseline forward into a full raw/SD build from
  current `main`.
- Fixes mobile/tablet Settings segmented controls in Appearance so `Auto`,
  `Mobile view`, `Auto hide`, and `Always visible` labels wrap cleanly and stay
  vertically centered.
- Keeps Hardened mobile view as a fork addition not present in the original
  NanoKVM project: native mobile keyboard control, separate on-screen HID
  keyboard, TouchSync pointer control, automatic KVM screen fitting,
  pinch-to-zoom, and touch-drag panning.

### Verified

- The post-RC8 Settings mobile/tablet fix was installed and checked on NanoKVM
  Cube devices `10.0.87.133` and `10.0.87.132`.
- Release validation for RC9 covers Rust backend tests, frontend production
  build, linked RISC-V build, app/rootfs package validation, raw/rootfs
  validation, metadata signature verification, checksums, and SD image xz
  integrity.

## Hardened NanoKVM 2.0.31 RC8 (2026-07-05)

Full application, raw system-update, and SD-card release candidate with app
`2.0.31`, raw system-update `0.2.22-raw.1`, and matching SD-card image.

### Changed

- Extends the Hardened mobile view from narrow phones to touch tablets and adds
  an explicit Appearance setting to force Mobile view on browsers that are not
  detected correctly by viewport size alone.
- Keeps TouchSync as the default mobile pointer mode: the whole KVM surface,
  including letterbox/pillarbox space, can be used as a touchpad while a local
  cursor overlay shows the controlled pointer position.
- Keeps the separate local-device keyboard button for Android/mobile soft
  keyboards and the separate on-screen HID keyboard menu item.
- Carries the RC7/RC7.1 mobile KVM improvements into a full raw/SD baseline:
  automatic fit scaling, pinch-to-zoom for the video surface, touch-drag
  panning of scaled video, mobile settings/menu containment, virtual-media
  visibility fixes, and CD-ROM/mass-storage mount safety fixes.
- Keeps the RC6/RC7 security baseline: no in-place password reset path,
  local-use firewall defaults, signed app/system metadata, raw-system update
  guardrails, startup NTP sync, mass-storage image validation, WebRTC
  restrictions in Restricted/Paranoid firewall modes, and opt-in USB HID
  wake-on-write.

### Verified

- The post-RC7 mobile/tablet UI builds were installed and smoke-tested on a
  NanoKVM Cube test device before the RC8 release build.
- Release validation for RC8 covers Rust backend tests, frontend production
  build, linked RISC-V build, app/rootfs package validation, raw/rootfs
  validation, metadata signature verification, checksums, and SD image xz
  integrity.

## Hardened NanoKVM 2.0.29 RC7 (2026-07-04)

Full application, raw system-update, and SD-card release candidate with app
`2.0.29`, raw system-update `0.2.21-raw.1`, and matching SD-card image.

### Changed

- Added a mobile-first web UI view for narrow phone screens. This is a
  Hardened fork addition and is not present in the original NanoKVM project.
- Reworked mobile settings navigation, System subtabs, menu submenus, and
  toolbar/menu containment so controls remain reachable on Android-class
  browser widths.
- Fixed the virtual keyboard menu crash by hardening the
  `react-simple-keyboard` import path and added a compact mobile keyboard
  panel for phone use.
- Added mobile KVM screen fitting improvements: automatic fit scaling, lower
  manual scale steps down to 10%, and safer MJPEG/WebRTC/H.264 layout bounds.
- Kept the RC6 security baseline: no in-place password reset path, local-use
  firewall defaults, signed app/system metadata, raw-system update guardrails,
  startup NTP sync, mass-storage image validation, and opt-in USB HID
  wake-on-write.

### Verified

- Rust backend tests, frontend build, linked RISC-V build, release package
  validation, raw/rootfs validation, and metadata verification passed locally.
- The mobile UI fixes and RC7 app payload were installed and smoke-tested on a
  NanoKVM Cube test device.

## Hardened NanoKVM 2.0.28 RC6 (2026-07-03)

Full application, raw system-update, and SD-card release candidate with app
`2.0.28`, raw system-update `0.2.20-raw.1`, and matching SD-card image.

### Changed

- Removed the web/API password reset path. Lost credentials now require
  reflashing the SD card instead of resetting root/web access in place.
- Continued the minimal-risk `kvm_system` migration by moving watchdog,
  Ethernet state, network shadow state, and web Wi-Fi reconnect handling into
  Rust while keeping low-level hardware/OLED helper code native.
- Added mass-storage image validation for virtual-media uploads while keeping
  ISO-only validation for CD-ROM mode.
- Synced configured NTP time during service startup so syslog and local logs use
  corrected time before the GUI is opened.
- Improved H.264 WebRTC hotplug recovery by reacting to browser keyframe
  requests and asking the capture path for a fresh keyframe.
- Made USB HID wake-on-write opt-in through the Device settings toggle and
  `/boot/usb.wakeup`; default images now suppress the repeated USB wakeup log
  spam.

### Verified

- Rust backend tests, frontend build, linked RISC-V build, release package
  validation, raw/rootfs validation, and metadata verification passed locally.
- The WebRTC HDMI hotplug and USB wakeup changes were installed and
  smoke-tested on NanoKVM hardware before the release build.

## Hardened NanoKVM 2.0.27 RC5 (2026-07-03)

Full application, raw system-update, and SD-card release candidate with app
`2.0.27`, raw system-update `0.2.19-raw.1`, and matching SD-card image.

### Changed

- Moved NanoKVM native runtime libraries and the `kvm_vision.h` ABI header into
  `server-rust/native/`; release packages still install the libraries under
  `/kvmapp/server/dl_lib` for runtime compatibility.
- Removed unused builder and packaging paths from the repository.
- Strengthened package/rootfs validation for stale backend artifacts.
- Simplified System settings confirmation flows:
  - Network now has one Apply action for IPv4, DNS, and IPv6 changes.
  - Network, Time, and System Log keep their save action in the fixed System
    header when there are pending changes.
  - Firewall mode cards now ask for confirmation directly and apply the
    selected mode without a separate Apply button.
  - The System section header remains fixed while long sections scroll.
- Published matching raw system-update and SD-card artifacts for
  `0.2.19-raw.1`.

### Verified

- Rust backend tests, frontend build, linked RISC-V build, release package
  validation, raw/rootfs validation, and metadata verification passed locally.
- The app package and final System settings UI were installed and smoke-tested
  on NanoKVM hardware.

## Hardened NanoKVM 2.0.26 RC4 (2026-07-02)

Current full raw/SD baseline with app `2.0.26`, raw system-update
`0.2.18-raw.1`, and matching SD-card image.

### Changed

- Added Moderate as the default managed firewall mode.
- Moderate, Restricted, and Paranoid firewall modes now accept new inbound
  connections only from local-use ranges:
  - IPv4 private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`;
  - IPv4 link-local and loopback: `169.254.0.0/16`, `127.0.0.0/8`;
  - IPv6 ULA, link-local, and loopback: `fc00::/7`, `fe80::/10`, `::1/128`.
- Refined the Firewall mode selection UI.
- Fixed ISO upload/download completion state and refreshed the virtual-media
  image list after downloads complete.
- Kept the raw/SD line on the Buildroot `2023.11.3 package backports`
  security-backport baseline.

## Hardened NanoKVM 2.0.25 RC3 (2026-07-01)

Previous full app/raw/SD release candidate.

### Changed

- Kept the tested video path while preserving selected video mode and
  Appearance display mode across updates.
- Fixed the login-screen firmware version display.
- Refined the System > Network IPv4/DNS layout.
- Published matching raw system-update and SD-card artifacts for
  `0.2.17-raw.1`.

## Hardened NanoKVM 2.0.21 RC2 (2026-07-01)

Application release candidate focused on System settings organization.

### Changed

- Moved Network settings under Settings > System.
- Updated Restricted firewall and WebRTC DNS text.
- Verified app-only update behavior on hardware.

## Hardened NanoKVM 2.0.20 RC1 (2026-07-01)

Application release candidate that introduced the System settings area.

### Added

- System Log with local tmpfs log viewing and optional UDP remote syslog.
- Time, timezone, and NTP controls.
- Managed Firewall controls with Baseline, Moderate, Restricted, and Paranoid
  modes.
- HTTPS/firewall recovery behavior for TLS changes.

## Notes

The current release channels and supported installation paths are documented in
`README.md`, `docs/rust-backend.md`, and
`docs/system-update-github-releases.md`.
