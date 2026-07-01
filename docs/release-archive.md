# Release Archive

This file preserves release history even when obsolete GitHub release entries
are removed from the public Releases page.

Policy:

- keep channel releases because GUI update checks depend on them;
- keep the latest usable app release and matching raw/SD release visible;
- remove old alpha/internal/broken release entries from the GitHub Releases UI
  after their notes are captured here;
- do not delete git tags unless explicitly doing a separate repository-history
  cleanup.

## Visible Releases

| Tag | Status | Notes |
| --- | --- | --- |
| `hardened-rust-rc3` | Current full RC | App `2.0.25` with matching raw system `0.2.17-raw.1` and SD-card image. Keeps the tested video path, persists the selected video mode and Appearance display mode, fixes the login firmware version, refines the System > Network IPv4/DNS layout, and keeps the Buildroot `2023.11.3 package backports` baseline on the raw/SD line. |
| `hardened-rust-2.0.24` | Previous app release | App `2.0.24` keeps the tested `2.0.21` video path, moves Network settings under System, and handles HTTP/HTTPS protocol changes through a warned device reboot plus delayed redirect. |
| `hardened-rust-rc2` | Previous app RC | App `2.0.21` with Network settings moved under `Settings > System > Network`, Restricted firewall/WebRTC DNS text updates, and tested app-only release behavior. |
| `hardened-rust-rc1` | Previous app RC | App `2.0.20` with System Log, Time/NTP/timezone controls, managed Firewall controls, Restricted/Paranoid modes, HTTPS/firewall recovery, and TLS toggles that keep `kvm_system` running. |
| `hardened-rust-beta-2.0.19` | Previous app beta / previous raw baseline app | Raw-update sysrq reboot fix, root-level preserve restore fix, deferred first-boot root restore, and automatic post-boot confirm. |
| `hardened-system-0.2.15-raw.1` | Previous raw/SD beta | Matching raw full-rootfs update and SD image with app `2.0.19`, base image `2026-06-29-12-08-d88d58.img`, Buildroot `2023.11.2`, security patch level `Buildroot 2023.11.3 package backports`. Live-validated on `10.0.87.132`. |
| `hardened-system-stable` | Channel | Stable raw-system metadata channel. Keep this release. |
| `hardened-rust-preview` | Channel | Preview app metadata channel. Keep this release while preview update support exists. |
| `hardened-system-preview` | Channel | Preview raw-system metadata channel. Keep this release while preview update support exists. |
| `hardened-rust-beta-1.0.5` | Historical milestone | First Rust-only security beta that removed the legacy Go backend from shipped artifacts. Can remain visible as a milestone. |

## Internal Or Obsolete App Releases

These releases were useful during bring-up, but are superseded by
`hardened-rust-rc3`. They can be removed from the GitHub Releases UI
without losing the changelog history.

| Tag | Archive status | Notes |
| --- | --- | --- |
| `hardened-rust-alpha-20260606` | Internal alpha | Early Rust backend archive. |
| `hardened-rust-alpha-adminadmin-20260606` | Internal alpha | Temporary default-credential test archive. |
| `hardened-rust-alpha-0.1-20260626` through `hardened-rust-alpha-0.1.9` | Internal alpha series | Early hardware/UI bring-up. Superseded by beta security releases. |
| `hardened-rust-beta-1.0`, `1.0.1`, `1.0.2` | Obsolete beta 1 candidates | Superseded by `1.0.5`. |
| `hardened-rust-sysupgrade-1.0.3`, `1.0.4`, `1.0.5` | Internal sysupgrade app builds | Lab channel while raw update plumbing was being separated from app latest metadata. |
| `hardened-rust-beta-2` | Obsolete beta 2 candidate | First beta 2 line release; superseded by point releases. |
| `hardened-rust-beta-2.0.1` | Obsolete | Preview fallback and stable USB gadget MAC work. |
| `hardened-rust-beta-2.0.2` | Obsolete | App-side init script sync for existing devices. |
| `hardened-rust-beta-2.0.3` | Obsolete | System-update stale-progress UI fix. |
| `hardened-rust-beta-2.0.4` | Obsolete | Legacy failed-progress cleanup. |
| `hardened-rust-beta-2.0.5` | Obsolete | Manual IPv4/DNS editing and stable Ethernet MAC support. |
| `hardened-rust-beta-2.0.6` | Obsolete | Manual IP redirect and HTML no-store cache fix. |
| `hardened-rust-beta-2.0.7` | Obsolete | Browser auth-state recovery after IP/protocol changes. |
| `hardened-rust-beta-2.0.8` | Obsolete | OLED timeout helper fix. |
| `hardened-rust-beta-2.0.9` | Broken beta | IPv6/DHCPv6 app build; matching raw rootfs missed required stock init scripts. Superseded by `2.0.10`. |
| `hardened-rust-beta-2.0.10` | Obsolete | Init script repair release. |
| `hardened-rust-beta-2.0.11` | Obsolete | Raw updater setting-preservation release. |
| `hardened-rust-beta-2.0.12` | Obsolete | Compressed raw staging release. |
| `hardened-rust-beta-2.0.13` | Internal lab | Intermediate app-only raw-staging hardening snapshot. |
| `hardened-rust-beta-2.0.14` | Broken/lab | Data staging guard release; later found to still lack idempotent p3 first-boot protection. Superseded by `2.0.15`. |
| `hardened-rust-beta-2.0.15` | Obsolete | Coherent app/raw/SD build with idempotent data-partition init and GUI system metadata label cleanup. Superseded by later raw-update reliability fixes. |
| `hardened-rust-beta-2.0.16` | Obsolete | Raw-updater runtime isolation and `/data` raw preserve state. Superseded by `2.0.19`. |
| `hardened-rust-beta-2.0.17` | Obsolete | Large raw staging fix for exFAT-backed `/data`. Superseded by `2.0.19`. |
| `hardened-rust-beta-2.0.18` | Obsolete | Deferred first-boot root restore and auto-confirm. Superseded by `2.0.19` because reboot after raw writes still depended on the overwritten live rootfs. |
| `hardened-rust-2.0.22` | Broken/lab | Experimental video-stream drain before protocol toggles. Superseded because H.264 backend switching could restart into safe-mode behavior. |
| `hardened-rust-2.0.23` | Broken/lab | Follow-up desktop/backend stream drain synchronization. Superseded because H.264 mode switching was still unstable on hardware. |

## Internal Or Obsolete System Releases

These raw-system releases are lab artifacts. Old raw releases should not be
installed unless a test explicitly needs to reproduce a historical failure.

| Tag | Archive status | Notes |
| --- | --- | --- |
| `hardened-system-0.1.0-dev.1` | Internal smoke test | Non-destructive first system-update flow validation. |
| `hardened-system-0.1.0-raw.1` | Revoked/broken | Built from stock SDK rootfs without Hardened `kvmapp`; must not be installed. |
| `hardened-system-0.1.1-raw.1` through `hardened-system-0.1.5-raw.1` | Internal raw bring-up | Superseded by beta 2 raw releases. |
| `hardened-system-0.2.0-raw.1` through `hardened-system-0.2.4-raw.1` | Obsolete raw beta | Early beta 2 raw images before the init-script and staging fixes. |
| `hardened-system-0.2.5-raw.1` | Broken raw beta | Missing required stock init scripts in rootfs; superseded by `0.2.6-raw.1`. |
| `hardened-system-0.2.6-raw.1` | Obsolete | Init script repair raw image. |
| `hardened-system-0.2.7-raw.1` | Obsolete | Setting-preserving raw image, but uncompressed staging could exhaust rootfs-backed `/data`. |
| `hardened-system-0.2.8-raw.1` | Obsolete | Compressed staging release. |
| `hardened-system-0.2.9-raw.1` | Internal lab | Superseded by later data-staging guard work. |
| `hardened-system-0.2.10-raw.1` | Broken/lab | Could trigger unsafe p3 first-boot formatting path after raw rootfs update. Superseded by `0.2.11-raw.1`. |
| `hardened-system-0.2.11-raw.1` | Obsolete | Coherent raw/SD build after idempotent data-partition fix; live test showed raw writer could crash before reboot due to dynamic runtime dependency. |
| `hardened-system-0.2.12-raw.1` | Obsolete | Runtime-isolated raw writer build; live staging could still fail during large `/data` archive sync. |
| `hardened-system-0.2.13-raw.1` | Obsolete | Large staging fix; live install wrote rootfs/boot and rebooted, but root config restore before reboot failed with `Resource busy`. |
| `hardened-system-0.2.14-raw.1` | Obsolete | Deferred first-boot root restore and auto-confirm; live test succeeded but found root-level `/device_key` restore issue and unreliable post-write reboot path. |

## Cleanup Checklist

Cleanup was executed on 2026-06-30 and historical git tags were left intact.
Later 2.0.17-2.0.19 / 0.2.13-0.2.15 validation releases were published after
that cleanup, so the GitHub Releases page may temporarily contain obsolete
entries listed above until the next cleanup pass.

When repeating GitHub Releases cleanup:

1. Verify `hardened-rust-rc3` is the GitHub latest release and its
   `latest.json` signature verifies.
2. Verify `hardened-system-stable/system-latest.json` points to
   `0.2.17-raw.1` and its signature verifies.
3. Delete only obsolete release entries/assets from the GitHub Releases UI.
4. Keep channel releases, the current app release, and the current raw/SD
   baseline release.
5. Leave git tags intact unless a separate tag-cleanup task is explicitly
   requested.
