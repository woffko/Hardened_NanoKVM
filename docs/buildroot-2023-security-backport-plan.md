# Buildroot 2023.11.2 Security Backport Plan

This document evaluates the practical path for keeping the proven NanoKVM
vendor SDK baseline, Buildroot 2023.11.2 plus `linux_5.10`, and applying
critical security updates without moving to a completely new Buildroot board
port.

Date checked: 2026-06-29.

## Feasibility

This is feasible for userspace packages and is the preferred near-term route.
It is much lower risk than a new Buildroot port because it keeps the existing
Sipeed/Sophgo SDK, board config, rootfs layout, multimedia stack, and NanoKVM
device-tree assumptions.

It is not feasible to honestly promise "all critical patches" as one automatic
operation. The practical target is:

- all critical/high fixes for packages that are enabled in the NanoKVM Buildroot
  config;
- all critical/high fixes for network-facing packages and archive/XML/media
  parsers;
- remove unused runtime packages where removal is safer than updating;
- track kernel 5.10 critical fixes separately because vendor HDMI/MMF/kernel
  patches make a full stable-kernel rebase high risk.

## Upstream Support State

Official Buildroot currently lists supported release lines newer than 2023.11.
The old 2023.11 line has a final `2023.11.3` tag, but there is no active
`2023.11.x` branch head in the upstream repository. The current long-term
Buildroot line checked during this study is `2025.02.x`.

Kernel 5.10 is still a longterm kernel line, but the NanoKVM vendor tree is far
behind current 5.10.y. The device reports a `5.10.4`-derived kernel while
kernel.org currently publishes `5.10.259` as the current 5.10 longterm release.

## Current Enabled Package Surface

The local vendor SDK Buildroot `.config` enables these relevant packages:

| Area | Enabled packages / versions in local SDK |
| --- | --- |
| TLS / SSH / HTTP client | OpenSSL `3.1.4`, OpenSSH `9.6p1`, libcurl `8.5.0`, ca-certificates `20230311` |
| Core shell / init | BusyBox `1.36.1` |
| Media / parsers | FFmpeg `4.4.4`, libxml2 `2.11.6`, expat `2.6.0`, sqlite `3.43.1` |
| Archives / compression | libarchive `3.7.2`, xz `5.4.4`, zstd `1.5.5`, brotli `1.1.0`, bzip2 `1.0.8`, p7zip `17.04`, unzip `6.0`, zip `3.0`, unrar `6.2.10` |
| Python stack | Python `3.11.6`, Flask, Django, Jinja2, Werkzeug, Requests, urllib3, SQLAlchemy, WTForms, and many support modules |
| System services | DBus `1.14.10`, dbus-glib `0.112`, eudev `3.2.14`, ipmitool `1.8.19` |

Dropbear is present as a Buildroot package but is not enabled in the local
NanoKVM config; OpenSSH server/client/key utilities are enabled.

## Version Comparison

| Package | Local 2023.11.2 | Upstream 2023.11.3 | Buildroot 2025.02.15 |
| --- | --- | --- | --- |
| OpenSSL | `3.1.4` | `3.1.5` | `3.5.6` |
| ca-certificates | `20230311` | `20230311` | `20260223` |
| OpenSSH | `9.6p1` | `9.6p1` | `9.9p2` plus CVE patches |
| libcurl | `8.5.0` | `8.6.0` | `8.20.0` |
| BusyBox | `1.36.1` | `1.36.1` | `1.37.0` plus CVE patches |
| FFmpeg | `4.4.4` | `4.4.4` | `6.1.5` |
| Python | `3.11.6` | `3.11.8` | `3.12.13` plus CVE patches |
| expat | `2.6.0` | `2.6.2` | `2.8.1` |
| libxml2 | `2.11.6` | `2.11.7` | `2.15.3` |
| libarchive | `3.7.2` | `3.7.2` | `3.8.7` |
| xz | `5.4.4` | `5.4.4` | `5.6.4` plus CVE patch |
| sqlite | `3.43.1` | `3.43.1` | `3.50.4` plus CVE patch |
| p7zip | `17.04` | `17.04` | `17.06` |
| unzip | `6.0` | `6.0` | `6.0` plus Debian/CVE patches |
| zip | `3.0` | `3.0` | `3.0` plus CVE patch |
| zstd | `1.5.5` | `1.5.5` | `1.5.7` |
| DBus | `1.14.10` | `1.14.10` | `1.14.10` plus init-script fixes |

## Recommended Backport Tracks

### Track 1: Low-Risk 2023.11.3 Delta

Backport the official 2023.11.2 to 2023.11.3 package/security delta into the
Sipeed vendor tree first:

- OpenSSL `3.1.5`;
- libcurl `8.6.0`;
- Python `3.11.8`;
- expat `2.6.2`;
- libxml2 `2.11.7`;
- related package hash and patch updates.

This is the safest first proof because it stays within the same Buildroot
release series. It should be built and boot-tested before larger updates.

The helper script for this first track is:

```sh
BUILDROOT_UPSTREAM_REPO=/tmp/buildroot-security-probe \
LICHEERV_NANO_SDK_DIR=/path/to/LicheeRV-Nano-Build \
  scripts/apply-buildroot-2023-11-3-security-backports.sh
```

It applies only these official Buildroot package directories from
`2023.11.2..2023.11.3`: `libopenssl`, `libcurl`, `python3`, `expat`, and
`libxml2`.

### Track 2: Network-Facing Critical Stack

After Track 1 boots:

- OpenSSH `9.9p2` and the Buildroot 2025.02.15 CVE patch set;
- libcurl `8.20.0`;
- OpenSSL current Buildroot LTS version, or latest compatible 3.x version after
  testing against OpenSSH, libcurl, Python SSL, and the Rust backend TLS path;
- ca-certificates `20260223`.

This is high priority because SSH and HTTPS/update download are externally
reachable device features.

### Track 3: Parser And Archive Stack

Update or patch:

- expat `2.8.1`;
- libxml2 `2.15.3`;
- libarchive `3.8.7`;
- xz `5.6.4` plus CVE patches;
- sqlite `3.50.4` plus CVE patches;
- p7zip `17.06`;
- unzip Debian/CVE patch set;
- zip CVE patch;
- zstd `1.5.7`.

These affect update/upload/archive/XML/media-adjacent paths. They are less
likely than SSH to be remotely reachable without authentication, but they are
still important because the GUI supports uploaded update packages and device
features can parse user-provided files.

### Track 4: BusyBox And Init-Sensitive Tools

BusyBox should be handled carefully because init scripts, networking helpers,
mount, shell behavior, and recovery scripts all depend on it.

Preferred order:

1. Apply specific CVE patches to BusyBox `1.36.1` if they apply cleanly.
2. If patching is messy, test BusyBox `1.37.0` from Buildroot 2025.02.15.
3. Run the full boot/reboot/system-update/rollback matrix before shipping.

### Track 5: Python Stack Reduction Or Update

The current Rust-only NanoKVM path should not need the old Python web stack at
runtime. The safer security move may be removal instead of updating:

1. Inventory live runtime use of `/usr/bin/python*` and installed Python
   modules on a booted device.
2. If unused, disable Python3, Flask, Django, Requests, urllib3, Jinja2,
   Werkzeug, SQLAlchemy, and related modules from the rootfs.
3. If Python is still needed by vendor tools, update Python and the enabled
   Python modules from the supported Buildroot branch.

Removal reduces both image size and security maintenance burden.

### Track 6: FFmpeg

FFmpeg `4.4.4` to `6.1.5` is a large jump. Before updating, verify whether the
Hardened runtime uses FFmpeg at all. The current video path is vendor MMF/VENC
and Rust backend code, not FFmpeg.

Preferred order:

1. If unused at runtime, disable FFmpeg and related CLI tools from the rootfs.
2. If needed, bump to the Buildroot 2025.02.15 package and run video/H.264 soak.

## Kernel Track

The kernel should not be mixed into the first userspace security bundle.

Recommended kernel path:

1. Record the exact vendor kernel commit and all local/Sipeed patches.
2. Diff the vendor tree against official Linux 5.10.4 to identify the vendor
   patch stack.
3. Attempt a lab-only rebase/cherry-pick onto current 5.10.y.
4. If that is too large, triage only critical/high CVE fixes that touch enabled
   subsystems: network stack, USB gadget, filesystems, tty/pty, input/HID, and
   memory-management bugs with local privilege escalation impact.
5. Ship kernel updates only after HDMI capture, H.264, USB HID, RNDIS/ACM,
   storage gadget, reboot, and rollback media are validated.

## Build And Release Process

Each security bundle should have a manifest recording:

- package name;
- old version;
- new version or patch commit;
- upstream source commit/tag;
- CVEs addressed where known;
- whether the package is network-facing, parser-facing, or local-only;
- Buildroot patch/hash files changed;
- runtime validation result.

Suggested build order:

1. Create a vendor SDK patch queue under this branch, not inside `build/vendor`
   without tracking.
2. Apply Track 1 only.
3. Build stock rootfs/image with `make vendor-sdk-stock`.
4. Inject Hardened app and build a raw update bundle from the known-good image.
5. Test on sacrificial SD media.
6. Add Track 2, rebuild, retest.
7. Add Tracks 3-6 one package family at a time.
8. Publish only after boot, SSH, HTTPS/HTTP, update, rollback, video, H.264,
   keyboard, mouse, paste, terminal, hostname change, and five reboot cycles
   pass.

## Assessment

The old proven Buildroot 2023.11.2 path is viable and should be the next
security work item. It will not give a fully current distribution, but it can
substantially reduce risk while preserving the known-good NanoKVM hardware
stack. The first useful release should be userspace-only. Kernel security work
should follow as a separate lab track because it has a much higher chance of
breaking HDMI capture or USB gadget behavior.
