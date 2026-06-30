# Hardened NanoKVM Handoff

Last updated: 2026-06-30

## Repository State

- Local repo: `/home/w0w/Hardened_NanoKVM-new-buildroot`
- GitHub repo: `woffko/Hardened_NanoKVM`
- Active branch: `feature/new-buildroot-sysupgrade-lab`
- Current work: replacement init-fix release `2.0.10` / `0.2.6-raw.1`
  published after `2.0.9` / `0.2.5-raw.1` raw images were found broken.
- Recent commits when this handoff was updated:
  - `2a9d02d Fix raw image init script installation`
  - `8f18209 Record beta 2.0.9 publication`
  - `47aac13 Record beta 2.0.9 IPv6 artifacts`
  - `59bc8dd Add explicit IPv6 network controls`
  - `81d252f Record beta 2.0.8 publication`

Detailed chronological build/update notes are in
[`docs/current-sysupgrade-build-trace.md`](current-sysupgrade-build-trace.md).

## Latest Releases

### App Release

- Current app release: `2.0.10`
- GitHub tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.10`
- Artifact:
  `build/artifacts/hardened-nanokvm-kvmapp-2.0.10.tar.gz`
- SHA256:
  `302e60f80f09ca0c29e876532d9fd0c69731733a05a253e2fb5ec2677f3be35e`
- Includes the raw/SD init-script fix, explicit IPv6 controls, bundled DHCPv6
  client, the `2.0.8` OLED helper fix, and the `2.0.7` login-loop fix.
- Local `latest.json` metadata signature verified with the bundled test public
  key.
- Published on GitHub and verified through `releases/latest/download/latest.json`.

### Raw System Release

- Current raw system channel: `0.2.6-raw.1`
- GitHub tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.2.6-raw.1`
- Stable channel tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`
- Artifact:
  `build/system-updates/hardened-nanokvm-system-0.2.6-raw.1.tar.gz`
- SHA256:
  `fb1e2dea3ca1c044da7ad74210c3f119a5ca847a05d8ece50ec3bb6fb9f78bac`
- Built from the beta `2.0.10` SD rootfs. Raw payload manifest source commit:
  `2a9d02d`.
- Local `system-latest.json` metadata signature verified with the bundled test
  public key.
- Published on GitHub and verified through `hardened-system-stable` and
  `hardened-system-preview` metadata.

### SD Image

- Latest SD image built: beta `2.0.10`
- File name:
  `Hardened_NanoKVM_beta_2_0_10_buildroot_2023_11_2_security_initfix_Rev1_4_2_rust.img.xz`
- SHA256:
  `9f396d235cbe40c006e07c9938d7903c15b32f2fcea04f0eefe6c720558267b7`

## Device State

### `10.0.87.132`

- Web: `admin/admin1234`
- Static IPv4 was set through `/boot/eth.nodhcp`:
  `10.0.87.132/24 10.0.87.5`; DNS is `10.0.87.5`.
- Previously appeared as DHCP `10.0.87.55`.
- Last verified after app update:
  - `/api/health`: OK
  - `/api/application/version`: `current=2.0.10`, `latest=2.0.10`
  - `/api/system-update/check`: `current=0.2.5-raw.1`,
    `latest=0.2.6-raw.1`, `updateAvailable=true`
  - raw install has not been started yet.

Root cause of login loop:

- backend session was valid;
- frontend only checked JS-readable `nano-kvm-csrf`;
- after IP/protocol/browser-state changes, CSRF cookie could be missing while
  HttpOnly session cookie was still valid;
- fixed by recovering CSRF from `GET /api/auth/account`.

### `10.0.87.133`

- Web: `admin/admin1234`
- Static IPv4 was set through `/boot/eth.nodhcp`:
  `10.0.87.133/24 10.0.87.5`; DNS is `10.0.87.5`.
- Previously appeared as DHCP `10.0.87.42`.
- First account setup was required and was completed as `admin/admin1234`.
- Last verified after app update:
  - `/api/health`: OK
  - `/api/application/version`: `current=2.0.10`, `latest=2.0.10`
  - `/api/system-update/check`: `current=0.2.5-raw.1`,
    `latest=0.2.6-raw.1`, `updateAvailable=true`
  - raw install has not been started yet.

## Important Implementation Notes

- App updates replace `/kvmapp` only.
- Raw system updates write SD-card boot/rootfs partitions and are lab-only.
- Do not delete GitHub channel releases:
  - `hardened-rust-preview`
  - `hardened-system-preview`
  - `hardened-system-stable`
- GUI update checks depend on those channel tags/assets.
- README now has a dedicated `How Updates Work` section describing app updates
  versus raw system updates.
- Security and backend docs should describe the Go backend as historical
  upstream/reference context only. Current release artifacts are Rust-only and
  validators reject legacy Go backend files and backend-switch scripts.

## Latest Fixes In Code

### Current Live Issue: `2.0.9` / `0.2.5-raw.1`

- Published app `2.0.9` and raw system `0.2.5-raw.1` should be treated as
  broken until superseded.
- Observed after raw update:
  - devices still boot and get SSH;
  - web UI does not answer because `NanoKVM-Server` starts before the vendor
    CVI hardware modules are loaded;
  - `/tmp/nanokvm-server.log` shows missing `/dev/cvi-sys`, `/dev/cvi-base`,
    and `/proc/cvitek/vb`;
  - `/etc/init.d` in the raw image only contained the Hardened overrides
    `S03usbdev`, `S30eth`, and `S95nanokvm`.
- Root cause:
  - raw/SD build only installed three init scripts into `/etc/init.d`;
  - original stock rootfs has required hardware boot scripts such as
    `S00kmod`, `S01fs`, and `S15kvmhwd`;
  - without those scripts, Sophgo/CVI modules and hardware detection do not run.
- Upstream/stock comparison:
  - `/kvmapp/system/init.d` contains `S03usbhid`;
  - stock `/etc/init.d` does not include `S03usbhid`;
  - therefore `S03usbhid` must remain available as an alternate HID-only mode
    script but must not be auto-installed into `/etc/init.d`.
- Device notes:
  - `10.0.87.48`: reachable by SSH as `root/root`; manual
    `/kvmapp/system/init.d/S00kmod start` plus `/etc/init.d/S95nanokvm restart`
    restored HTTP for the current boot.
  - `10.0.87.60`: reachable by SSH as `root/root` and shows the same missing
    init script symptom; still needs the same temporary boot-script repair.
- Required fix:
  - define a stock-compatible boot-safe init script list;
  - install `S00kmod`, `S01fs`, `S03usbdev`, `S15kvmhwd`, `S30eth`,
    `S30wifi`, `S50avahi-daemon`, `S50sshd`, `S80dnsmasq`, and
    `S95nanokvm`;
  - leave base-rootfs services such as `S50ssdpd` to the base image unless a
    later change deliberately replaces them;
  - keep optional Hardened scripts `S96picoclaw` and `S98tailscaled` available
    only if they are intentionally installed as services;
  - do not auto-install `S03usbhid`;
  - update SD/raw builder, runtime self-healing sync, and rootfs validator;
  - publish a replacement app/raw/SD release and mark `2.0.9` as broken or
    prerelease on GitHub rather than leaving it as a normal latest release.

### `2.0.9`

- Adds explicit IPv6 controls under Settings > Network:
  - Disabled;
  - SLAAC;
  - DHCPv6;
  - Manual IPv6 address/prefix/router.
- IPv6 defaults to Disabled when `/boot/eth.ipv6.mode` is missing.
- `S30eth` applies IPv6 separately from IPv4 and uses `ip -4 addr flush` so
  IPv6 settings do not erase IPv4 state and vice versa.
- A bundled BusyBox `udhcpc6` client was added at
  `/kvmapp/system/bin/udhcpc6`.
- DHCPv6 uses `/kvmapp/system/network/udhcpc6.script`, a Hardened hook that
  only manages IPv6/DNS and does not call the stock `udhcpc` script that resets
  `eth0` to `0.0.0.0`.
- Backend route: `GET/POST /api/network/ipv6`.
- GUI shows an Apply button for `needs-apply`, e.g. when desired mode is
  Disabled but IPv6 is still active after an app update.
- Local checks passed:
  - `sh -n kvmapp/system/init.d/S30eth`
  - `sh -n kvmapp/system/init.d/S95nanokvm`
  - `sh -n kvmapp/system/network/udhcpc6.script`
  - `cargo fmt --manifest-path server-rust/Cargo.toml`
  - `cargo check --manifest-path server-rust/Cargo.toml`
  - `corepack pnpm --dir web exec tsc --noEmit`
- Device `10.0.87.132` was tested before the DHCPv6 hook fix. The stock
  DHCPv6 script reset IPv4 and made the device unreachable by HTTP/SSH. After
  the local fix, repeat device validation only after the user restores/reboots
  the device.

### `2.0.8`

- Root cause: `kvm_system` parsed `/etc/kvm/oled_sleep` into `uint8_t`, so UI
  values of 300 seconds and higher overflowed before the sleep comparison.
- Source fix is in `support/sg2002/kvm_system/main/lib/oled_ui/oled_ui.cpp`
  and `support/sg2002/kvm_system/main/include/config.h`: OLED sleep is now
  parsed into a 32-bit value, the input buffer is terminated, and values above
  one day fall back to the default.
- Local MaixCDK build now produces
  `support/sg2002/kvm_system/dist/kvm_system_release/kvm_system`.
- Package `build/artifacts/hardened-nanokvm-kvmapp-2.0.8.tar.gz` was built
  with `KVM_SYSTEM_SOURCE` pointing at that rebuilt helper.

### `2.0.7`

- `server-rust/src/api/account.rs`
  - `GET /api/auth/account` returns `csrfToken` and `expiresAt`.
- `web/src/components/auth.tsx`
  - `ProtectedRoute` tries `/api/auth/account` before redirecting to login
    when CSRF cookie is missing.
- `web/src/lib/cookie.ts`
  - CSRF cookie is set/removed with explicit path `/` and `SameSite=Lax`.

### `2.0.6`

- HTML shell responses now include `Cache-Control: no-store, max-age=0`.
- Manual network Apply schedules redirect before waiting for the POST to finish.

### `2.0.5`

- Full Manual wired IP/subnet/router/DNS editing.
- Static network state persisted in `/boot/eth.nodhcp`.
- Stable wired `eth0` MAC persisted in `/boot/eth.mac`.

## Suggested Next Steps

1. After the user restores/reboots `10.0.87.132`, install the fixed app and
   validate IPv6 Disabled, SLAAC, DHCPv6, and Manual modes on hardware.
2. Confirm devices see app `2.0.9` and raw `0.2.5-raw.1` through GUI update
   checks.
3. Keep updating `docs/current-sysupgrade-build-trace.md` with device checks.
