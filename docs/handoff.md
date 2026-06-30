# Hardened NanoKVM Handoff

Last updated: 2026-06-30

## Repository State

- Local repo: `/home/w0w/Hardened_NanoKVM-new-buildroot`
- GitHub repo: `woffko/Hardened_NanoKVM`
- Active branch: `feature/new-buildroot-sysupgrade-lab`
- Current uncommitted work: IPv6 GUI/API/init support for app `2.0.9` plus
  matching raw/SD rebuild artifacts.
- Recent commits when this handoff was updated:
  - `81d252f Record beta 2.0.8 publication`
  - `ef1e770 Document beta 2.0.8 OLED helper fix`
  - `10392e8 Fix OLED sleep timeout overflow`
  - `c496b67 Clarify Rust-only security documentation`
  - `24cfb02 Refresh README release status and handoff`

Detailed chronological build/update notes are in
[`docs/current-sysupgrade-build-trace.md`](current-sysupgrade-build-trace.md).

## Latest Releases

### App Release

- Current app release: `2.0.9`
- GitHub tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.9`
- Artifact:
  `build/artifacts/hardened-nanokvm-kvmapp-2.0.9.tar.gz`
- SHA256:
  `d64c3ba4f36a56e80bee7c254261e201bda17ee70a3a864abdfd001612382fb5`
- Includes explicit IPv6 controls, bundled DHCPv6 client, the `2.0.8` OLED
  helper fix, and the `2.0.7` login-loop fix.
- Local `latest.json` metadata signature verified with the bundled test public
  key.

### Raw System Release

- Current raw system channel: `0.2.5-raw.1`
- GitHub tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.2.5-raw.1`
- Stable channel tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`
- Artifact:
  `build/system-updates/hardened-nanokvm-system-0.2.5-raw.1.tar.gz`
- SHA256:
  `1eb1e6a52cbde814d3b30629f3b63c6866d6acb2c6efcae3073ce7906f082dfb`
- Built from the beta `2.0.9` SD rootfs, with raw rootfs SHA
  `66df01ceb0d97a7d8cc8e7b16049b2d07009b6ea38b03349dcfe1e42f98fbf02` after
  `/etc/kvm/system-version.json` is patched into the payload.
- Local `system-latest.json` metadata signature verified with the bundled test
  public key.

### SD Image

- Latest SD image built: beta `2.0.9`
- File name:
  `Hardened_NanoKVM_beta_2_0_9_buildroot_2023_11_2_security_ipv6_Rev1_4_2_rust.img.xz`
- SHA256:
  `4534e7bef92077926ec12efd528166c05efea58f8822df77c0b40c735c08f1ce`

## Device State

### `10.0.87.132`

- Web: `admin/admin1234`
- SSH was previously expected as `root/admin1234`, but host key changed during
  testing; use a temporary known-hosts file or clear the entry before SSH.
- Directly repaired with local offline app update package `2.0.7`.
- Last verified:
  - `/api/health`: OK
  - `/api/vm/info`: `application=2.0.7`
  - `/api/application/version`: `current=2.0.7`, `latest=2.0.7`
  - `/api/auth/account` returns `username`, `csrfToken`, and `expiresAt`
- User confirmed GUI works after this fix.

Root cause of login loop:

- backend session was valid;
- frontend only checked JS-readable `nano-kvm-csrf`;
- after IP/protocol/browser-state changes, CSRF cookie could be missing while
  HttpOnly session cookie was still valid;
- fixed by recovering CSRF from `GET /api/auth/account`.

### `10.0.87.133`

- Web password used during latest diagnostics: `admin/admin1234`
- App was last observed as `2.0.5` before `2.0.7` publication.
- DNS was corrected from bad manual value `10.0.77.133` to local router/DNS
  `10.0.87.5`.
- Last verified network state:
  - mode: `manual`
  - address: `10.0.87.133/24`
  - gateway: `10.0.87.5`
  - DNS/effective/DHCP: `10.0.87.5`
- After app `2.0.9` is published, it should see `2.0.9`; verify before
  installing anything.

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

1. Publish/push the `2.0.9` app release, `0.2.5-raw.1` system release, and
   channel metadata once GitHub connectivity is available.
2. After the user restores/reboots `10.0.87.132`, install the fixed app and
   validate IPv6 Disabled, SLAAC, DHCPv6, and Manual modes on hardware.
3. Confirm devices see app `2.0.9` and raw `0.2.5-raw.1` through GUI update
   checks.
4. Keep updating `docs/current-sysupgrade-build-trace.md` with publication
   verification and device checks.
