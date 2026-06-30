# Hardened NanoKVM Handoff

Last updated: 2026-06-29

## Repository State

- Local repo: `/home/w0w/Hardened_NanoKVM-new-buildroot`
- GitHub repo: `woffko/Hardened_NanoKVM`
- Active branch: `feature/new-buildroot-sysupgrade-lab`
- Recent commits when this handoff was created:
  - `10392e8 Fix OLED sleep timeout overflow`
  - `c496b67 Clarify Rust-only security documentation`
  - `24cfb02 Refresh README release status and handoff`
  - `b3ec117 Recover web auth state from active session`
  - `66a8dae Document application and raw system updates`
  - `219af6d Record beta 2.0.6 release artifacts`

Detailed chronological build/update notes are in
[`docs/current-sysupgrade-build-trace.md`](current-sysupgrade-build-trace.md).

## Latest Releases

### App Release

- Current app release: `2.0.8`
- GitHub tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.8`
- Published as app-only hotfix.
- Fixes OLED sleep timers of 5 minutes and higher by shipping a rebuilt
  `kvm_system` helper with 32-bit timeout parsing.
- Includes the `2.0.7` login-loop fix after IP/protocol changes or stale
  browser auth state.
- GitHub `latest.json` should be downloaded after publication and signature
  verified.

### Raw System Release

- Current raw system channel remains: `0.2.4-raw.1`
- GitHub tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.2.4-raw.1`
- Stable channel tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`
- This raw release was built together with app `2.0.6`, not `2.0.8`.
- No raw/SD rebuild has been made yet for `2.0.8`.

### SD Image

- Latest SD image built: beta `2.0.6`
- File name:
  `Hardened_NanoKVM_beta_2_0_6_buildroot_2023_11_2_security_Rev1_4_2_rust.img.xz`
- SHA256:
  `338df3e1477984892986f3e7ae5ce491bf0cb2001d827863bd5212fd8e8f3752`

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
- After app `2.0.8` is published, it should see `2.0.8`; verify before
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

1. Publish app `2.0.8` and verify devices see it through GUI update checks.
2. Decide whether to build a matching raw system/SD release for app `2.0.8`.
3. If raw/SD is rebuilt, bump raw system version from `0.2.4-raw.1` to the next
   value and update `hardened-system-stable`.
4. Continue testing Manual network changes across HTTP/HTTPS and browser cache
   states.
5. Keep updating `docs/current-sysupgrade-build-trace.md` with release hashes
   and device checks.
