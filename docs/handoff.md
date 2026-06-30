# Hardened NanoKVM Handoff

Last updated: 2026-06-30

## Repository State

- Local repo: `/home/w0w/Hardened_NanoKVM-new-buildroot`
- GitHub repo: `woffko/Hardened_NanoKVM`
- Active branch: `feature/new-buildroot-sysupgrade-lab`
- Current work: app `2.0.16` raw-updater fix after live `0.2.11-raw.1`
  testing on `10.0.87.132` showed the raw writer did not reboot by itself.
  The device booted after manual power-cycle and `0.2.11-raw.1` was confirmed
  healthy, but the writer log showed it stopped during ROOTFS streaming before
  boot partition write/reboot.
- Recent commits when this handoff was updated:
  - `d9614b6 Clarify system update metadata display`
  - `c2ee893 Make raw data partition handling idempotent`
  - `7891449 Harden raw system update staging`
  - `28161aa Support compressed raw system payloads`

Detailed chronological build/update notes are in
[`docs/current-sysupgrade-build-trace.md`](current-sysupgrade-build-trace.md).

## Latest Releases

### App Release

- Current published app release: `2.0.15`
- Current source version: `2.0.15`
- GitHub tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.15`
- Artifact:
  `build/artifacts/hardened-nanokvm-kvmapp-2.0.15.tar.gz`
- SHA256:
  `860a860424393a0e4e7ac6f3e855fde6ad55b686df50d6e4e5faf090300a8bf1`
- Includes compressed raw payload support, raw updater setting preservation,
  raw staging-on-rootfs refusal, `/data` p3 mounting, explicit IPv6 controls,
  bundled DHCPv6 client, the `2.0.8` OLED helper fix, and the `2.0.7`
  login-loop fix. `2.0.15` adds the follow-up idempotent p3 init guard,
  `/etc/kvm.disk0` raw preservation, and GUI system metadata label cleanup.
- Local `latest.json` metadata signature verified with the bundled test public
  key.
- Published on GitHub and verified through `releases/latest/download/latest.json`.

### Raw System Release

- Current raw system channel: `0.2.11-raw.1`
- GitHub tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.2.11-raw.1`
- Stable channel tag:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`
- Artifact:
  `build/system-updates/hardened-nanokvm-system-0.2.11-raw.1.tar.gz`
- SHA256:
  `f2033beb9453f1afc08552cc9ec5d311c5ca8945754890ea0116b2c0a61c25e8`
- Built from the beta `2.0.15` SD rootfs. Raw payload manifest source commit:
  `d9614b6`.
- Base image: `2026-06-29-12-08-d88d58.img`.
- Kernel string: `5.10.4-tag-`.
- Buildroot release shown by the rootfs: `2023.11.2`.
- Security backport level: `Buildroot 2023.11.3 package backports`.
- Raw payloads are staged as `images/rootfs.sd.gz` and `images/boot.vfat.gz`;
  manifest `required_free_bytes` is `671088640` bytes instead of the old 2 GiB
  lab value.
- Local `system-latest.json` metadata signature verified with the bundled test
  public key.
- Published on GitHub and verified through `hardened-system-stable` and
  `hardened-system-preview` metadata.

### SD Image

- Latest SD image built: beta `2.0.15`
- File name:
  `Hardened_NanoKVM_beta_2_0_15_buildroot_2023_11_2_security_backports_datafix_Rev1_4_2_rust.img.xz`
- SHA256:
  `39c3fde0af70eb8ed9400c2da6257f0b2952c6929c6c8e45d932ac699afb614b`

### Release Cleanup

- Preserve release history in `docs/release-archive.md`.
- Keep GitHub channel releases:
  - `hardened-rust-preview`
  - `hardened-system-preview`
  - `hardened-system-stable`
- Keep current visible releases:
  - `hardened-rust-beta-2.0.15`
  - `hardened-system-0.2.11-raw.1`
- Keep `hardened-rust-beta-1.0.5` as the first Rust-only security beta
  milestone unless the user later asks for stricter cleanup.
- Delete only obsolete GitHub release entries/assets, not git tags.

### Current Raw Reboot Fix

- Live device: `10.0.87.132`.
- User installed raw `0.2.11-raw.1` from the GUI.
- During install, ICMP stayed alive for a while but HTTP/HTTPS/SSH were closed
  because the raw writer had already stopped runtime services.
- No automatic reboot happened. The user power-cycled the device manually.
- After manual power-cycle, the device booted and the user confirmed the update
  in the GUI.
- Verified on device after power-cycle:
  - `/kvmapp/version`: `2.0.15`;
  - `/etc/kvm/system-version.json`: `0.2.11-raw.1`;
  - `/data` mounted from `/dev/mmcblk0p3`;
  - `/etc/kvm/system-update-boot-good.json` confirms healthy boot.
- `/data/hardened-system-raw-update.log` root cause:
  - writer stopped services;
  - preserved config;
  - remounted rootfs read-only;
  - started `streaming compressed ROOTFS to /dev/mmcblk0p2`;
  - then emitted repeated `Segmentation fault`;
  - it never logged `ROOTFS image write finished`,
    `raw system image update finished; rebooting`, or boot image write.
- Confirmed secondary symptom: `/dev/mmcblk0p1` SHA256 did not match the
  manifest boot image hash, so boot was not rewritten.
- Likely root cause: the writer copied BusyBox to `/tmp`, but BusyBox is
  dynamically linked and still used musl loader/libc from the rootfs being
  overwritten. After `/dev/mmcblk0p2` changed, later tool invocations crashed.
- Additional issue: preserve state was under `/tmp` and copying large optional
  files such as `/usr/sbin/tailscaled` could hit tmpfs space limits.
- Fix in progress for app `2.0.16`:
  - copy BusyBox, musl loader, and libc into
    `/tmp/hardened-system-raw-update`;
  - launch the writer through the copied loader with
    `--library-path /tmp/hardened-system-raw-update`;
  - keep preserved boot/rootfs config under the staging directory on `/data`,
    not under `/tmp`.

## Device State

### `10.0.87.132`

- Web: `admin/admin1234`
- Static IPv4 was set through `/boot/eth.nodhcp`:
  `10.0.87.132/24 10.0.87.5`; DNS is `10.0.87.5`.
- Previously appeared as DHCP `10.0.87.55`.
- Last verified before compressed raw update test:
  - `/api/health`: OK
  - `/api/application/version`: `current=2.0.11`, latest app channel now
    `2.0.12`
  - `/api/system-update/check`: `current=0.2.5-raw.1`,
    latest raw channel now `0.2.8-raw.1`, `updateAvailable=true`
  - first raw download of `0.2.7-raw.1` failed before install because the
    uncompressed staged rootfs exhausted rootfs space; only
    `/data/.hardened-kvmcache/system-update` was removed afterward.
  - raw install has not been started yet for `0.2.8-raw.1`.

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
- Last verified before compressed raw update test:
  - `/api/health`: OK
  - `/api/application/version`: `current=2.0.11`, latest app channel now
    `2.0.12`
  - `/api/system-update/check`: `current=0.2.5-raw.1`,
    latest raw channel now `0.2.8-raw.1`, `updateAvailable=true`
  - raw install has not been started yet.

## Important Implementation Notes

- App updates replace `/kvmapp` only.
- Raw system updates write SD-card boot/rootfs partitions and are lab-only.
- Raw system updates must be launched only from app `2.0.12` or newer for
  compressed raw payloads. Older `2.0.11` app updaters preserve settings but do
  not understand `images/rootfs.sd.gz`.
- Raw system updates must be launched only from app `2.0.11` or newer. Older
  app updaters write the raw boot/rootfs images without restoring user
  settings.
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

### `2.0.12`

- Raw system manifests now support gzip-compressed raw partition payloads:
  `images/rootfs.sd.gz` and `images/boot.vfat.gz`.
- Raw updater validates compressed payloads with `gzip -t` and streams
  `gzip -dc` directly to `/dev/mmcblk0p2` and `/dev/mmcblk0p1`.
- Raw bundle builder emits uncompressed image size/hash plus compressed
  stored size/hash fields.
- This fixes the observed `No space left on device` staging failure on
  `10.0.87.132` where `/data` was not mounted separately and rootfs had only
  about 698 MiB free after cleaning the failed staging cache.
- Local validation:
  - `sh -n scripts/create-raw-system-update-bundle.sh`
  - `cargo fmt`
  - `cargo test` in `server-rust` passed: 116 lib tests and 2 main tests.

### `2.0.11`

- Raw updater now preserves user configuration before raw partition writes and
  restores it onto the new boot/rootfs before reboot.
- Preserved boot files include static IPv4/DNS, IPv6 mode/config, stable MAC,
  hostname prefix/name, USB gadget flags, Wi-Fi seed files, SSH one-shot flag,
  and custom logo.
- Preserved rootfs state includes `/etc/kvm` user settings, web account,
  session secret, TLS certificate/key, terminal/session config, root/web
  password files, SSH host keys, hostname/machine-id, `device_key`,
  Tailscale/PicoClaw state, and installed optional Tailscale/PicoClaw runtime
  binaries/init scripts.
- The updater deliberately does not restore old sysupgrade state files such as
  `system-version.json`, `system-update-pending.json`, rollback markers, or the
  system-update public key. The new rootfs must keep its own version/key files
  so the device reports the new system version after reboot.
- Regression test added:
  `raw_image_updater_preserves_user_configuration`.
- Local validation:
  - `cargo fmt`
  - `cargo test` in `server-rust` passed: 116 tests.

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

1. Clean obsolete/internal/broken GitHub release entries after confirming this
   archive is pushed.
2. Test app `2.0.15` and raw `0.2.11-raw.1` on one device before moving more
   devices to the raw channel.
3. Do not retry raw install from `0.2.10-raw.1`; it lacks the idempotent
   `/data` init guard and `/etc/kvm.disk0` preservation.
4. Validate IPv6 Disabled, SLAAC, DHCPv6, and Manual modes on hardware after a
   device is on a known-good image.

## 2026-06-30: 2.0.14 / 0.2.10 Raw Update Lab State

Current branch:

- `feature/new-buildroot-sysupgrade-lab`
- latest pushed commit: `7891449 Harden raw system update staging`

Implemented and pushed:

- app `2.0.14`;
- raw system update `0.2.10-raw.1`;
- SD image
  `Hardened_NanoKVM_beta_2_0_14_buildroot_2023_11_2_security_datafix_Rev1_4_2_rust.img.xz`.

Important fix details:

- Raw install now refuses to start if the staged payload directory is on the
  root filesystem. On these devices `/data` must be mounted from
  `/dev/mmcblk0p3`; staging on `/dev/mmcblk0p2` is unsafe because rootfs would
  be read while it is being overwritten.
- `S01fs` now mounts `/dev/mmcblk0p3` on `/data` with explicit `exfat` and
  retries. First-time `mkfs.exfat` is no longer launched in the background.
- Raw writer status now marks a stopped raw writer as failed instead of leaving
  an indefinite stale reboot-required state.
- Raw writer stops more runtime services before the rootfs read-only remount
  attempt and reboots cleanly on pre-write failure after services were stopped.

Build note:

- Do not run `make rust-kvmapp` without `RUST_TARGET`; it builds an x86-64 host
  binary and causes `Exec format error` on NanoKVM.
- In this checkout, `server-rust/sysroot/lib` is missing. The working RISC-V
  build command used for `2.0.14` was:

```sh
NANOKVM_SYSROOT_LIB=/home/w0w/Hardened_NanoKVM/server-rust/sysroot/lib \
  server-rust/scripts/build-linked-libkvm.sh
RUST_TARGET=riscv64gc-unknown-linux-musl \
  APP_VERSION=2.0.14 \
  scripts/package-rust-kvmapp.sh
```

Published artifacts:

- App release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.14`
- Raw system release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.2.10-raw.1`
- System stable channel now reports `0.2.10-raw.1`.
- `.132` device confirmed it could query GitHub and see latest
  `0.2.10-raw.1`.

Device `10.0.87.132` before raw install:

- app manually restored to correct RISC-V `2.0.14`;
- `/data` mounted from `/dev/mmcblk0p3`;
- rootfs free space about 698 MiB;
- `/data` free space about 20.7 GiB;
- system status clean: no staged, pending, or progress before downloading
  `0.2.10`.

Raw update attempt on `10.0.87.132`:

- download/stage of `0.2.10-raw.1` succeeded;
- staged cache was about 541 MiB on `/data` p3;
- install endpoint returned HTTP 200 with pending `raw-1782829729`;
- device then dropped SSH/HTTP, later responded to ICMP at `10.0.87.132`, but
  ports 22 and 80 remained refused for several minutes.

Current blocker:

- `10.0.87.132` appears to boot far enough for network/ICMP, but SSH and web do
  not start after raw `0.2.10` install.
- No SSH access is currently available, so next diagnosis likely needs physical
  SD-card inspection or another device/serial path.
- Most likely areas to inspect on the written card:
  - `/etc/init.d/S01fs`, `/etc/init.d/S50sshd`, `/etc/init.d/S95nanokvm`;
  - `/etc/kvm` preserved state, especially SSH stop flags and raw pending files;
  - `/data` p3 contents and whether it mounts during boot;
  - `/tmp` logs are unavailable after reboot, so inspect persistent files only.

Follow-up source fix:

- commit `c2ee893 Make raw data partition handling idempotent`;
- app version bumped to `2.0.15`;
- `S01fs` now creates/formats p3 only when `/dev/mmcblk0p3` is actually absent;
- if `/dev/mmcblk0p3` already exists, `S01fs` only restores
  `/etc/kvm.disk0` and mounts `/data`;
- raw updater now preserves/restores `/etc/kvm.disk0`;
- validation:
  - `sh -n kvmapp/system/init.d/S01fs`: passed;
  - `cargo fmt --manifest-path server-rust/Cargo.toml`: passed;
  - `cargo test --manifest-path server-rust/Cargo.toml`: passed, 116 lib tests
    plus 2 main tests.

Device recovery after the `0.2.10-raw.1` attempt:

- `10.0.87.132` reappeared through DHCP as `10.0.87.44`.
- The device was first-setup only; web login returned
  `password setup required`, so the account was recreated as
  `admin/admin1234`.
- Scripts API diagnostics showed:
  - app `2.0.14`;
  - system `0.2.10-raw.1`;
  - hostname `kvm-48ad`;
  - `/boot/eth.nodhcp` empty;
  - `/data` mounted from p3, but `/tmp/data-mount.log` showed p3 had been
    formatted during boot;
  - SSH was disabled, but `/etc/init.d/S50sshd permanent_on` from a script
    started it successfully.
- App `2.0.15` was manually copied to `/kvmapp`; `S01fs`, `S30eth`, and
  `S95nanokvm` were copied to `/etc/init.d`.
- Static network was restored:
  - `/boot/eth.nodhcp`: `10.0.87.132/24 10.0.87.5`;
  - DNS mode manual with server `10.0.87.5`.
- Final verified state:
  - HTTP `/api/health`: OK, Rust backend;
  - web login `admin/admin1234`: OK;
  - `/api/application/version`: current `2.0.15`, latest `2.0.14`
    at the time of manual repair, before `2.0.15` was published;
  - `/api/system-update/status`: current `0.2.10-raw.1`, no staged/pending
    update;
  - `/api/vm/ssh`: enabled;
  - `/api/network/dns`: `10.0.87.132/24`, gateway/DNS `10.0.87.5`.
- Second device search was paused by request until after this recovery.

Second device recovery:

- `10.0.87.133` later reappeared on the network with ICMP, SSH 22, and HTTP
  80 available; HTTPS 443 was closed.
- `/api/health` returned the Rust backend status.
- Web login `admin/admin1234` worked.
- Initial state:
  - app `2.0.13`;
  - system `0.2.5-raw.1`;
  - static network already set to `10.0.87.133/24`, gateway/DNS
    `10.0.87.5`;
  - SSH enabled;
  - raw system updates disabled.
- Local `build/artifacts/hardened-nanokvm-kvmapp-2.0.15.tar.gz` was copied to
  `/tmp` and installed manually.
- BusyBox `tar` on this image does not support `-z`, and `tar -a` reported
  invalid tar magic for the gzip archive; use:
  `gzip -dc archive.tar.gz | tar -xf - -C DEST`.
- `/kvmapp` was replaced with `2.0.15`; fixed `S01fs`, `S30eth`, and
  `S95nanokvm` were copied to `/etc/init.d`.
- Static network was restored/confirmed:
  - `/boot/eth.nodhcp`: `10.0.87.133/24 10.0.87.5`;
  - DNS mode manual with server `10.0.87.5`.
- Device was rebooted once; it dropped off the network briefly and returned on
  `10.0.87.133`.
- Final verified state:
  - HTTP `/api/health`: OK, Rust backend;
  - web login `admin/admin1234`: OK;
  - `/api/application/version`: current `2.0.15`, latest `2.0.14`
    at the time of manual repair, before `2.0.15` was published;
  - `/api/system-update/status`: current `0.2.5-raw.1`, boot health healthy;
  - `/api/vm/ssh`: enabled;
  - `/api/network/dns`: static `10.0.87.133/24`, gateway/DNS `10.0.87.5`;
  - `/data` mounted from `/dev/mmcblk0p3`;
  - installed `S01fs` is idempotent and does not create/format p3 when
    `/dev/mmcblk0p3` already exists.
