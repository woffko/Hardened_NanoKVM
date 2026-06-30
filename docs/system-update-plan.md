# GUI System Update Plan

This plan covers future base-system updates for Hardened NanoKVM. It is separate
from the current `kvmapp` application updater.

## Goal

Keep the SG2002/Sipeed vendor kernel and multimedia stack, but ship Hardened
system bundles with selected kernel and base-system security backports through
the web UI.

Do not move to a mainline Linux kernel until vendor video, H.264, CSI, MMF,
reserved-memory, and `libkvm.so` compatibility is understood and tested.

## Current State

- Application updates are implemented as `kvmapp` tarballs published through
  `woffko/Hardened_NanoKVM` GitHub Releases.
- Application update metadata is served as signed `latest.json` plus
  `latest.json.sig`, and the downloaded archive is verified with sha512 before
  installation.
- System updates will use a separate GitHub release channel metadata file,
  `system-latest.json`, attached to fixed channel tags such as
  `hardened-system-stable`. They must not use GitHub `/releases/latest` while
  application updates still depend on that endpoint.
- SD-card images are currently produced by patching a trusted upstream NanoKVM
  Rev1.4.2 base image with the current Hardened `kvmapp`.
- The Sipeed/LicheeRV Nano vendor SDK source and `host-tools` refs have been
  selected and can be bootstrapped with `make vendor-sdk`. The pinned checkout,
  `defconfig sg2002_licheervnano_sd`, and a full stock SD image build through
  `make vendor-sdk-stock` have been verified locally. Hardware boot validation
  for that stock image is still pending.
- A separate branch, `feature/new-buildroot-sysupgrade-lab`, records the
  newer-SDK/newer-Buildroot feasibility study. Sipeed `main`/`20260407` remain
  Buildroot 2023.11.2 with `linux_5.10`; `newsdk` is an experimental
  patch/submodule workflow and is not yet proven NanoKVM/LT6911-ready; official
  newer Buildroot would be a board-port project rather than a drop-in SDK
  update.
- Because the new Buildroot path is not yet proven, the preferred security
  direction is a curated backport fork of the proven Buildroot 2023.11.2 vendor
  SDK. Userspace package backports are viable; kernel 5.10 critical fixes remain
  a separate lab track because of vendor HDMI/MMF and USB gadget dependencies.
- System-update version/check/status/download/install/rollback is implemented
  in the Rust backend and GUI through manual rollback. It displays the current
  system baseline, validates GitHub `system-latest.json`, downloads the archive,
  verifies archive sha256/sha512, safely extracts it, validates `manifest.json`,
  verifies every payload file hash/size/path, backs up touched files, applies
  payload files atomically, writes `/etc/kvm/system-version.json`, records
  pending/backup markers, generates an init-time rollback script, supports
  manual boot-good confirmation after basic health checks, and can
  automatically roll back a pending update when boot health fails.
- Experimental raw boot/rootfs partition bundles are implemented behind
  `security.allow_raw_system_updates`. They can be staged through the same GUI,
  write only `images/boot.vfat` or `images/boot.vfat.gz` to `/dev/mmcblk0p1`
  and `images/rootfs.sd` or `images/rootfs.sd.gz` to `/dev/mmcblk0p2`, sync,
  and reboot. Current raw releases use gzip-compressed payloads and stream them
  directly to the block devices to avoid extracting a full 1.5GB rootfs into
  the staging filesystem. This is for lab devices with SD-card recovery only
  and has no automatic rollback. Raw bundle tooling now rejects rootfs images
  that do not contain the Hardened NanoKVM `/kvmapp`, `/etc/kvm`, init script,
  web assets, and Rust-only backend files, and do not contain legacy Go backend
  files or switch scripts.
- `hardened-system-0.1.0-raw.1` is a revoked experimental raw release. It was
  built from the stock vendor SDK rootfs and must not be installed. Use a newer
  raw release produced from a validated Hardened SD image.
- The first signed rootfs-only smoke release,
  `hardened-system-0.1.0-dev.1`, validated the non-destructive
  check/download/install/status/confirm/rollback flow on `10.0.87.132`. It is
  now historical. The current stable system channel points to lab raw release
  `hardened-system-0.2.11-raw.1`, built from the beta `2.0.15` Hardened SD
  image. The GUI reports system update version, base image, Buildroot release,
  and security backport level separately so the raw channel version is not
  confused with the underlying Buildroot base.
  The bundled public key is installed from `kvmapp` to
  `/etc/kvm/system-update-signing.pub.pem` on service start, but this is still
  not a production private-key custody process.

## Implementation Order

1. Inventory the current base system on test devices:
   - `uname -a`, kernel config, loaded modules, `/lib/modules`;
   - boot partition contents, kernel/dtb/u-boot file locations;
   - rootfs partition layout and available `/data` and `/tmp` space;
   - `/etc/kvm`, account files, SSH, network, TLS, and backend state;
   - `kvm_system`, `libkvm.so`, multimedia libraries, device nodes, and
     reserved-memory layout.

2. Reproduce a clean stock build from the Sipeed/LicheeRV Nano vendor SDK:
   - bootstrap the pinned SDK checkout with `make vendor-sdk`;
   - run the stock build with `make vendor-sdk-stock` so Buildroot gets a
     Linux-only PATH on WSL hosts;
   - inspect the generated `upgrade.zip` with `make vendor-sdk-inspect`;
   - build a stock image first, without Hardened changes;
   - boot it on test hardware;
   - verify video, HID, storage, network, SSH, web UI, and Rust-only backend startup;
   - only then apply selected security backports.

3. Define a separate system-update bundle format:
   - `manifest.json` with version, target hardware revision, base/kernel
     version, required free space, file hashes, backup paths, and reboot flag;
   - payload for kernel, dtb, modules, and known system files;
   - optional experimental raw `boot.vfat`/`rootfs.sd` image entries, including
     gzip-compressed `.gz` variants, gated by device config for lab-only
     partition flashing;
   - fixed installer operations controlled by the backend, not arbitrary scripts
     from the archive.

4. Add signature verification:
   - sign channel metadata with a project release key (tooling implemented with
     detached OpenSSL sha256/RSA signatures);
   - verify metadata signatures on device before trusting `system-latest.json`
     (backend enforcement implemented);
   - keep unsigned system updates blocked except for explicit development mode
     through `security.allow_unsigned_updates` (implemented).

5. Add Rust backend API:
   - `GET /api/system-update/version` (implemented read-only);
   - `GET /api/system-update/check` (implemented read-only);
   - `GET /api/system-update/status` (implemented read-only);
   - `POST /api/system-update/download` (implemented staging-only);
   - `POST /api/system-update/install` (implemented manual);
   - `POST /api/system-update/rollback` (implemented manual);
   - `POST /api/system-update/confirm` (implemented manual boot-good).

6. Implement staging, backup, install, and rollback:
   - download to the configured update cache, currently
     `/data/.hardened-kvmcache/system-update`;
   - unpack into a staging directory and verify manifest/payload files
     (implemented);
   - back up touched files under
     `/data/.hardened-kvmcache/system-update/backups/<id>` (implemented);
   - write a pending-update marker under `/etc/kvm` (implemented);
   - generate `/etc/kvm/system-update-rollback.sh` for boot-time recovery
     (implemented);
   - install only after all checks pass (implemented);
   - reboot into the updated system (manual through the existing reboot API/UI).

7. Add boot health confirmation:
   - Rust backend started;
   - HTTP/HTTPS reachable;
   - persisted system version matches the pending update;
   - boot marker exists;
   - web root exists;
   - after success, write `boot-good` manually from GUI/API;
   - otherwise `S95nanokvm` executes `/etc/kvm/system-update-rollback.sh` and
     reboots after rollback (implemented).

8. Add GUI support under Check for Updates:
   - separate `Application Update` and `System Update` sections;
   - explicit warning for kernel/base updates;
   - progress, verification state, reboot prompt, and rollback status.

9. Add remote syslog support for update observability:
   - `Settings > Device > Advanced` toggle and host/port/protocol fields;
   - BusyBox `syslogd` forwarding with local logging kept enabled;
   - Rust/backend, init/watchdog, and raw updater logs routed through syslog
     tags such as `nanokvm-server` and `hardened-system-update`;
   - `Send test log` action in the GUI;
   - LAN/VPN-only warning because initial syslog transport is plaintext UDP.

## GitHub Release Contract

The initial release contract is documented in
[system-update-github-releases.md](system-update-github-releases.md).

Versioned system-update releases carry immutable archives named
`hardened-nanokvm-system-<version>.tar.gz`. Fixed channel releases carry
`system-latest.json`, which points to the versioned archive and includes sha256,
sha512, target hardware, size, release notes URL, signature algorithm, and
signature key id. Signed channel releases must also carry
`system-latest.json.sig`.

The current helper scripts are:

- `scripts/bootstrap-vendor-sdk.sh`
- `scripts/create-system-update-bundle.sh`
- `scripts/extract-sd-raw-images.sh`
- `scripts/validate-nanokvm-rootfs.sh`
- `scripts/create-raw-system-update-bundle.sh`
- `scripts/create-system-update-metadata.sh`
- `scripts/verify-system-update-metadata.sh`

The pinned vendor SDK bootstrap and stock-image validation sequence are
documented in [vendor-sdk-build.md](vendor-sdk-build.md).
Newer SDK and new Buildroot feasibility notes are documented in
[new-buildroot-sysupgrade-study.md](new-buildroot-sysupgrade-study.md).
The Buildroot 2023.11.2 security backport route is documented in
[buildroot-2023-security-backport-plan.md](buildroot-2023-security-backport-plan.md).
Live device layout observations are recorded in
[system-update-live-inventory.md](system-update-live-inventory.md).

The Rust backend can download, verify, install, manually confirm boot-good, and
manually roll back these archives. It enforces signed channel metadata by
default using `paths.system_update_public_key`, with unsigned metadata accepted
only when `security.allow_unsigned_updates=true`. The installer does not reboot
automatically. If a rebooted pending update fails local boot health checks,
`S95nanokvm` executes the generated rollback script and reboots after restoring
the previous files.

## Required Test Sequence

1. Validate raw/system update tooling against a freshly built known-good
   Hardened SD image from the sysupgrade branch before testing any SDK-derived
   image. Do not use the old `1.0.1` baseline for this stage because it predates
   the bundled system-update public key.
2. Extract boot/rootfs from that known-good image, validate the rootfs, build a
   raw bundle, install it through GUI/API on sacrificial SD media, and confirm
   web, SSH, video, HID, and reboot behavior.
3. Manual system bundle install over SSH.
4. Manual rollback.
5. Backend API download/status flow.
6. Backend API install/rollback flow.
7. GUI flow.
8. Rollback-on-bad-boot flow.
9. Only after the known-good Hardened image path passes, repeat the same flow
   with SDK-derived images.
10. Long video, HID, network, reboot, and Rust backend startup/restart soak
   after update.

## Non-Goals For The First Version

- Mainline kernel migration.
- Live rootfs overwrite without staging and rollback.
- Raw partition updates outside explicit lab mode with SD-card recovery ready.
- Arbitrary post-install scripts from update archives.
- Automatic system update installation without explicit user confirmation.
