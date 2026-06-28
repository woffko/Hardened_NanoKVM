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
- Application update metadata is served as `latest.json` and the downloaded
  archive is verified with sha512 before installation.
- System updates will use a separate GitHub release channel metadata file,
  `system-latest.json`, attached to fixed channel tags such as
  `hardened-system-stable`. They must not use GitHub `/releases/latest` while
  application updates still depend on that endpoint.
- SD-card images are currently produced by patching a trusted upstream NanoKVM
  Rev1.4.2 base image with the current Hardened `kvmapp`.
- A reproducible full boot/rootfs image build from the Sipeed/LicheeRV Nano
  vendor SDK is not yet established.
- GUI system updates for kernel, dtb, modules, boot files, or rootfs files are
  not implemented yet.

## Implementation Order

1. Inventory the current base system on test devices:
   - `uname -a`, kernel config, loaded modules, `/lib/modules`;
   - boot partition contents, kernel/dtb/u-boot file locations;
   - rootfs partition layout and available `/data` and `/tmp` space;
   - `/etc/kvm`, account files, SSH, network, TLS, and backend state;
   - `kvm_system`, `libkvm.so`, multimedia libraries, device nodes, and
     reserved-memory layout.

2. Reproduce a clean stock build from the Sipeed/LicheeRV Nano vendor SDK:
   - build a stock image first, without Hardened changes;
   - boot it on test hardware;
   - verify video, HID, storage, network, SSH, web UI, and backend switching;
   - only then apply selected security backports.

3. Define a separate system-update bundle format:
   - `manifest.json` with version, target hardware revision, base/kernel
     version, required free space, file hashes, backup paths, and reboot flag;
   - payload for kernel, dtb, modules, and known system files;
   - fixed installer operations controlled by the backend, not arbitrary scripts
     from the archive.

4. Add signature verification:
   - sign the manifest with a project release key, for example Ed25519 or
     minisign;
   - verify the signature and every file hash on device before installation;
   - keep unsigned system updates blocked except for explicit development mode.

5. Add Rust backend API:
   - `GET /api/system-update/version`;
   - `GET /api/system-update/check`;
   - `POST /api/system-update/download`;
   - `POST /api/system-update/install`;
   - `GET /api/system-update/status`;
   - `POST /api/system-update/rollback`.

6. Implement staging, backup, install, and rollback:
   - download to `/data/update-cache`;
   - unpack into a staging directory;
   - back up kernel, dtb, modules, and config files to `/data/system-backups`;
   - write a pending-update marker;
   - install only after all checks pass;
   - reboot into the updated system.

7. Add boot health confirmation:
   - Rust backend started;
   - HTTP/HTTPS reachable;
   - video pipeline responds;
   - HID paths exist;
   - network is alive;
   - after success, write `boot-good`; otherwise rollback on next boot.

8. Add GUI support under Check for Updates:
   - separate `Application Update` and `System Update` sections;
   - explicit warning for kernel/base updates;
   - progress, verification state, reboot prompt, and rollback status.

## GitHub Release Contract

The initial release contract is documented in
[system-update-github-releases.md](system-update-github-releases.md).

Versioned system-update releases carry immutable archives named
`hardened-nanokvm-system-<version>.tar.gz`. Fixed channel releases carry
`system-latest.json`, which points to the versioned archive and includes sha256,
sha512, target hardware, size, and release notes URL.

The current helper scripts are:

- `scripts/create-system-update-bundle.sh`
- `scripts/create-system-update-metadata.sh`

The Rust backend installer is not implemented yet. These scripts only define and
validate the release artifact format.

## Required Test Sequence

1. Manual system bundle install over SSH.
2. Manual rollback.
3. Backend API download/install/status flow.
4. GUI flow.
5. Long video, HID, network, reboot, and backend-switching soak after update.

## Non-Goals For The First Version

- Mainline kernel migration.
- Live rootfs overwrite without staging and rollback.
- Arbitrary post-install scripts from update archives.
- Automatic system update installation without explicit user confirmation.
