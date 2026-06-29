# Current Sysupgrade Build Trace

This file is the local handoff/trace for the active experimental system-update
build. Keep it updated before long-running builds or risky device operations.

## 2026-06-29: Raw System Update With Buildroot 2023.11.3 Security Delta

Goal:

- build a sacrificial raw system-update bundle that can be installed from the
  Hardened NanoKVM GUI system-update path;
- include the current Hardened application/backend;
- include the first low-risk Buildroot security backport layer from upstream
  `2023.11.2..2023.11.3`;
- keep the vendor Sipeed/Sophgo SDK, kernel, board config, MMF/VENC, LT6911,
  and SD-card layout.

Branch:

- repository worktree:
  `/home/w0w/Hardened_NanoKVM-new-buildroot`
- branch: `feature/new-buildroot-sysupgrade-lab`
- latest committed baseline before current uncommitted trace updates:
  `a9dee95 Add Buildroot 2023 security backport trace`

SDK checkout used for the build:

- `/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build`
- baseline SDK commit: `d88d58feca49ef15f4cc7bd1f27dbf17dc25f85e`
- this checkout is intentionally outside the tracked repository source.

Buildroot backport helper added:

- `scripts/apply-buildroot-2023-11-3-security-backports.sh`

Backport command run:

```sh
BUILDROOT_UPSTREAM_REPO=/tmp/buildroot-security-probe \
LICHEERV_NANO_SDK_DIR=/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build \
  scripts/apply-buildroot-2023-11-3-security-backports.sh
```

Upstream Buildroot source used for the diff:

- `/tmp/buildroot-security-probe`
- range: `2023.11.2..2023.11.3`
- package dirs only:
  - `package/libopenssl`
  - `package/libcurl`
  - `package/python3`
  - `package/expat`
  - `package/libxml2`

Expected version changes now applied in the SDK checkout:

| Package | Old | New |
| --- | --- | --- |
| libopenssl | `3.1.4` | `3.1.5` |
| libcurl | `8.5.0` | `8.6.0` |
| python3 | `3.11.6` | `3.11.8` |
| expat | `2.6.0` | `2.6.2` |
| libxml2 | `2.11.6` | `2.11.7` |

SDK git status after applying the patch:

```text
M  buildroot/package/expat/expat.hash
M  buildroot/package/expat/expat.mk
D  buildroot/package/libcurl/0001-gnutls-fix-build-with-disable-verbose.patch
M  buildroot/package/libcurl/libcurl.hash
M  buildroot/package/libcurl/libcurl.mk
M  buildroot/package/libopenssl/libopenssl.hash
M  buildroot/package/libopenssl/libopenssl.mk
M  buildroot/package/libxml2/libxml2.hash
M  buildroot/package/libxml2/libxml2.mk
M  buildroot/package/python3/python3.hash
M  buildroot/package/python3/python3.mk
?? buildroot/package/libcurl/0001-configure.ac-find-libpsl-with-pkg-config.patch
```

Next planned steps:

1. Test the GUI update check/install on a sacrificial NanoKVM with raw updates
   explicitly enabled and SD-card recovery available.
2. Record device-side installer logs and outcome here.
3. If the GUI install succeeds, decide whether to keep `hardened-system-stable`
   pointed at `0.1.4-raw.1` or move this raw build to preview-only.

Progress log:

- Applied the Buildroot `2023.11.2..2023.11.3` package patch to the SDK
  checkout successfully.
- Ran targeted Buildroot cleanup:

```sh
make -C /home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build/buildroot \
  host-libopenssl-dirclean libopenssl-dirclean \
  host-python3-dirclean python3-dirclean \
  host-expat-dirclean expat-dirclean \
  host-libxml2-dirclean libxml2-dirclean \
  libcurl-dirclean
```

- First `make vendor-sdk-stock` attempt from the new worktree failed before the
  build because that worktree did not have local `host-deps`.
- Re-ran with `VENDOR_SDK_CLEAN_PATH` pointing at the already unpacked
  `/home/w0w/Hardened_NanoKVM/build/host-deps`.
- SDK rebuild progressed through U-Boot, FSBL, boot packaging, kernel/modules,
  osdrv, middleware, LT6911 sensor library, and reached `br-rootfs-pack`.
- Buildroot then failed while downloading the new Track 1 source tarballs due
  to sandbox DNS failure, not due to compile errors:
  - `openssl-3.1.5.tar.gz`
  - `curl-8.6.0.tar.xz`
  - `Python-3.11.8.tar.xz`
  - `expat-2.6.2.tar.xz`
  - `libxml2-2.11.7.tar.xz`
- Re-ran the same `vendor-sdk-stock` command with network access outside the
  sandbox. Buildroot downloaded the new tarballs and successfully rebuilt the
  Track 1 packages.
- Vendor SDK stock build completed successfully.

Generated patched stock SDK artifacts:

| Artifact | Path | Size | SHA256 |
| --- | --- | ---: | --- |
| SD image | `/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build/install/soc_sg2002_licheervnano_sd/images/2026-06-29-12-08-d88d58.img` | ~1.6G | `887d2198d889424f54b5d4a80664adc280183647a1d4ba08dfaa6cf3d73dad0b` |
| boot partition image | `/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build/install/soc_sg2002_licheervnano_sd/images/boot.vfat` | 16M | `cbaf57e5fbc3f0adb86a033beb5404e96cd26564481d42c56290dc7bc7942b78` |
| raw rootfs | `/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build/install/soc_sg2002_licheervnano_sd/rawimages/rootfs.sd` | ~1.5G | `c56ec0ed5433c8647dba0dca259802f9a8bb5281a4da875fa35ac73c60773406` |

Important detail:

- `/usr/lib/os-release` inside this stock rootfs still reports
  `VERSION_ID=2023.11.2`, because this build is not a full Buildroot version
  migration. It is vendor Buildroot `2023.11.2` plus selected package-level
  security backports from upstream `2023.11.3`.
- These are still stock SDK artifacts. The current Hardened app/backend has not
  been injected yet.

Application build and packaging:

- App version: `1.0.5`.
- Rust tests passed:
  - `cargo test --manifest-path server-rust/Cargo.toml`
  - 108 library tests, 2 main tests, 0 failures.
- Frontend build passed:
  - `corepack pnpm --dir web build`
- First linked Rust backend build failed because this new worktree did not have
  `server-rust/sysroot/lib/libc.so`.
- Reused the known-good NanoKVM runtime sysroot from the previous worktree:
  `/home/w0w/Hardened_NanoKVM/server-rust/sysroot/lib`.
- Linked Rust backend build passed:

```sh
NANOKVM_SYSROOT_LIB=/home/w0w/Hardened_NanoKVM/server-rust/sysroot/lib \
  server-rust/scripts/build-linked-libkvm.sh
```

- `kvm_system` helper source:
  `/home/w0w/Hardened_NanoKVM/build/kvmapp-rust/kvmapp/kvm_system/kvm_system`
  (`325040` bytes).
- Staged `kvmapp-rust` archive:
  `/home/w0w/Hardened_NanoKVM-new-buildroot/build/artifacts/nanokvm-kvmapp-rust.tar.gz`
  - size: `12M`
  - sha256:
    `2c6ee4621548dee2b1ee927eceece958e8e0a199deef4785c3eaba435eee0d85`

Generated Hardened SD artifacts:

| Artifact | Path | Size | SHA256 |
| --- | --- | ---: | --- |
| Hardened SD image | `/home/w0w/Hardened_NanoKVM-new-buildroot/build/sd-image/Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust.img` | ~1.6G | `6af992da38937d9891364055b003b54d992afcc626765babecffa162cd7bfffe` |
| Compressed Hardened SD image | `/home/w0w/Hardened_NanoKVM-new-buildroot/build/sd-image/Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust.img.xz` | 151M | `357874b815a4f49f8056b6d4960a9e814cbfc042a0419fe60c9dfa2d66116315` |
| Extracted raw boot | `/home/w0w/Hardened_NanoKVM-new-buildroot/build/sd-image/raw-system-update/Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust/boot.vfat` | 16M | `cbaf57e5fbc3f0adb86a033beb5404e96cd26564481d42c56290dc7bc7942b78` |
| Extracted raw rootfs before bundle patch | `/home/w0w/Hardened_NanoKVM-new-buildroot/build/sd-image/raw-system-update/Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust/rootfs.sd` | ~1.5G | `153282537b8c6bfa368566cf495ccb5e09c79b8f0a83eac45c6001afc2e04c57` |

Validation:

```sh
scripts/validate-nanokvm-rootfs.sh \
  build/sd-image/Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust.rootfs.ext
```

Result:

- `kvmapp version: 1.0.5`
- `backend: rust`

Generated raw system-update bundle:

```sh
BASE_VERSION=2026-06-29-12-08-d88d58.img \
KERNEL_VERSION=5.10.4-tag- \
scripts/create-raw-system-update-bundle.sh \
  0.1.4-raw.1 \
  sg2002-licheervnano-sd \
  build/sd-image/raw-system-update/Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust/boot.vfat \
  build/sd-image/raw-system-update/Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust/rootfs.sd \
  build/system-updates
```

Note:

- A local intermediate `0.1.3-raw.1` bundle was built first, but the GitHub tag
  already existed with older assets. The published release was bumped to
  `0.1.4-raw.1` to avoid overwriting and cache confusion.

Bundle artifacts:

| Artifact | Path | Size | SHA256 |
| --- | --- | ---: | --- |
| Raw system-update archive | `/home/w0w/Hardened_NanoKVM-new-buildroot/build/system-updates/hardened-nanokvm-system-0.1.4-raw.1.tar.gz` | 225M | `14a3654de1741c6beabea80d95a3647c990daf1e8a3b907a0158c5e91b3d5f83` |
| Metadata | `/home/w0w/Hardened_NanoKVM-new-buildroot/build/system-updates/system-latest.json` | 762 bytes | `4ba73f0d4b888089a127e4a0e9f2c920aa75df97b00cf1922be1e1654eeccf5f` |
| Metadata signature | `/home/w0w/Hardened_NanoKVM-new-buildroot/build/system-updates/system-latest.json.sig` | 384 bytes | `7bc1a09be4507b26b2c12e7bfc6224bc70dbc7b295e84723be0bf69968345fea` |

Bundle manifest notes:

- Version: `0.1.4-raw.1`
- Target: `sg2002-licheervnano-sd`
- Source commit: `52f491c`
- Required staging free space: `2147483648` bytes.
- Raw writes:
  - `/dev/mmcblk0p2` from `images/rootfs.sd`
  - `/dev/mmcblk0p1` from `images/boot.vfat`
- Bundle script patches `/etc/kvm/system-version.json` into the rootfs copy
  before archiving, so the rootfs hash inside the archive is:
  `3330105693b94e952dd5dcbb0dd356c391750fba34f9916fec45c59213c758e1`.

Metadata signing:

```sh
SYSTEM_UPDATE_SIGNING_KEY=/home/w0w/Hardened_NanoKVM/build/release/system-update-signing-test.pem \
SYSTEM_UPDATE_SIGNATURE_KEY_ID=hardened-system-test \
scripts/create-system-update-metadata.sh \
  0.1.4-raw.1 \
  hardened-system-0.1.4-raw.1 \
  build/system-updates/hardened-nanokvm-system-0.1.4-raw.1.tar.gz \
  build/system-updates/system-latest.json
```

Signature verification passed:

```sh
scripts/verify-system-update-metadata.sh \
  build/system-updates/system-latest.json \
  build/system-updates/system-latest.json.sig \
  kvmapp/system/keys/system-update-signing.pub.pem
```

Result: `Verified OK`.

GitHub publication:

- Branch pushed:
  `feature/new-buildroot-sysupgrade-lab` at `52f491c`.
- Versioned release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.1.4-raw.1`
- Uploaded versioned release assets:
  - `hardened-nanokvm-system-0.1.4-raw.1.tar.gz`
  - `hardened-nanokvm-system-0.1.4-raw.1.tar.gz.sha256`
  - `hardened-nanokvm-system-0.1.4-raw.1.tar.gz.sha512`
  - `system-latest.json`
  - `system-latest.json.sha256`
  - `system-latest.json.sig`
  - `system-latest.json.sig.base64`
  - `Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust.img.xz`
  - `Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust.sha256`
- Stable channel release updated:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`
- Public channel metadata was downloaded from GitHub and verified locally:

```sh
scripts/verify-system-update-metadata.sh \
  /tmp/hardened-system-stable-latest.json \
  /tmp/hardened-system-stable-latest.json.sig \
  kvmapp/system/keys/system-update-signing.pub.pem
```

Result: `Verified OK`.

Risk notes:

- This is a lab raw update. It writes raw `/dev/mmcblk0p1` and
  `/dev/mmcblk0p2`.
- Recovery is SD-card rewrite, not automatic rollback.
- Kernel is still the vendor 5.10 tree; no kernel security rebase is included in
  this first bundle.

## 2026-06-29: Device Install Attempt on `10.0.87.132`

Start state before installing `0.1.4-raw.1`:

- SSH login works as `root/admin1234`.
- Local WSL `curl` to `http://10.0.87.132:80` failed, but SSH showed
  `NanoKVM-Server` listening on `0.0.0.0:80`; API calls will be made from the
  device itself through `localhost`.
- Device kernel: `5.10.4-tag-`.
- `/etc/os-release`: Buildroot `2023.11.2`.
- `/kvmapp/version`: `1.0.5`.
- `/etc/kvm/system-version.json`: `0.1.3-raw.1`.
- `/boot/ver`: `2026-01-05-1_4_1.img`.
- Processes before install:
  - `/tmp/kvm_system/kvm_system`
  - `/tmp/server/NanoKVM-Server`
- `/etc/kvm/preview_updates` exists and contains `1`.

Planned test:

1. Authenticate against `http://127.0.0.1/api/auth/login`.
2. Check `/api/system-update/check` and `/api/system-update/status`.
3. Reuse or download the staged `0.1.4-raw.1` bundle.
4. Run `/api/system-update/install`.
5. Track `/data/hardened-system-raw-update.log`, API status, and reboot/SSH
   reachability.

Observed before install:

- Initial `GET /api/system-update/*` returned `404`: the device had app version
  `1.0.5`, but it was not the sysupgrade-capable app build.
- Installed local sysupgrade-capable application bundle through the existing
  offline application update endpoint:
  `/data/hardened-nanokvm-kvmapp-1.0.5.tar.gz`
  (`2c6ee4621548dee2b1ee927eceece958e8e0a199deef4785c3eaba435eee0d85`).
- The restarted backend then exposed `/api/system-update/version`,
  `/api/system-update/check`, `/api/system-update/status`, and raw update
  strings.
- `allow_raw_system_updates` was set to `true` in `/etc/kvm/server.yaml` for
  this lab test.
- Preview updates had to be disabled by removing `/etc/kvm/preview_updates`;
  writing `0` to the file is not enough because the code treats file existence
  as enabled.
- Stable channel check succeeded:
  - current: `0.1.3-raw.1`
  - latest: `0.1.4-raw.1`
  - update available: `true`
- `POST /api/system-update/download` succeeded after about 5.5 minutes:
  - staged version: `0.1.4-raw.1`
  - channel: `stable`
  - archive:
    `hardened-nanokvm-system-0.1.4-raw.1.tar.gz`
  - sha256:
    `14a3654de1741c6beabea80d95a3647c990daf1e8a3b907a0158c5e91b3d5f83`
  - `fileCount`: `2`
  - `imageCount`: `2`
  - `destructive`: `true`
  - `requiresReboot`: `true`

Notes:

- The GUI/API progress stays at `download/verifying` for several minutes while
  hashing/extracting the raw rootfs. Future UX should expose a more specific
  phase and byte progress for this stage.
- The current preview-channel fallback behavior can hide a newer stable system
  update when preview metadata is valid but older. This should be fixed before
  this feature is used outside lab testing.

Install attempt result so far:

- `POST /api/system-update/install` was started against staged `0.1.4-raw.1`.
- The API client timed out after 120 seconds while the backend was still in
  `install/extracting`; the backend continued the install.
- Raw writer then started successfully:
  - stopped NanoKVM runtime;
  - prepared `/boot`;
  - remounted `/` read-only with the normal remount path;
  - started writing `ROOTFS` to `/dev/mmcblk0p2` at `10:31:40`.
- Last observed raw log line before the SSH session stopped responding:
  `writing ROOTFS to /dev/mmcblk0p2`.
- After that, `10.0.87.132` did not return to SSH/HTTP during repeated probes;
  `ssh` reported `No route to host` and HTTP timed out.

Image contents confirmation:

- The SD image and the raw system-update rootfs were built from the patched
  Hardened rootfs, not from the stock SDK rootfs.
- The rootfs includes full `/kvmapp`:
  - Rust `server/NanoKVM-Server`;
  - web UI assets;
  - `/kvmapp/version` = `1.0.5`;
  - `kvm_system` helper;
  - runtime shared libraries under `server/dl_lib`;
  - system init scripts and kernel modules;
  - bundled system-update public key at
    `/kvmapp/system/keys/system-update-signing.pub.pem`.
- `scripts/validate-nanokvm-rootfs.sh` passed before publishing and reported:
  `kvmapp version: 1.0.5`, `backend: rust`.
- Legacy Go backend files are rejected by the package/rootfs validators and
  should not be present in this build.

Post-write device state:

- The device did not come back on the old DHCP address `10.0.87.132`.
- It reappeared as `10.0.87.55`.
- SSH credentials after the raw rootfs write are `root/root`.
- HTTP is not listening on the new address.
- The raw system update appears to have been applied:
  - `uname -a`: vendor `5.10.4-tag-`, build timestamp
    `Mon Jun 29 11:59:04 EEST 2026`;
  - `/etc/os-release`: Buildroot `2023.11.2` with SDK revision
    `-gd88d58fec-dirty`;
  - `/etc/kvm/system-version.json`: `0.1.4-raw.1`;
  - `/kvmapp/version`: `1.0.5`;
  - `/boot/ver`: `2026-06-29-12-08-d88d58.img`;
  - `/etc/kvm/backend`: `rust`.
- `/etc/kvm/pwd` is absent, so first web login setup would be expected if the
  web backend started.
- `ps` shows `/tmp/kvm_system/kvm_system`, but no running `NanoKVM-Server`.
- `/tmp/nanokvm-watchdog.log` repeatedly reports that `NanoKVM-Server` is not
  running.
- Manual server start from `/kvmapp/server` exits with `Segmentation fault`.
- The only userspace log before the crash is:
  `[SAMPLE_COMM_SNS_ParseIni]-2204: Parse /mnt/data/sensor_cfg.ini`.
- `dmesg` reports repeated `NanoKVM-Server` signal 11 crashes at bad address
  `0x1a0` inside `libstdc++.so.6.0.28`.
- Replacing bundled `/kvmapp/server/dl_lib/libsys.so` with the system
  `/mnt/system/usr/lib/libsys.so` did not change the crash.

Corrected diagnosis after comparing with working `10.0.87.133`:

- The raw updater wrote the new boot/rootfs and included `/kvmapp`; this is not
  an empty stock-image problem.
- The web outage is caused by Rust backend startup crashing during native video
  initialization.
- The binary/runtime ABI mismatch hypothesis was tested and is not the current
  root cause:
  - `10.0.87.133` runs the same `NanoKVM-Server`, `libkvm.so`,
    `libkvm_mmf.so`, `libsys.so`, and Buildroot `libstdc++.so.6.0.28` hashes;
  - replacing `libsys.so` and temporarily bundling the MaixCDK `libstdc++`
    variant on `10.0.87.55` did not fix the crash.
- The confirmed difference is `/mnt/data` sensor configuration:
  - broken `10.0.87.55` after the raw update had only
    `sensor_cfg.ini.alpha` and `sensor_cfg.ini.beta`;
  - working `10.0.87.133` has `sensor_cfg.ini.LT`,
    `sensor_cfg.ini.OA`, `sensor_cfg.ini.SC035`, alpha/beta, and active
    `sensor_cfg.ini` copied from the LT file;
  - working active config is `LONTIUM_LT6911_2M_60FPS_8BIT`, bus `4`,
    address `ff`, lane `2, 4, 3, 1, 0`, `mclk_en=0`, `fps=60`;
  - its sha256 is
    `26f3e80b1a05eb93b18a0d7e557851462f0bb04619cca902f5ade8abe66bb3c8`.
- Copying that LT config to `10.0.87.55` fixed backend startup:
  - `NanoKVM-Server` stayed running;
  - port `80` listened on the device;
  - device-local `GET http://127.0.0.1/api/health` returned
    `{"backend":"rust","phase":"skeleton","status":"ok"}`.
- Local WSL `curl` to `10.0.87.55:80` still failed even after the backend was
  listening; this matches the earlier device-local-vs-host reachability quirk
  seen on `10.0.87.132`.

Fix applied locally:

- Added bundled sensor configs under `/kvmapp/system/mnt-data`:
  - `sensor_cfg.ini.LT`
  - `sensor_cfg.ini.OA`
  - `sensor_cfg.ini.SC035`
  - `sensor_cfg.ini.alpha`
  - `sensor_cfg.ini.beta`
- Updated `S95nanokvm` to restore missing `/mnt/data/sensor_cfg.*` files from
  `/kvmapp/system/mnt-data` and copy LT to active `/mnt/data/sensor_cfg.ini`
  before starting the backend.
- Updated `scripts/build-rust-sd-image.sh` to write bundled sensor configs
  directly into rootfs `/mnt/data`, including active `sensor_cfg.ini` from LT.
- Updated `scripts/validate-nanokvm-rootfs.sh` to fail builds missing the
  bundled and rootfs LT sensor config.
- Syntax checks passed:
  - `sh -n kvmapp/system/init.d/S95nanokvm`
  - `sh -n scripts/build-rust-sd-image.sh`
  - `sh -n scripts/validate-nanokvm-rootfs.sh`

Final sensorfix release:

- Code/source commit for the fixed artifacts:
  `06c643f Fix LT6911 sensor config in sysupgrade image`.
- Branch pushed:
  `feature/new-buildroot-sysupgrade-lab`.
- Release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.1.5-raw.1`
- Stable channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`
- Public stable metadata was checked and returns:
  - version: `0.1.5-raw.1`;
  - sha256:
    `88d681e07f99128ce9e8f6d9f61fde21502afab727d117f3708f641a98379936`;
  - URL:
    `https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-0.1.5-raw.1/hardened-nanokvm-system-0.1.5-raw.1.tar.gz`.
- Final local artifacts:
  - app archive:
    `/home/w0w/Hardened_NanoKVM-new-buildroot/build/artifacts/nanokvm-kvmapp-rust.tar.gz`
    sha256 `7d5ca62eef83099e93e3691758733123671bef43392558718bf903b01bf1f31b`;
  - SD image:
    `/home/w0w/Hardened_NanoKVM-new-buildroot/build/sd-image/Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_sensorfix_Rev1_4_2_rust.img`
    sha256 `ba3f08b4657a47b4529154c9094d4ac5c761b1c60294b9265ba198a1b1f734c0`;
  - compressed SD image:
    `/home/w0w/Hardened_NanoKVM-new-buildroot/build/sd-image/Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_sensorfix_Rev1_4_2_rust.img.xz`
    sha256 `8c330399656b183ce72f861f16abb332e276033445ea5c87f3e16e69db946bf0`;
  - raw system-update archive:
    `/home/w0w/Hardened_NanoKVM-new-buildroot/build/system-updates/hardened-nanokvm-system-0.1.5-raw.1.tar.gz`
    sha256 `88d681e07f99128ce9e8f6d9f61fde21502afab727d117f3708f641a98379936`;
  - final metadata:
    `/home/w0w/Hardened_NanoKVM-new-buildroot/build/system-updates/system-latest.json`
    sha256 `63ce32f551342d22a9ef2dacb3e98380f40ee4cbcdaccb3568e212ed7ceea64a`.
- Final raw manifest source commit is `06c643f`; raw image entries inside the
  archive:
  - ROOTFS `/dev/mmcblk0p2` sha256
    `a33ef9313ec64449cf6f86df3a9a27672ed5efbd0f55a152180ad3c87321bc41`;
  - BOOT `/dev/mmcblk0p1` sha256
    `cbaf57e5fbc3f0adb86a033beb5404e96cd26564481d42c56290dc7bc7942b78`.
- `10.0.87.133` was inspected read-only only. No files, services, or reboot
  actions were changed there.

## 2026-06-29: Beta 2 Integrated App/SD/Raw Release Build

Goal:

- publish a single beta 2 line that includes the latest Rust-only application,
  the sysupgrade GUI/backend work, the LT6911 sensorfix, and the Buildroot
  2023.11.2 security-backport SD/rootfs baseline;
- add a GUI switch on Check for Updates for explicitly enabling raw system
  updates before destructive boot/rootfs writes;
- ship app update, SD-card image, and raw system-update bundle together.

Source commit:

- `8fa6bd6 Add guarded raw system update toggle`

Versioning:

- application update version: `2.0.0`
- web display version: `beta 2`
- raw system-update version: `0.2.0-raw.1`
- app release tag: `hardened-rust-beta-2`
- system release tag: `hardened-system-0.2.0-raw.1`

Base image for SD/raw:

- `/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build/install/soc_sg2002_licheervnano_sd/images/2026-06-29-12-08-d88d58.img`
- This is the vendor Buildroot `2023.11.2` SDK image with selected
  Buildroot `2023.11.3` package-level security backports. It is not a full
  Buildroot version migration.

Build commands used:

```sh
cargo check --manifest-path server-rust/Cargo.toml
corepack pnpm --dir web build
NANOKVM_SYSROOT_LIB=/home/w0w/Hardened_NanoKVM/server-rust/sysroot/lib \
  server-rust/scripts/build-linked-libkvm.sh
RUST_TARGET=riscv64gc-unknown-linux-musl \
APP_VERSION=2.0.0 \
ARTIFACT_NAME=hardened-nanokvm-kvmapp-2.0.0.tar.gz \
KVM_SYSTEM_SOURCE=/home/w0w/Hardened_NanoKVM/build/kvmapp-rust/kvmapp/kvm_system/kvm_system \
  scripts/package-rust-kvmapp.sh
NANOKVM_BASE_IMAGE=/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build/install/soc_sg2002_licheervnano_sd/images/2026-06-29-12-08-d88d58.img \
SD_IMAGE_BASENAME=Hardened_NanoKVM_beta_2_buildroot_2023_11_2_security_Rev1_4_2_rust \
HARDENED_RELEASE_VERSION=2.0.0 \
  make sd-image
scripts/extract-sd-raw-images.sh \
  build/sd-image/Hardened_NanoKVM_beta_2_buildroot_2023_11_2_security_Rev1_4_2_rust.img \
  build/sd-image/raw-system-update/Hardened_NanoKVM_beta_2_buildroot_2023_11_2_security_Rev1_4_2_rust
BASE_VERSION=2026-06-29-12-08-d88d58.img \
KERNEL_VERSION=5.10.4-tag- \
  scripts/create-raw-system-update-bundle.sh \
  0.2.0-raw.1 \
  sg2002-licheervnano-sd \
  build/sd-image/raw-system-update/Hardened_NanoKVM_beta_2_buildroot_2023_11_2_security_Rev1_4_2_rust/boot.vfat \
  build/sd-image/raw-system-update/Hardened_NanoKVM_beta_2_buildroot_2023_11_2_security_Rev1_4_2_rust/rootfs.sd \
  build/system-updates
```

Validation:

- `cargo check`: passed.
- `corepack pnpm --dir web build`: passed.
- `scripts/validate-nanokvm-rootfs.sh` on the SD rootfs image: passed with
  `kvmapp version: 2.0.0`, `backend: rust`.
- `scripts/verify-update-metadata.sh`: `Verified OK`.
- `scripts/verify-system-update-metadata.sh`: `Verified OK`.

Generated app artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| App archive | `build/artifacts/hardened-nanokvm-kvmapp-2.0.0.tar.gz` | `acc2a60ffc11bbb751b185ed2b59d1fe6226f1921881fc941e39c4e0e117b989` |
| App metadata | `build/artifacts/latest.json` | `5a4b29ed5c7e663dbfcfe7e0929e54c52b6f84bf2ed2480b475bf0893a81954f` |
| App metadata signature | `build/artifacts/latest.json.sig` | `592ee3a1b11e772d084bbd215e7ce488e9ef68cb1250d3dab577b3ce9f3ce07f` |

Generated SD artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| SD image | `build/sd-image/Hardened_NanoKVM_beta_2_buildroot_2023_11_2_security_Rev1_4_2_rust.img` | `d5fb17a7550c9534b7b54926fc2c0ee9cde274ece7459704002ea735a08882d7` |
| Compressed SD image | `build/sd-image/Hardened_NanoKVM_beta_2_buildroot_2023_11_2_security_Rev1_4_2_rust.img.xz` | `eb8ed7195e731acfc874c6250f1e64974b02b96b14778645cf91f5a4f4dd3eed` |
| SD rootfs image | `build/sd-image/Hardened_NanoKVM_beta_2_buildroot_2023_11_2_security_Rev1_4_2_rust.rootfs.ext` | `07364d3fee1f543c7daa75625d4d03a361a57a971cc1404921d193d60924e75b` |

Generated raw system-update artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| Raw system-update archive | `build/system-updates/hardened-nanokvm-system-0.2.0-raw.1.tar.gz` | `a718b5546ffea67ebc8ead8ebd7c93f2278faa0d69a950264848acb99d9ac310` |
| System metadata | `build/system-updates/system-latest.json` | `0fa53649380dfcb5a65df66e2ddf1172cd14c1be63d1ec9085624ab6c2563129` |
| System metadata signature | `build/system-updates/system-latest.json.sig` | `9f835ca2e1b7ffe4844039cb2fe3f57f44b6dd35c23c6aefd638f01460a0357a` |

Raw manifest notes:

- base version: `2026-06-29-12-08-d88d58.img`
- kernel version: `5.10.4-tag-`
- source commit: `8fa6bd6`
- required staging free space: `2147483648` bytes
- raw writes:
  - ROOTFS `/dev/mmcblk0p2`, patched payload sha256
    `54480569cee2641e70d3825deba37696f041c7125c9e2329882e62af9f6c1b3e`
  - BOOT `/dev/mmcblk0p1`, payload sha256
    `cbaf57e5fbc3f0adb86a033beb5404e96cd26564481d42c56290dc7bc7942b78`

Publication:

- App release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2`
- System release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.2.0-raw.1`
- System stable channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`

Post-publish verification:

- `https://github.com/woffko/Hardened_NanoKVM/releases/latest/download/latest.json`
  returns app version `2.0.0` and points to `hardened-rust-beta-2`.
- `https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-stable/system-latest.json`
  returns system version `0.2.0-raw.1` and points to
  `hardened-system-0.2.0-raw.1`.
- Both downloaded metadata signatures verified with
  `kvmapp/system/keys/system-update-signing.pub.pem`.

## 2026-06-29: Beta 2.0.1 App/System Patch

Reason:

- device `10.0.87.41` with Preview Updates enabled did not see the newer app
  release because the preview channel metadata was stale;
- USB gadget MAC addresses can change after reboot because `S03usbdev` did not
  set deterministic NCM/RNDIS `dev_addr` and `host_addr` values;
- app updates replace `/kvmapp`, while the boot-time USB gadget script is run
  from `/etc/init.d`, so `S95nanokvm` now syncs the bundled `S03usbdev` into
  `/etc/init.d` on startup.

Device check before the 2.0.1 release:

- `10.0.87.41` login: `admin/admin1234`
- current app: `1.0.5`
- visible app update after republishing preview channel metadata: `2.0.0`
- current system: `0.1.4-raw.1`
- visible system update: `0.2.0-raw.1`
- device key: `c9cbd99715194c6c`

Code changes staged for the 2.0.1 release:

- application update checks compare preview and stable metadata and return the
  newer semantic app version;
- system update checks compare preview and stable metadata and return the newer
  raw system version;
- `S03usbdev` derives stable locally-administered USB MACs from `/device_key`
  with fallbacks to `/etc/machine-id`, CPU serial, and a fixed seed;
- SD image patching now installs the bundled `S03usbdev` into `/etc/init.d`;
- rootfs validation now requires both bundled and boot-time `S03usbdev`.

Validation before build:

- `sh -n kvmapp/system/init.d/S03usbdev`: passed.
- `sh -n kvmapp/system/init.d/S95nanokvm`: passed.
- `sh -n scripts/build-rust-sd-image.sh`: passed.
- `sh -n scripts/validate-nanokvm-rootfs.sh`: passed.
- `cargo test --manifest-path server-rust/Cargo.toml`: passed.
- `corepack pnpm --dir web build`: passed.

Planned release tags:

- app: `hardened-rust-beta-2.0.1`
- system: `hardened-system-0.2.1-raw.1`
- stable app latest: GitHub Releases latest points to app `2.0.1`
- preview app latest: `hardened-rust-preview` will be updated to app `2.0.1`
- stable and preview system metadata will be updated to `0.2.1-raw.1`
