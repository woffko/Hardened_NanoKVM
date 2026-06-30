# Current Sysupgrade Build Trace

This file is the local handoff/trace for the active experimental system-update
build. Keep it updated before long-running builds or risky device operations.

## 2026-06-30: IPv6 Controls + DHCPv6 Client for App/Raw Rebuild

Goal:

- add explicit IPv6 control in the Hardened GUI instead of allowing IPv6 to run
  implicitly in the background;
- default IPv6 to Disabled on Hardened-managed devices;
- support SLAAC, DHCPv6, and Manual IPv6 modes for local networks that need
  managed IPv6;
- include the same IPv6 stack in the app archive, raw system-update bundle, and
  SD-card image.

Implementation status:

- app version bumped locally to `2.0.9`;
- added `GET/POST /api/network/ipv6` in the Rust backend;
- added Settings > Network > IPv6 panel with Disabled/SLAAC/DHCPv6/Manual;
- added `/boot/eth.ipv6.mode` and `/boot/eth.ipv6` persistence;
- `S30eth` now applies IPv4 and IPv6 separately and defaults missing IPv6 mode
  to Disabled;
- bundled RISC-V BusyBox `udhcpc6` at `/kvmapp/system/bin/udhcpc6`;
- added `/kvmapp/system/network/udhcpc6.script`, a DHCPv6 hook that avoids the
  stock script's IPv4 reset behavior.

Validation so far:

- `sh -n kvmapp/system/init.d/S30eth`: passed.
- `sh -n kvmapp/system/init.d/S95nanokvm`: passed.
- `sh -n kvmapp/system/network/udhcpc6.script`: passed.
- `cargo fmt --manifest-path server-rust/Cargo.toml`: passed.
- `cargo check --manifest-path server-rust/Cargo.toml`: passed.
- `cargo test --manifest-path server-rust/Cargo.toml`: passed, 115 tests.
- `corepack pnpm --dir web exec tsc --noEmit`: passed.
- `corepack pnpm --dir web build`: passed.

Final generated artifacts after commit `59bc8dd`:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| App archive | `build/artifacts/hardened-nanokvm-kvmapp-2.0.9.tar.gz` | `d64c3ba4f36a56e80bee7c254261e201bda17ee70a3a864abdfd001612382fb5` |
| App metadata | `build/artifacts/latest.json` | `a779428aea93ea7c78f841be678e6b2ec96b8c71045e31111fb6916d4f134de2` |
| App metadata signature | `build/artifacts/latest.json.sig` | `5ab94cc012a9a4af6e3b5ad93e470b357347d537f92096421bf5d1ed879235b0` |
| SD image | `build/sd-image/Hardened_NanoKVM_beta_2_0_9_buildroot_2023_11_2_security_ipv6_Rev1_4_2_rust.img` | `563292d151dcc2f9351954892b7b9775d9213ac89f34895893a042a68f96f3e1` |
| Compressed SD image | `build/sd-image/Hardened_NanoKVM_beta_2_0_9_buildroot_2023_11_2_security_ipv6_Rev1_4_2_rust.img.xz` | `4534e7bef92077926ec12efd528166c05efea58f8822df77c0b40c735c08f1ce` |
| SD/rootfs validation image | `build/sd-image/Hardened_NanoKVM_beta_2_0_9_buildroot_2023_11_2_security_ipv6_Rev1_4_2_rust.rootfs.ext` | `724b51ef22da45738abbf9ee72e8281954cb08580d3cd72f5c5eec75d548eb94` |
| Raw boot image | `build/sd-image/raw-system-update/Hardened_NanoKVM_beta_2_0_9_buildroot_2023_11_2_security_ipv6_Rev1_4_2_rust/boot.vfat` | `cbaf57e5fbc3f0adb86a033beb5404e96cd26564481d42c56290dc7bc7942b78` |
| Raw rootfs before bundle patch | `build/sd-image/raw-system-update/Hardened_NanoKVM_beta_2_0_9_buildroot_2023_11_2_security_ipv6_Rev1_4_2_rust/rootfs.sd` | `724b51ef22da45738abbf9ee72e8281954cb08580d3cd72f5c5eec75d548eb94` |
| Raw rootfs inside bundle | `payload/images/rootfs.sd` | `66df01ceb0d97a7d8cc8e7b16049b2d07009b6ea38b03349dcfe1e42f98fbf02` |
| Raw system update | `build/system-updates/hardened-nanokvm-system-0.2.5-raw.1.tar.gz` | `1eb1e6a52cbde814d3b30629f3b63c6866d6acb2c6efcae3073ce7906f082dfb` |
| System metadata | `build/system-updates/system-latest.json` | `95168b992519300db07b25220eb1cc03e3ada714ade8d495b465515dc7c96f36` |
| System metadata signature | `build/system-updates/system-latest.json.sig` | `b064a4dca34ac4ae3a69ec23b0e5499427263a5fb90e7c681ed3561af6587074` |

Signature checks:

- `openssl dgst -sha256 -verify ... build/artifacts/latest.json`: verified OK.
- `openssl dgst -sha256 -verify ... build/system-updates/system-latest.json`:
  verified OK.

Manifest source commit:

- App archive `MANIFEST.txt`: `source: 59bc8dd`.
- Raw system manifest: `source_commit: 59bc8dd`.

Device note:

- On `10.0.87.132`, pre-fix Disabled and SLAAC tests worked.
- A pre-fix DHCPv6 test used the stock BusyBox udhcpc hook, which reset IPv4
  on `deconfig`; HTTP/SSH then became unreachable (`No route to host`/connect
  failure).
- Do not repeat DHCPv6 device testing until the fixed `S30eth`,
  `/kvmapp/system/bin/udhcpc6`, and `/kvmapp/system/network/udhcpc6.script`
  are installed on the device after it is restored/rebooted.

Next steps:

1. After the user restores/reboots `10.0.87.132`, validate the fixed DHCPv6
   flow on hardware.

Publication:

- App release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.9`
- Raw system release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.2.5-raw.1`
- System stable channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`
- App preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-preview`
- System preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-preview`

Post-publication verification:

- All five release tags point at commit
  `47aac135a0f0aa533c5325b3f9d2b6831d26f71c`.
- Published `latest.json` and `system-latest.json` signatures verify OK with
  the bundled test public key.
- `https://github.com/woffko/Hardened_NanoKVM/releases/latest/download/latest.json`
  returns app `2.0.9`.
- `hardened-rust-preview/latest.json` returns app `2.0.9`.
- `hardened-system-preview/system-latest.json` returns raw system
  `0.2.5-raw.1`.

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

Build commands completed:

```sh
NANOKVM_SYSROOT_LIB=/home/w0w/Hardened_NanoKVM/server-rust/sysroot/lib \
  server-rust/scripts/build-linked-libkvm.sh
corepack pnpm --dir web build
RUST_TARGET=riscv64gc-unknown-linux-musl \
APP_VERSION=2.0.1 \
ARTIFACT_NAME=hardened-nanokvm-kvmapp-2.0.1.tar.gz \
KVM_SYSTEM_SOURCE=/home/w0w/Hardened_NanoKVM/build/kvmapp-rust/kvmapp/kvm_system/kvm_system \
  scripts/package-rust-kvmapp.sh
APP_UPDATE_SIGNING_KEY=/home/w0w/Hardened_NanoKVM/build/release/system-update-signing-test.pem \
APP_UPDATE_SIGNATURE_KEY_ID=hardened-system-test \
  scripts/create-update-metadata.sh \
  2.0.1 \
  hardened-rust-beta-2.0.1 \
  build/artifacts/hardened-nanokvm-kvmapp-2.0.1.tar.gz \
  build/artifacts/latest.json
NANOKVM_BASE_IMAGE=/home/w0w/Hardened_NanoKVM/build/vendor/LicheeRV-Nano-Build/install/soc_sg2002_licheervnano_sd/images/2026-06-29-12-08-d88d58.img \
SD_IMAGE_BASENAME=Hardened_NanoKVM_beta_2_0_1_buildroot_2023_11_2_security_Rev1_4_2_rust \
HARDENED_RELEASE_VERSION=2.0.1 \
  make sd-image
scripts/extract-sd-raw-images.sh \
  build/sd-image/Hardened_NanoKVM_beta_2_0_1_buildroot_2023_11_2_security_Rev1_4_2_rust.img \
  build/sd-image/raw-system-update/Hardened_NanoKVM_beta_2_0_1_buildroot_2023_11_2_security_Rev1_4_2_rust
BASE_VERSION=2026-06-29-12-08-d88d58.img \
KERNEL_VERSION=5.10.4-tag- \
  scripts/create-raw-system-update-bundle.sh \
  0.2.1-raw.1 \
  sg2002-licheervnano-sd \
  build/sd-image/raw-system-update/Hardened_NanoKVM_beta_2_0_1_buildroot_2023_11_2_security_Rev1_4_2_rust/boot.vfat \
  build/sd-image/raw-system-update/Hardened_NanoKVM_beta_2_0_1_buildroot_2023_11_2_security_Rev1_4_2_rust/rootfs.sd \
  build/system-updates
SYSTEM_UPDATE_SIGNING_KEY=/home/w0w/Hardened_NanoKVM/build/release/system-update-signing-test.pem \
SYSTEM_UPDATE_SIGNATURE_KEY_ID=hardened-system-test \
  scripts/create-system-update-metadata.sh \
  0.2.1-raw.1 \
  hardened-system-0.2.1-raw.1 \
  build/system-updates/hardened-nanokvm-system-0.2.1-raw.1.tar.gz \
  build/system-updates/system-latest.json
```

Validation after build:

- `scripts/verify-update-metadata.sh`: `Verified OK`.
- `scripts/verify-system-update-metadata.sh`: `Verified OK`.
- `make sd-image` rootfs validation: passed.

Generated app artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| App archive | `build/artifacts/hardened-nanokvm-kvmapp-2.0.1.tar.gz` | `3c832e9a50ba83d645f1a20056ee75df5070cd74a55c7dd62cfeb3dbf251bf6d` |
| App metadata | `build/artifacts/latest.json` | `713b9266bd143e109b42e4b666eaf66fff012f4476bc93a98d244536a43b4db8` |
| App metadata signature | `build/artifacts/latest.json.sig` | `2e96826aeebe331772469d1409fcf770db1fb7a1395702fe292f2fe892f8bafc` |

Generated SD artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| SD image | `build/sd-image/Hardened_NanoKVM_beta_2_0_1_buildroot_2023_11_2_security_Rev1_4_2_rust.img` | `6e2eacac921b54d6fd5878196ac8b6c1244f244923dc5390f738152f3550c3b8` |
| Compressed SD image | `build/sd-image/Hardened_NanoKVM_beta_2_0_1_buildroot_2023_11_2_security_Rev1_4_2_rust.img.xz` | `2a775f81de34ef126d5f491c467741f169269e994b993bdc316de1ef56c93282` |
| SD/rootfs payload | `build/sd-image/Hardened_NanoKVM_beta_2_0_1_buildroot_2023_11_2_security_Rev1_4_2_rust.rootfs.ext` | `d73b8d23989f7797deb96e73b0f0816054bed47f63877336c1315386b48e79cd` |

Generated raw system-update artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| Raw system-update archive | `build/system-updates/hardened-nanokvm-system-0.2.1-raw.1.tar.gz` | `aed90c1b63ab0c407f9154214b70defef3916da1220c51be6a1714eaf76f7a6d` |
| System metadata | `build/system-updates/system-latest.json` | `65538d3972646ac3c682fa2b028689efb78e7e35df4adf290c8add0e2b67608e` |
| System metadata signature | `build/system-updates/system-latest.json.sig` | `9bf6c8a4ca282301ca9b69d2bbe5661eabbf7ea6a9880e9d13531fbe32218840` |

Raw manifest notes:

- base version: `2026-06-29-12-08-d88d58.img`
- kernel version: `5.10.4-tag-`
- source commit: `f21155c`
- raw writes:
  - BOOT `/dev/mmcblk0p1`, payload sha256
    `cbaf57e5fbc3f0adb86a033beb5404e96cd26564481d42c56290dc7bc7942b78`
  - ROOTFS `/dev/mmcblk0p2`, payload sha256
    `d73b8d23989f7797deb96e73b0f0816054bed47f63877336c1315386b48e79cd`

Publication:

- App release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.1`
- System release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.2.1-raw.1`
- System stable channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`
- App preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-preview`
- System preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-preview`

Post-publish verification:

- `https://github.com/woffko/Hardened_NanoKVM/releases/latest/download/latest.json`
  returns app version `2.0.1` and points to `hardened-rust-beta-2.0.1`.
- `https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-rust-preview/latest.json`
  returns app version `2.0.1`.
- `https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-stable/system-latest.json`
  returns system version `0.2.1-raw.1`.
- `https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-preview/system-latest.json`
  returns system version `0.2.1-raw.1`.
- Downloaded GitHub app `latest.json` signature verified with
  `scripts/verify-update-metadata.sh`: `Verified OK`.
- Downloaded GitHub system `system-latest.json` signature verified with
  `scripts/verify-system-update-metadata.sh`: `Verified OK`.
- Device `10.0.87.41` now reports app `current=1.0.5`, `latest=2.0.1`.
- Device `10.0.87.41` now reports system `current=0.1.4-raw.1`,
  `latest=0.2.1-raw.1`, `updateAvailable=true`.

## 2026-06-29: Beta 2.0.2 Startup Boot-Script Sync

Reason:

- `2.0.1` fixed stable USB MAC generation in `S03usbdev`, but an ordinary
  application update on an already-flashed device only replaces `/kvmapp`;
- the boot-time scripts actually run from `/etc/init.d`, so devices with an old
  `/etc/init.d/S95nanokvm` could install app `2.0.1` without copying the new
  `S03usbdev` into `/etc/init.d`;
- Rust backend startup now syncs `/kvmapp/system/init.d/S03usbdev` and
  `/kvmapp/system/init.d/S95nanokvm` into `/etc/init.d` after an app update.

Validation before build:

- `cargo test --manifest-path server-rust/Cargo.toml`: passed.
- `corepack pnpm --dir web build`: passed.
- `sh -n kvmapp/system/init.d/S03usbdev`: passed.
- `sh -n kvmapp/system/init.d/S95nanokvm`: passed.

Generated app artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| App archive | `build/artifacts/hardened-nanokvm-kvmapp-2.0.2.tar.gz` | `ee9f23333510d59eafaa164f9cf8c1f77b247241ffea8261687a7206a7aad55b` |
| App metadata | `build/artifacts/latest.json` | `da0eafa991b578c798396348c9d37ee6eb15a556a1120544ea1be76fad2f0d04` |
| App metadata signature | `build/artifacts/latest.json.sig` | `9996aaea2e1f4951fabb087597f8ef12fcc7001bc56da10450d47417b0fa9d51` |

Generated SD artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| SD image | `build/sd-image/Hardened_NanoKVM_beta_2_0_2_buildroot_2023_11_2_security_Rev1_4_2_rust.img` | `c3c9f2fbbad5c9c608582cafe7c1325a2dadc41f7444d62917d8bc84eff96d2b` |
| Compressed SD image | `build/sd-image/Hardened_NanoKVM_beta_2_0_2_buildroot_2023_11_2_security_Rev1_4_2_rust.img.xz` | `32dcd3d674fe2de0f3474867636423af5744551b3cdf029de161d8f3498fe016` |
| SD/rootfs payload | `build/sd-image/Hardened_NanoKVM_beta_2_0_2_buildroot_2023_11_2_security_Rev1_4_2_rust.rootfs.ext` | `c9aedd65788668ec7572217e446062fe06ce5cc995866e22e377e343def01f46` |

Generated raw system-update artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| Raw system-update archive | `build/system-updates/hardened-nanokvm-system-0.2.2-raw.1.tar.gz` | `b68cff2527b99baf23dd8970c19c082f14ccb40a69f9755d3877236ba3325c98` |
| System metadata | `build/system-updates/system-latest.json` | `9e7698462c1f8503e76a505c664fdb20e56cd503a20edf8ab28c1b6c78bd1b5e` |
| System metadata signature | `build/system-updates/system-latest.json.sig` | `3fdaabd107b11e425900fb78731a37d621ba5af1ff3d4a3282502f6f26789aed` |

Raw manifest notes:

- base version: `2026-06-29-12-08-d88d58.img`
- kernel version: `5.10.4-tag-`
- source commit: `8dc8d31`
- raw writes:
  - BOOT `/dev/mmcblk0p1`, payload sha256
    `cbaf57e5fbc3f0adb86a033beb5404e96cd26564481d42c56290dc7bc7942b78`
  - ROOTFS `/dev/mmcblk0p2`, payload sha256
    `c9aedd65788668ec7572217e446062fe06ce5cc995866e22e377e343def01f46`

Publication:

- App release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.2`
- System release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.2.2-raw.1`
- System stable channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`
- App preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-preview`
- System preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-preview`

Post-publish verification:

- `https://github.com/woffko/Hardened_NanoKVM/releases/latest/download/latest.json`
  returns app version `2.0.2` and points to `hardened-rust-beta-2.0.2`.
- `https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-rust-preview/latest.json`
  returns app version `2.0.2`.
- `https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-stable/system-latest.json`
  returns system version `0.2.2-raw.1`.
- `https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-preview/system-latest.json`
  returns system version `0.2.2-raw.1`.
- Downloaded GitHub app `latest.json` signature verified with
  `scripts/verify-update-metadata.sh`: `Verified OK`.
- Downloaded GitHub system `system-latest.json` signature verified with
  `scripts/verify-system-update-metadata.sh`: `Verified OK`.
- Device `10.0.87.41` now reports app `current=1.0.5`, `latest=2.0.2`.
- Device `10.0.87.41` now reports system `current=0.1.4-raw.1`,
  `latest=0.2.2-raw.1`, `updateAvailable=true`.

## 2026-06-29: Beta 2.0.3 Stale Staged System Update UI Fix

Reason:

- device `10.0.87.133` was on app `2.0.2` and system page showed an old
  staged raw update `0.1.3-raw.1` with `Install`;
- latest GitHub system metadata was already correct at `0.2.2-raw.1`;
- the displayed error `forbidden: raw partition system updates are disabled`
  was an old failed progress marker from pressing Install before raw updates
  were enabled;
- the UI did not compare staged archive/version/hash against latest metadata,
  so stale staged packages could keep taking precedence over Download/Verify.

Fix:

- app version bumped to `2.0.3`;
- system-update install progress records the staged version;
- UI treats staged system updates as installable only when version, archive
  name, and sha256 match the latest GitHub metadata;
- if a newer system update exists, the failed/staged screen now offers
  Download and Verify instead of Install for the stale staged package.

Validation:

- `cargo test --manifest-path server-rust/Cargo.toml`: passed.
- `corepack pnpm --dir web build`: passed.
- app metadata signature verified locally and after GitHub publication:
  `Verified OK`.

Generated app artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| App archive | `build/artifacts/hardened-nanokvm-kvmapp-2.0.3.tar.gz` | `18270060fcdbebec6f1b9e69e5bab147a975d4e5f59a9448181d17ec27fbb160` |
| App metadata | `build/artifacts/latest.json` | `81587eaa0edd0484e8c8548d4adeb11010af3d3b974dbd52196da81af41576fc` |
| App metadata signature | `build/artifacts/latest.json.sig` | `5f145fa6a2597c9676a1541397697cfcddf01595d7ce1eef6575a8a5f44c15f7` |

Publication:

- App release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.3`
- App preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-preview`
- System stable/preview remain at `0.2.2-raw.1`.

Device check:

- `10.0.87.133` app before installing `2.0.3`: `current=2.0.2`,
  `latest=2.0.3`.
- `10.0.87.133` system check: `current=0.0.0-stock`,
  `latest=0.2.2-raw.1`, `updateAvailable=true`.

## 2026-06-29: Beta 2.0.4 Legacy Failed-Progress Cleanup

Reason:

- another device on app `2.0.3` still displayed
  `forbidden: raw partition system updates are disabled` even with the raw
  update toggle enabled;
- root cause was a legacy `install/failed` progress record written by older
  builds before raw updates were enabled, not the current raw-update setting;
- the app `2.0.3` UI already showed Download and Verify for newer metadata, but
  it still displayed the stale failed-progress message.

Fix:

- app version bumped to `2.0.4`;
- Rust status normalization clears legacy `install/failed` progress records
  that have no staged version;
- UI hides stale failed-progress text when a newer system update can be
  downloaded and verified.

Validation:

- `cargo test --manifest-path server-rust/Cargo.toml`: passed.
- `corepack pnpm --dir web build`: passed.
- app metadata signature verified locally and after GitHub publication:
  `Verified OK`.

Generated app artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| App archive | `build/artifacts/hardened-nanokvm-kvmapp-2.0.4.tar.gz` | `ac6e8dbf248503f3cb1cb4887af8b9d6024674e13669391ff635f46751026483` |
| App metadata | `build/artifacts/latest.json` | `9a52e6b29c352cdb7b55c634c0106c67010428d05b752c97e43aec23ed7db980` |
| App metadata signature | `build/artifacts/latest.json.sig` | `918a65854af8129a2e30d8f50262f26dee36517cf5d0583d52a5bae825581d3f` |

Publication:

- App release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.4`
- App preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-preview`
- System stable/preview remain at `0.2.2-raw.1`.

Device check:

- `10.0.87.133` app after installing `2.0.3`: `current=2.0.3`,
  `latest=2.0.4`.
- `10.0.87.133` Download and Verify completed for system `0.2.2-raw.1`;
  status now shows staged `0.2.2-raw.1` and `progress=null`.
- `10.0.87.133` app was then updated to `2.0.4`; final check reports
  app `current=2.0.4`, `latest=2.0.4`, staged system `0.2.2-raw.1`,
  and `progress=null`.

## 2026-06-29: Local WIP Manual Network Settings and Stable eth0 MAC

Scope:

- no releases, no GitHub publication, no device writes in this step;
- local working-tree changes only.

Implemented locally:

- Network/DNS settings Manual mode now edits full wired network settings:
  IP address, subnet mask, router, and DNS servers.
- The existing `POST /api/network/dns` endpoint now accepts optional
  `interface`, `address`, `subnetMask`, and `gateway` fields when
  `mode=manual`.
- Manual mode persists static Ethernet config to `/boot/eth.nodhcp`, matching
  the existing vendor `S30eth` boot mechanism.
- Applying Manual mode restarts `/etc/init.d/S30eth`; if the browser loses the
  HTTP response because the IP changed, the UI still redirects to the entered
  address.
- Switching back to DHCP removes `/boot/eth.nodhcp`, restarts `S30eth`, and
  preserves the previous manual DNS list for later.
- The Rust backend now syncs `/kvmapp/system/init.d/S30eth` into `/etc/init.d`
  at startup, same as `S03usbdev` and `S95nanokvm`.
- `S95nanokvm` also installs the bundled `S30eth` boot script.
- `S30eth` now creates/uses `/boot/eth.mac` and applies that locally
  administered MAC to `eth0` before DHCP/static configuration. This targets the
  wired MAC changing on every reboot; USB gadget MACs were already handled by
  `S03usbdev`.

Validation:

- `cargo fmt --check`: passed.
- `cargo check`: passed.
- `corepack pnpm --dir web run build`: passed.
- Prettier check for touched web files: passed.
- `sh -n kvmapp/system/init.d/S30eth`: passed.
- `sh -n kvmapp/system/init.d/S95nanokvm`: passed.

Initial mistaken device check:

- `http://10.0.87.47/`: TCP connection refused.
- `https://10.0.87.47/`: TCP connection refused.
- `ssh root@10.0.87.47`: TCP connection refused.
- Earlier ICMP ping from outside the sandbox succeeded, so the address is
  reachable at IP level but no expected NanoKVM services are listening from
  this environment.

Corrected device diagnostic:

- device is `10.0.87.48`, not `.47`;
- HTTP is reachable, HTTPS is disabled/refused;
- web login `admin/admin1234` succeeded;
- SSH `root/admin1234` succeeded via askpass;
- current app: `2.0.4`;
- current system: `0.2.2-raw.1`, base `2026-06-29-12-08-d88d58.img`;
- hostname: `secondary`;
- `/api/network/dns` reports DHCP mode, `eth0`, `10.0.87.48/24`,
  router/DNS `10.0.87.5`, search domain `int`;
- installed `/etc/init.d/S30eth` and `/kvmapp/system/init.d/S30eth` do not
  contain the local stable-eth0-MAC fix yet;
- `/boot/eth.mac` is absent and `/boot/eth.nodhcp` is absent;
- `/device_key` is `e192d5a315195372`, `/etc/machine-id` is empty;
- current runtime `eth0` MAC is `e2:2e:7a:43:22:9c`;
- the local WIP stable-MAC algorithm would derive `02:a1:a9:62:76:d7` for
  this device from `/device_key`.

## 2026-06-29: Beta 2.0.5 Network/MAC Fix Release

Scope:

- app release, raw system update, and SD-card image all include the Manual
  network settings and stable `eth0` MAC fixes;
- release was published from commit
  `a154d2d Add manual network settings and stable eth0 MAC` on branch
  `feature/new-buildroot-sysupgrade-lab`.

Included fixes:

- Settings > Network/DNS Manual mode can edit and apply wired IP address,
  subnet mask, router, and DNS servers.
- Manual network settings are stored in `/boot/eth.nodhcp` and applied through
  `/etc/init.d/S30eth`.
- Switching back to DHCP removes `/boot/eth.nodhcp` and restarts Ethernet.
- `S30eth` now persists a locally administered `eth0` MAC in `/boot/eth.mac`
  and applies it before DHCP/static configuration.
- Rust backend syncs the bundled `S30eth` to `/etc/init.d/S30eth` at startup;
  SD/raw rootfs validation now requires both bundled and installed copies.

Validation before publication:

- `cargo fmt --check`: passed.
- `cargo test`: passed.
- `corepack pnpm --dir web run build`: passed.
- `sh -n` for touched shell scripts: passed.
- `git diff --check`: passed.
- Rootfs validation passed with `EXPECTED_KVMAPP_VERSION=2.0.5`.
- App and system update metadata signatures verified locally and after
  downloading the published metadata from GitHub.

Generated app artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| App archive | `build/artifacts/hardened-nanokvm-kvmapp-2.0.5.tar.gz` | `2ede03a071755a62e3292e0e0929e0044ac0658b3ed27823df7467dd6b27b7ad` |

Generated SD-card artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| SD image | `build/sd-image/Hardened_NanoKVM_beta_2_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust.img` | `c0cca617e4f87d3b4937f6c13c6e3da7ada4020218eb6a229a485e86ee6515f1` |
| Compressed SD image | `build/sd-image/Hardened_NanoKVM_beta_2_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust.img.xz` | `b7f285f02ce13fa876b7dd020662950f3b0f7acec571135a3752918e61317487` |
| Rootfs validation image | `build/sd-image/Hardened_NanoKVM_beta_2_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust.rootfs.ext` | `338b4debf369dc92e89a0dd9b72aec09783919bd1c7cfe4380748fa2c559b6cf` |

Generated raw system update artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| Raw system update | `build/system-updates/hardened-nanokvm-system-0.2.3-raw.1.tar.gz` | `744a187d818ef3fa96aeba1f08c3b51e1fd09f13a02c2d085e4a074fb8fb71cc` |

Raw system manifest:

- version: `0.2.3-raw.1`
- target: `sg2002-licheervnano-sd`
- base: `2026-06-29-12-08-d88d58.img`
- kernel: `5.10.4-tag-`
- source commit: `a154d2d`

Publication:

- App release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.5`
- Raw system release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.2.3-raw.1`
- System stable channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`
- App preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-preview`
- System preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-preview`

Notes:

- The raw manifest rootfs SHA differs from the SD rootfs validation image SHA
  because `create-raw-system-update-bundle.sh` patches
  `/etc/kvm/system-version.json` into the staged raw rootfs before packaging.
- Post-publication GitHub REST tag checks later failed from the local
  environment with DNS resolution errors for `api.github.com`; direct GitHub
  download URLs for app/system metadata succeeded and both downloaded
  signatures verified.

## 2026-06-29: Beta 2.0.6 Redirect/Cache Hotfix Release

Reason:

- after updating to app `2.0.5`, changing wired Manual IP from the GUI could
  leave the browser on the old address if the network-setting POST was
  interrupted by `S30eth` restarting Ethernet;
- one browser also kept returning to the login page after the app update, while
  another browser worked. Device API login/session checks were healthy, so the
  likely cause was stale browser state or a stale cached React shell;
- `10.0.87.133` also had a bad manually-entered DNS server
  `10.0.77.133`. It was corrected on-device to local router/DNS `10.0.87.5`
  over HTTPS.

Fix:

- app version bumped to `2.0.6`;
- Manual network Apply now schedules the browser redirect before waiting for
  the POST to finish, so navigation still happens if Ethernet restart cuts the
  request;
- backend security headers now add `Cache-Control: no-store, max-age=0` for
  `/` and `*.html`, not only `/api/*`, so browsers do not reuse stale
  `index.html` after app updates;
- old GitHub releases were intentionally not deleted. Channel releases
  `hardened-system-stable`, `hardened-rust-preview`, and
  `hardened-system-preview` remain because update checks depend on them.

Validation:

- `cargo fmt --check --manifest-path server-rust/Cargo.toml`: passed.
- `cargo test --manifest-path server-rust/Cargo.toml`: passed.
- `corepack pnpm --dir web run build`: passed.
- Prettier check for touched web file: passed.
- `git diff --check`: passed.
- Rootfs validation passed with `EXPECTED_KVMAPP_VERSION=2.0.6`.
- App and system update metadata signatures verified locally and after
  downloading the published metadata from GitHub.

Generated app artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| App archive | `build/artifacts/hardened-nanokvm-kvmapp-2.0.6.tar.gz` | `893933918298bad101cf3d8efe83ab3d66eddbc1b03b0f4d3fdde7946533a31d` |
| App metadata | `build/artifacts/latest.json` | `5362c40239a8d41ed5ebb44cd8deddc2c5af1ae5ba8b1f9c5e8f69f057306a13` |
| App metadata signature | `build/artifacts/latest.json.sig` | `a11ae96c371557345a2d9e10990953a58b9a42d877fa97fc30a29022e4dea44f` |

Generated SD-card artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| SD image | `build/sd-image/Hardened_NanoKVM_beta_2_0_6_buildroot_2023_11_2_security_Rev1_4_2_rust.img` | `7bf2007d93224401c29d41da9cf6818d45d0af2431a782fc81c6d27fbc5367ce` |
| Compressed SD image | `build/sd-image/Hardened_NanoKVM_beta_2_0_6_buildroot_2023_11_2_security_Rev1_4_2_rust.img.xz` | `338df3e1477984892986f3e7ae5ce491bf0cb2001d827863bd5212fd8e8f3752` |
| Rootfs validation image | `build/sd-image/Hardened_NanoKVM_beta_2_0_6_buildroot_2023_11_2_security_Rev1_4_2_rust.rootfs.ext` | `3f2f70e4315ac082823dee0a36440b6fb52ebbe7af9c8bf1529e8f44e7307e02` |

Generated raw system update artifacts:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| Raw system update | `build/system-updates/hardened-nanokvm-system-0.2.4-raw.1.tar.gz` | `a4faeafaf25ce6cbb1357f4318e34fa09d39bcded9fcaa1f8838cec89648e961` |
| System metadata | `build/system-updates/system-latest.json` | `ef51d82d79e399c6c7e2efc8713325d75feaca8047b9260d9a98aae1f42dd54f` |
| System metadata signature | `build/system-updates/system-latest.json.sig` | `a9b00667c3639195b0c15f32ee6d935eb39e32c3906e59f7dfb3fc10755b8d0e` |

Raw system manifest:

- version: `0.2.4-raw.1`
- target: `sg2002-licheervnano-sd`
- base: `2026-06-29-12-08-d88d58.img`
- kernel: `5.10.4-tag-`
- source commit: `33e8f3a`

Publication:

- App release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.6`
- Raw system release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.2.4-raw.1`
- System stable channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-stable`
- App preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-preview`
- System preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-preview`

Device check:

- `10.0.87.133` current app: `2.0.5`, latest app: `2.0.6`;
- `10.0.87.133` current system: `0.2.2-raw.1`, latest system:
  `0.2.4-raw.1`, `updateAvailable=true`;
- `10.0.87.133` network DNS after correction:
  mode `manual`, servers/effective/DHCP all `10.0.87.5`, address
  `10.0.87.133/24`, gateway `10.0.87.5`.

## 2026-06-29: Beta 2.0.7 App Auth-State Hotfix

Reason:

- `10.0.87.132` could log in successfully through the backend API, but the UI
  immediately returned to the login screen;
- protected API calls with the HttpOnly session cookie worked, so the backend
  session was valid;
- root cause was frontend auth state relying only on the JS-readable
  `nano-kvm-csrf` cookie. After IP/protocol changes or stale browser state, the
  CSRF cookie can be absent while the HttpOnly session cookie is still valid.

Fix:

- app version bumped to `2.0.7`;
- `GET /api/auth/account` now returns the current session CSRF token and
  expiry alongside the username;
- `ProtectedRoute` now checks `/api/auth/account` with credentials before
  redirecting to login when the CSRF cookie is missing. If the HttpOnly session
  is still valid, it restores the CSRF cookie and lets the UI continue;
- CSRF cookie writes/removes now explicitly use path `/` and `SameSite=Lax`.

Validation:

- `cargo fmt --check --manifest-path server-rust/Cargo.toml`: passed.
- `cargo test --manifest-path server-rust/Cargo.toml`: passed.
- `corepack pnpm --dir web run build`: passed.
- Prettier check for touched web files: passed.
- `git diff --check`: passed.
- `10.0.87.132` was repaired directly with a local offline app update package.
- After repair, `10.0.87.132` reports app `2.0.7`, and
  `/api/auth/account` returns `username`, `csrfToken`, and `expiresAt`.
- GitHub `latest.json` for app `2.0.7` downloaded successfully and its
  signature verified.

Generated app artifact:

| Artifact | Path | SHA256 |
| --- | --- | --- |
| App archive | `build/artifacts/hardened-nanokvm-kvmapp-2.0.7.tar.gz` | `f890f71f5a022e141055e986c4f75ece2d52145b01aa634641ed570c33b5d7e2` |

Publication:

- App release:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-beta-2.0.7`
- App preview channel:
  `https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-preview`

Notes:

- This was published as an app-only hotfix because the failure was in the
  browser/backend auth contract, not in boot/rootfs. The existing raw system
  channel remains at `0.2.4-raw.1`.
