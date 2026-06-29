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
