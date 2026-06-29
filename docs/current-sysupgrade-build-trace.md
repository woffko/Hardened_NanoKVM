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

1. Publish versioned release `hardened-system-0.1.3-raw.1` with the raw bundle
   and system metadata.
2. Update the stable channel release `hardened-system-stable` so GUI update
   checks see `system-latest.json`.
3. Test the GUI update check/install on a sacrificial NanoKVM with raw updates
   explicitly enabled and SD-card recovery available.
4. Record device-side installer logs and outcome here.

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
  0.1.3-raw.1 \
  sg2002-licheervnano-sd \
  build/sd-image/raw-system-update/Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust/boot.vfat \
  build/sd-image/raw-system-update/Hardened_NanoKVM_1_0_5_buildroot_2023_11_2_security_Rev1_4_2_rust/rootfs.sd \
  build/system-updates
```

Bundle artifacts:

| Artifact | Path | Size | SHA256 |
| --- | --- | ---: | --- |
| Raw system-update archive | `/home/w0w/Hardened_NanoKVM-new-buildroot/build/system-updates/hardened-nanokvm-system-0.1.3-raw.1.tar.gz` | 225M | `671a202d93c9ed0df78d701daa9f1262b147baabd9ac8276496ed4b3bf8a7d12` |
| Metadata | `/home/w0w/Hardened_NanoKVM-new-buildroot/build/system-updates/system-latest.json` | 762 bytes | `0432ce2d36a40ce4923fdb87e78f89adca92ebcdb5960df73ef98843c33ef65f` |
| Metadata signature | `/home/w0w/Hardened_NanoKVM-new-buildroot/build/system-updates/system-latest.json.sig` | 384 bytes | `69f9f0120747cd24888abe240ffd99d7642fd4006f62928530cc54ab8f40f50a` |

Bundle manifest notes:

- Version: `0.1.3-raw.1`
- Target: `sg2002-licheervnano-sd`
- Required staging free space: `2147483648` bytes.
- Raw writes:
  - `/dev/mmcblk0p2` from `images/rootfs.sd`
  - `/dev/mmcblk0p1` from `images/boot.vfat`
- Bundle script patches `/etc/kvm/system-version.json` into the rootfs copy
  before archiving, so the rootfs hash inside the archive is:
  `741d4e0529c6d0c3b22ec1f2956c88a629c0af2c27ba7f333090afe24b0a1069`.

Metadata signing:

```sh
SYSTEM_UPDATE_SIGNING_KEY=/home/w0w/Hardened_NanoKVM/build/release/system-update-signing-test.pem \
SYSTEM_UPDATE_SIGNATURE_KEY_ID=hardened-system-test \
scripts/create-system-update-metadata.sh \
  0.1.3-raw.1 \
  hardened-system-0.1.3-raw.1 \
  build/system-updates/hardened-nanokvm-system-0.1.3-raw.1.tar.gz \
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

Risk notes:

- This is a lab raw update. It writes raw `/dev/mmcblk0p1` and
  `/dev/mmcblk0p2`.
- Recovery is SD-card rewrite, not automatic rollback.
- Kernel is still the vendor 5.10 tree; no kernel security rebase is included in
  this first bundle.
