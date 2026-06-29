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
- latest committed baseline before build trace updates:
  `6c97121 Document Buildroot sysupgrade feasibility`

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

1. Commit the repository-side helper/docs updates.
2. Run the vendor SDK stock build against the patched checkout.
3. Build current web/Rust app artifacts from this branch.
4. Inject the app into the patched SDK SD image.
5. Extract `boot.vfat` and `rootfs.sd`.
6. Validate rootfs with `scripts/validate-nanokvm-rootfs.sh`.
7. Package raw system-update bundle with a new experimental system version.
8. Generate metadata/signature if publishing through GitHub release channel.
9. Record artifact paths, sizes, hashes, and any build failures here.

Risk notes:

- This is a lab raw update. It writes raw `/dev/mmcblk0p1` and
  `/dev/mmcblk0p2`.
- Recovery is SD-card rewrite, not automatic rollback.
- Kernel is still the vendor 5.10 tree; no kernel security rebase is included in
  this first bundle.
