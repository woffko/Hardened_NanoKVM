# Hardened NanoKVM Developer Handoff

Last updated: 2026-08-28

This document is the current takeover guide. Detailed chronological release and
device-recovery history was intentionally removed from the handoff and remains
available in:

- [`release-archive.md`](release-archive.md);
- [`current-sysupgrade-build-trace.md`](current-sysupgrade-build-trace.md);
- [`kvm-system-rust-migration-plan.md`](kvm-system-rust-migration-plan.md).
- [`security-maintenance-raw11.md`](security-maintenance-raw11.md).
- [`key-transition-2026q3.md`](key-transition-2026q3.md).
- [`rc12-final-physical-gates.md`](rc12-final-physical-gates.md).

## Repository And GitHub State

- Local checkout: `/home/w0w/Hardened_NanoKVM-new-buildroot`.
- GitHub repository: `woffko/Hardened_NanoKVM`.
- GitHub default branch: `main`.
- Current maintenance branch: `security/kernel-5.10.265`. Phase 3 batch 1
  reproducibility artifacts were built from outer commit
  `ebdaa1cae40b75aa9cc4f0987dedb4e0d700abf0`; batch 2 artifacts were built
  from `473baf95a0cb60f46b1ed0b21d7215b590c1ab7f`. The branch continues the
  accepted `security/raw11-userspace` work based on `latestbuilroot` commit
  `5288195deb62873e642c0d86b5e432683fd51bdf`.
  Commit `d5f480f` adds application `2.0.41` and guarded system-update metadata
  format 2. Runtime candidate commit `4ab8c4e` includes raw.10 update-key
  compatibility, explicit app-owned native-library packaging and RPATH-free
  native artifacts. Commit `4d46c8b` makes the bridge server install bundled
  public update trust on its first start; `ac12e2d` removes build-host paths
  from the reproducible app manifest. RC12 was published from release commit
  `8be6b4d` on `security/kernel-5.10.265`. `rc8-main-sync`, tracking
  `origin/main`, remains the previous mainline release-baseline branch.
- `latestbuilroot` is the experimental Buildroot `2026.05.1` board-port branch
  used for RC11. Raw/SD artifacts are published as preview only; the stable
  system channel remains on RC9. Keep recovery media and the restrictions in
  [`latest-buildroot-port.md`](latest-buildroot-port.md) in scope.
- `feature/rust-kvm-system-migration` is historical. Its validated work is in
  `main`; do not continue release work from that branch.
- Current source and published RC12 application version is bridge app `2.0.42`
  (`kvmapp/version`); the published RC12 system preview is `0.3.0-raw.12`.
- The production-key bridge plan is authoritative in
  [`key-transition-2026q3.md`](key-transition-2026q3.md). Corrected app `2.0.42`
  independently reproduces and passes the full immediate-trust, signature,
  reboot, SSH and browser matrix from app `2.0.41`/raw.11, app `2.0.40` on
  raw.12, and the exact published app `2.0.40`/raw.10 state on recoverable
  media. A restore-verified encrypted backup was copied off-host and re-hashed;
  all transition-release gates now pass.
- Current installed test state: `10.0.87.133` runs corrected bridge app
  `2.0.42`, production-key-signed system `0.3.0-raw.12`, kernel
  `5.10.265-tag-`, dual trust and the preserved SSH identity. `10.0.87.49` runs the same bridge app, system
  `0.3.0-raw.12`, kernel `5.10.265-tag-` and dual trust. Both passed exact
  post-reboot runtime and browser-account checks with zero kernel alerts.
- Physical recovery-card repeatability is accepted on a second NanoKVM. Two
  clean writes booted far enough to generate a new MAC, expand p2 and create
  p3; the accepted second boot used `10.0.87.60` / `02:4b:c9:fb:cc:5d` and
  passed first-account, HTTP/API, root SSH, storage/mount, network, Avahi,
  module, native-provenance and dmesg gates. The user waived repeating the
  HDMI/video/HID matrix on that unit; the full final-runtime matrix remains
  proven on `.133`.
- Current combined release: app `2.0.42 RC12` plus system `0.3.0-raw.12`, tag
  [`hardened-system-0.3.0-raw.12`](https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.3.0-raw.12),
  published from `8be6b4d` on 2026-08-28. Existing devices first install the
  manual
  [`2.0.42 key-transition prerelease`](https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-rust-2.0.42-key-transition),
  then enable Preview and install raw.12; the RC12 SD image already includes
  app `2.0.42`. All remote assets, both Preview channels and the GitHub latest
  metadata redirect match the accepted local artifacts. The retained remote
  acceptance report SHA-256 is
  `d70e156c865c28c340d39c9ec085cfc73d66b20360bce533db8ef6644ca43c9d`.
- Current stable raw/SD baseline: RC9 app `2.0.32`, raw system
  `0.2.23-raw.1`, tags `hardened-rust-rc9` and
  `hardened-system-0.2.23-raw.1`.
- GitHub Pages RC12 update: `gh-pages` commit `e4c8bfd`. Live HTML is
  byte-exact to the worktree and desktop/mobile Playwright acceptance passes;
  report SHA-256 values are
  `4d1294ce76d20b8c1d85f53ef475879ea47b3bbc5f2953d0a9fdf4e038b2ee6b`
  and `bddbfe352f53f96af80f62c8b4d2329f6a33030556547e0f1de25897c181eda3`.
- GitHub CLI is authenticated as `woffko`. A 2026-08-28 API check found nine
  open npm alerts on the default branch `web/pnpm-lock.yaml` (four high and five
  medium). RC12 pins versions outside every reported vulnerable range, and
  `corepack pnpm --dir web audit --prod --audit-level low` reports no known
  vulnerabilities. `Cargo.lock` contains patched `anyhow 1.0.103`.

Unpublished accepted raw.11 lab artifacts from runtime commit `4ab8c4e`:

| Purpose | Local path | SHA-256 |
| --- | --- | --- |
| app `2.0.41` archive installed on the test device | `build/artifacts/nanokvm-kvmapp-rust.tar.gz` | `c8520306d70b3c6998a486e84faf82f1a8509f7a97f621d14dfc34af368ae18d` |
| reproducible rootfs ext4 | `build/latestbuildroot/sg2002-config-2026.05.1-raw11-repro6/images/rootfs.ext2` | `afb1503063278fc8ab5cf1cb71cad4b3fbdd9f30bb762a81a34203406362b29b` |
| recovery SD image to write to a separate card | `build/latestbuildroot/sg2002-sd-image-2026.05.1-raw11-final-4ab8c4e/images/hardened-sg2002-port.img` | `3fcbc569ec414702dde116b3ed8690a37b1274cf4ab9b500bfeaad70c82e9756` |
| compressed recovery SD image | `build/latestbuildroot/sg2002-sd-image-2026.05.1-raw11-final-4ab8c4e/images/hardened-sg2002-port.img.xz` | `5155e6fa13d962fe0fd732f572cfa31d5e5dd936edab703bc60169ee5ae3157d` |
| unsigned production-preflight raw.11 bundle | `build/latestbuildroot/raw-system-update-0.3.0-raw.11-secure-final/unsigned-artifacts-4ab8c4e/hardened-nanokvm-system-0.3.0-raw.11.tar.gz` | `4a66e0393a665e6884aa17c64268cdfd1a37e97e6e11e738143dcf62f0cd9601` |

Write only the recovery SD image to sacrificial media. Do not attempt to feed
the unsigned bundle to the updater. In-place raw.11 hardware acceptance is
complete and physical recovery-card boot is repeatable. Explicit
metadata/manifest/signature failure tests pass; raw partition rollback is the
now-proven manual SD rewrite path, not an automatic partition rollback.
At that raw.11 checkpoint, production signing and redistribution remained; the
subsequent RC12 release completed both.

Historical combined RC11 release artifacts and SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| `hardened-nanokvm-kvmapp-2.0.40.tar.gz` | `85e6aa195ccf7274203462a0488c9e251c567a523519fd50d4973eb60ddd65d5` |
| `hardened-nanokvm-system-0.3.0-raw.10.tar.gz` | `e4d19f42305de9a3666ef7afb0a15000a857b742cfa58800037884c201c693db` |
| Buildroot `2026.05.1` SD image `.img.xz` | `96e44ee8eb482ba2609348164b8c80ac1b94a1c1152db328331fba799d5e0632` |
| uncompressed SD image | `2bfb0b2000786a6860f069b235fe6026fc8e77f7132f0f72e284e725246cb92e` |
| application metadata | `0ea6a80aae1072898118908ff523e4708809223198f20684363661ba9b07dbe6` |
| application detached signature | `d41d76509ce8e850309c79d9a0ce11e7bdeedc6488c2e6897672693841e80069` |
| system metadata | `9048e06c4b5cfb0689b57bac9606e09a70ea00b0d50defc38a19e92a0c18940a` |
| system detached signature | `3c0cb60003f9a0c201da0bbe473178220fc3a7ffafb8757c9f705fb7028c1a31` |

Published corrected bridge artifact:

| Artifact | SHA-256 |
| --- | --- |
| app `2.0.42` bridge archive | `aa0cd78c1b2e9951f216826c44b4b7ff2fb211fc1980540366f8f5b1f7e0dd20` |
| RISC-V Rust server | `fd116fc459a1961cfc16fd0c7077a8f4c5e24d8f32d8745fd3b9744217083d6d` |
| reproducibility report | `065c636e8c9e05c9fcbbe13313b6ee3d728c605e7fc252b6ffa69215ea5381c2` |

The retained pipeline-A archive is under
`build/key-transition-2.0.42-bootstrap/app-a/out/`. The old bridge archive
`e9c0bb08...` and all old RC12 rootfs/full-image hashes are superseded. RC12
rebuilt and repeated A/B, full-SD, signed-raw and recovery acceptance with the
corrected app.

RC10 was app-only. It did not change raw/system metadata or the SD image.
GitHub tag `hardened-rust-rc10` was published from
`26a2986d3080cb95557f06fde437c1de6189f491` as the latest release; its
signed application metadata has SHA-256
`d12c6aa8da087deaed3a9865d984afc6f140b9e9d12856427a89c614050a62f3` and
the detached signature has SHA-256
`f5913ae509672fd16c62468be71c251c8d08ff38978b2116a3434aed6a06c500`.
Those hashes remain historical RC10 evidence. The mutable
`hardened-rust-preview` now points to production-signed RC12 app `2.0.42`
metadata.

Pre-publication raw.10 lab artifacts retained for comparison:

| Artifact | SHA-256 |
| --- | --- |
| application archive `2.0.40` | `22dacfdb7627f0914cae201e53d353d96d12b9aa7d01d8f4c4ff9f68c9857ba3` |
| Buildroot rootfs ext4 | `0076f77cc71e788bdfb5ee584bdf19e66e14ce57b90d13a0631caa84f0295816` |
| Buildroot rootfs tar | `3be6fea121e8156da42071def3cd07a7f090ab6a7d23f261d83aff5fbffda1cf` |
| signed raw update | `bc01de0bc47de1a07fd931a7a50ecfbaf2b0848fa5588b386990daae0ec0314a` |
| full SD image | `7150f0c8a6b6aae82a09b68e1896189727e321175e0ca74aaf67311aa65e1333` |
| metadata | `966f494430b9d64f8018de5c01435f27cc5ce158e59fbf9b61aabbad1f4a9666` |
| detached signature | `a05877a9787966727586a8c81cc359931dc9985d1c01527233dbae8bd3ac2afd` |

The published RC11 artifacts were rebuilt/repackaged from the accepted payload
and release commit, so their outer archive and metadata hashes intentionally
differ from these lab hashes. All 16 GitHub assets were downloaded after
publication, matched `SHA256SUMS`, and both application/system metadata pairs
verified with the bundled public key. They remain historical RC11 evidence.
GitHub latest and `hardened-rust-preview` now advertise app `2.0.42`;
`hardened-system-preview` advertises raw `0.3.0-raw.12`; stable remains on
`0.2.23-raw.1`.

## Current Architecture

- The shipped web backend is Rust from `server-rust/`, installed as
  `/kvmapp/server/NanoKVM-Server`.
- Rust is the only supported web backend in the current project.
  Package/rootfs validation rejects stale alternate-backend artifacts.
- Rust still calls the native C ABI in `libkvm.so`; the video pipeline and
  CVI/MMF integration remain C/C++ in:
  - `support/sg2002/additional/kvm/`;
  - `support/sg2002/additional/kvm_mmf/`;
  - `support/sg2002/additional/vision/`;
  - `support/sg2002/additional/peripheral/`.
- Native runtime libraries are packaged from `server-rust/native/dl_lib` to
  `/kvmapp/server/dl_lib`.
- `kvm_system` remains a C++ helper for OLED drawing, button input, Wi-Fi OLED/AP
  provisioning, and hardware-compatible fallback behavior. It is not the web
  backend.
- `nanokvm-hwmon` supplies Rust-normalized passive USB, HDMI, stream, and
  network state. `S95nanokvm` enables Rust snapshot consumption by default when
  the helper is packaged.
- C++ passive readers can still act as compatibility fallback when the hwmon
  marker/snapshot is absent, stale, or malformed. Normal authenticated Wi-Fi
  reconnect is Rust/init-owned, but positive Wi-Fi and OLED AP provisioning
  still need validation on hardware with `wlan0`.
- The Rust server installs validated bundled public update trust atomically on
  its first start. `S95nanokvm` idempotently enforces the same trust state on
  later starts and owns runtime staging/start/stop, old app/image marker
  cleanup, init compatibility repair, and delayed hwmon startup.
- In-place root/web password reset was removed. Lost credentials require SD
  reflash/recovery rather than a network reset endpoint.

## Native C/C++ Audit

The 2026-07-11 review found native defects in the production video path and
retained helper. The current working tree addresses the complete finding list;
the original findings, code references, repair summary, and remaining hardware
coverage are in
[`native-code-audit.md`](native-code-audit.md).

Highest-priority findings (now addressed in the working tree):

1. HDMI detection can run `cam->restart()` concurrently with frame reads,
   deleting the camera implementation while it is in use.
2. `kvmv_deinit()` destroys the mutex and MMF/camera state without stopping and
   joining its internal threads.
3. H.264 VENC error paths contain dangling `pstPack` state, leaks, invalid
   release ordering, and possible double-free behavior.
4. `free_all_kvmv_data()` has a definite one-element out-of-bounds access.
5. Several HDMI/resolution readers overflow or read past fixed stack arrays.
6. NV21 H.264 stride copying uses `stride * h` instead of the loop row and
   corrupts frames when stride differs from width.
7. Automatic resolution detection busy-loops indefinitely with no HDMI signal.
8. Active LT6911 I2C reads dereference `nullptr` after transient I2C failures.
9. JPEG/H.264 output allocation and encoder failure results are not checked.
10. Retained `kvm_system` has shared-state races, button/OLED bugs, QR leaks,
    and an every-poll Wi-Fi status write that causes unnecessary SD activity.

Remediation status:

- all 26 recorded findings have source fixes in the current working tree;
- native libraries and `kvm_system` rebuild successfully with the target
  RISC-V toolchain, and the current linked Rust package passes all 154 tests;
- the rebuilt libraries were deployed to `10.0.87.133` and passed full reboot,
  authenticated MJPEG, H.264 Direct, and controlled backend stop/start tests;
- a stale vendor sensor-name table was also synchronized with the current
  MaixCDK enum; without that compatibility fix, a clean rebuild selects the
  wrong numeric sensor ID for LT6911 even though the log prints its name;
- HDMI source-mode changes and physical OLED/button coverage remain post-RC11
  follow-up limits; physical HDMI cable hotplug and the automated 30-minute
  video/dmesg/local-syslog endurance passed;
- `10.0.87.132` was not used.

## Test Devices

### Primary native test device: `10.0.87.133`

- Model used for validation: NanoKVM Cube.
- Hostname: `secondary`.
- Static network: `10.0.87.133/24`, gateway `10.0.87.5`; manual DNS is
  preserved from legacy `/boot/resolv.conf` and currently contains six unique
  servers recorded by the raw.9 network audit.
- Web and SSH test credentials are stored only in the encrypted Project Memory
  test asset. Stage its password field as one-time Longrun stdin; never place
  the value in commands, logs, docs, prompts, or source.
- HTTPS uses a local/self-signed certificate; automation must ignore the
  certificate warning explicitly.
- This is the required target for native C/C++, HDMI, MMF, virtual-media, OLED,
  and button validation.
- Read-only check on 2026-07-11: HTTPS health reported the Rust backend, app
  version was `2.0.32`, SSH login succeeded, and installed system version was
  `0.2.19-raw.1` on base `2026-06-29-12-08-d88d58.img`.
- Current automated-test state on 2026-08-28: production-key-signed system
  `0.3.0-raw.12`, Buildroot `2026.05.1`, corrected bridge app `2.0.42`, kernel
  `5.10.265-tag-`, HTTPS and SSH working, source-built media trio loaded,
  production and legacy public update trust installed, remote syslog active and
  online update checking clean. The corrected bridge was installed from a
  clean app `2.0.41`/raw.11 state and passed immediate trust deployment,
  production/historical signature checks, a full reboot and browser login.
  The exact production-signed raw.12 update then passed configuration restore,
  boot-good confirmation, an additional exact reboot, the complete software
  regression suite with five more reboots and a final exact freeze.
  Earlier complete-suite evidence includes the
  same-WebSocket H.264 mode-resume test, controlled runtime restart, watchdog
  recovery and five reboot cycles with backend `f1e3772a...`, RPATH-free
  `libkvm.so` `4f86642e...` and `libkvm_mmf.so` `c1b61ace...`. The final
  30-minute endurance passed 40 alternating MJPEG/H.264 cycles with zero new
  dmesg/syslog alerts. The current bridge server is `fd116fc4...`; the native
  binaries are unchanged. Physical HDMI cable unplug/replug was previously
  confirmed on raw.9 with the same native stack; source-mode switching was
  unavailable on the current source. Published RC12 is app `2.0.42`; raw.12
  remains on the system Preview channel and stable remains RC9.
- Vendor-kernel Phase 1 is reconstructed and accepted on recoverable media: the
  24-layer official/Milk-V/Sipeed source stack, clean Image/vmlinux, 3 DTBs,
  all 57 modules, and `boot.sd` are independently reproducible; all covered
  packaged hashes match the accepted `5.10.4-tag-` bytes. The unchanged
  baseline image was written to a SanDisk High Endurance card, booted, and
  obtained its router-assigned address. Any future `5.10.265` merge must still
  begin on recoverable media and must not be installed first by raw update.
  Details:
  [`vendor-kernel-5.10-security-plan.md`](vendor-kernel-5.10-security-plan.md).
  The accepted recoverable baseline image has SHA-256
  `2bfb0b2000786a6860f069b235fe6026fc8e77f7132f0f72e284e725246cb92e`
  under `build/latestbuildroot/recoverable-kernel-baseline-sd-v2/`.
- Vendor-kernel Phase 2 is complete through the kernel/device recovery boot
  gate on the dedicated `.48` unit described below. The initial stable merge's
  silent boot failure was a duplicate RISC-V `of_clk_init(NULL)` call; accepted
  source tree `d53dfbde34f1de6b4565e686009b688c04b8913d`, the tracked resolution
  patch series and the outer clock-init guard prevent recurrence. Two
  independent clean pipelines match
  exactly through kernel, 57 modules, Buildroot rootfs, FIT, full SD image and
  `.img.xz`. See
  [`kernel-5.10.265-recovery-candidate.md`](kernel-5.10.265-recovery-candidate.md).
- Vendor-kernel Phase 3 batch 1 enables only restricted unprivileged dmesg.
  Two complete clean pipelines from `ebdaa1c` match through the compressed SD
  image. The candidate xz SHA-256 is
  `cfd6ec4c1a7e70b28b5d91ea1fd3be4214b5bb9e807e36e8ebfbe867c69a6303`.
  Recovery boot, the root/unprivileged dmesg boundary and ten reboot cycles
  pass on `.47`, with 57 modules and zero kernel alerts after the final boot.
  Batch 1 is accepted. See
  [`kernel-5.10.265-phase3-dmesg-restrict.md`](kernel-5.10.265-phase3-dmesg-restrict.md).
- Vendor-kernel Phase 3 batch 2 retains restricted dmesg and disables user
  namespaces after source, rootfs and live-process consumer audits found no
  consumer. Two complete clean pipelines from `473baf9` match exactly through
  the compressed recovery image. Its SHA-256 is
  `b48376723aa30358809eb32600dfe85b0660b31a67b2a5ff7f0ab23afc4320bc`.
  Recovery boot at `.41`, exact running config/module/provenance identity and
  ten reboot cycles pass with zero kernel alerts. The prior batch-1 image was
  then booted at `.56` and passed its exact rollback identity/runtime gate.
  Batch 2 was restored at `.48` and passed its strengthened identity/runtime
  gate again. Batch 2 is accepted; batch 3 may begin as a separate
  slab-freelist hardening candidate. See
  [`kernel-5.10.265-phase3-userns-disable.md`](kernel-5.10.265-phase3-userns-disable.md).
- Vendor-kernel Phase 3 batch 3 adds only SLUB freelist randomisation and
  pointer hardening. A fresh Kconfig proof has no cascaded change. Two batch-2
  baseline runs at `.48` recorded medians of 680 ms and 650 ms with zero kernel
  alerts. Two clean full candidate pipelines from `97407be` match exactly
  through the compressed recovery image; its SHA-256 is
  `7294ac12a5d9719c03abf03c1d1516752ae2ac136ed76399c2185e8637c887c9`.
  Its first recovery boot stopped before p2 was ever mounted or network state
  created; exact boot files and pristine rootfs rule out a write/rootfs defect.
  Randomisation-only then passed exact runtime identity, both predeclared
  performance runs and ten reboot cycles at `.41`; pointer hardening remained
  disabled. Hardened-only independently failed to return after reboot and is
  rejected. The random-only FIT backup is under `/data/hardened-kernel-probes/`;
  physical restoration at `.41` passes. The canonical batch-3 fragment now
  selects only randomisation. Two final clean full pipelines from `06c8106`
  match exactly through the compressed recovery image; selected A xz SHA-256
  is `ad80ce703a46ec13c2388d3003b0c603091e81f579aedef93ab39670cccfebdb`.
  The batch-2 rollback and full-image final selected A boot now pass. The final
  image at `.45` matches rootfs commit `06c8106`, exact kernel/config/modules
  and provenance, expanded p2/p3 layout, two post-expansion software boots and
  zero kernel alerts. Batch 3 is accepted with randomisation enabled and
  pointer hardening rejected. The next separate kernel batch is
  init-on-allocation.
  Fixed limits, evidence and the accepted result are documented in
  [`kernel-5.10.265-phase3-slab-freelist.md`](kernel-5.10.265-phase3-slab-freelist.md).
- Phase 3 batch 4 enables only init-on-allocation. Its exact cross-toolchain
  Kconfig proof is one line, accepted batch-3 baseline medians are 670/670 ms,
  and the predeclared candidate limit is 770.5 ms. Two clean full pipelines from
  `f97d12d` are byte-exact through the compressed recovery image. Candidate
  medians are 680/700 ms; exact identity, functional runtime, ten reboots and
  exact rollback to batch 3 pass with zero alerts. `.45` is left on batch 3.
  Only the complete selected A recovery-image boot remains before kernel-scope
  freeze. HDMI/Wi-Fi/HID physical-matrix repetition was explicitly waived and
  is not claimed as new evidence. Init-on-free remains a later separate
  decision outside the next RC. See
  [`kernel-5.10.265-phase3-init-on-alloc.md`](kernel-5.10.265-phase3-init-on-alloc.md).
- The previous app `2.0.41` RC12 candidate and its accepted full image are now
  superseded for publication by the required signing-key transition. Their
  kernel evidence remains valid, but app/rootfs/raw/full-image hashes must be
  rebuilt and reaccepted.
- RC12 preparation is now pinned to bridge app `2.0.42`, system
  `0.3.0-raw.12`, kernel
  `5.10.265-tag-`, format-2 system metadata and
  `required_app_version=2.0.42`. The release scripts bind the full build commit,
  system manifest, signed metadata, SD image and publication commit separately.
  Preparation and publication refuse to proceed if the reviewed full-image
  blocker marker is present.
- Superseded RC12 pipelines A/B from build commit `34cb2cb` are byte-exact
  through the compressed full SD image. Selected A `.img.xz` is 33,779,072 bytes with
  SHA-256 `23df0435fb81d762fcc55483e7159cb7022e150dd03935d42f480671e1d3e546` at
  `build/latestbuildroot/kernel-5.10.265-rc12-release-a/recovery/assembly/images/hardened-sg2002-port.img.xz`.
  Duplicate B was removed after the retained strict comparison. Physical boot
  of selected A now passes at `.49`: exact initial identity/runtime, expanded
  partitions, two post-expansion reboot cycles and final runtime all pass with
  zero kernel alerts. This remains valid kernel/device evidence, but the image
  does not contain the corrected bridge server and must not be published. The
  kernel scope is frozen; fresh app/rootfs/full-image A/B pipelines are next.
- The superseded isolated unsigned raw.12 preflight passed the then-current
  `scripts/verify-rc12-raw-bundle.sh`; this is a retained historical result, not
  a PASS of today's signed-default verifier. Its 57,134,321-byte archive SHA-256 is
  `85f5a52be375456eef0acdc618a77219fc0de7d42675d05bc30ee82ec3969b1e`;
  the decompressed rootfs and boot payloads remain byte-exact to selected A at
  `a5254238d690cd963b2b0f663977211634c424d78fb5e30fa095d815ab5d7701`
  and `0d74f6acbd21499a181636afbcb3fc3d221734d3093df95cc42532c5f567864b`.
  Format 2 and
  `required_app_version=2.0.41` pass. This preflight is explicitly unsigned,
  requires the wrong bridge version and cannot be installed or published. The retained report SHA-256 is
  `5fa4a27dbdc93e2c429af0dd4d945d2adb6d659e1e50d9c9363b90fc17fe6358`.
  It is retained only as historical packaging evidence.
  Current verifier scope, signed defaults and explicit unsigned-fixture limits
  are documented in [historical raw verification](security-raw-bundle-verification.md).
- A new RSA-4096 production key was created outside the repository with key ID
  `hardened-system-prod-2026q3`; its public DER SHA-256 is
  `97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75`.
  App `2.0.42` retains the legacy key, adds the production keyring entry and a
  policy allowing both historical IDs plus the production ID. Preparation and
  publication still reject any future `RELEASE_BLOCKED_*` marker. Two
  independent encrypted backups restore correctly and an off-host ciphertext
  copy re-hashes to the accepted value. Selected full-image initial, expansion,
  runtime, two-reboot and physical recovery-round-trip acceptance pass. See
  [`key-transition-2026q3.md`](key-transition-2026q3.md).
- Corrected bridge app `2.0.42` pipelines A/B from source commit `ac12e2d` use
  independent Cargo targets and are byte-exact through the server, manifest and
  archive. The selected 22,495,269-byte archive SHA-256 is
  `aa0cd78c1b2e9951f216826c44b4b7ff2fb211fc1980540366f8f5b1f7e0dd20`
  under `build/key-transition-2.0.42-bootstrap/app-a/out/`. The server installs
  the public trust set on its first start, fixing old-init-script transition
  behavior. Embedded legacy/production fingerprints and the three-ID policy
  pass, with no private-key archive entry. The old `e9c0bb08...` archive is
  superseded.
- Superseding RC12 pipelines A/B from build commit `9567b5f` are exact through
  kernel, 57 modules, runtime staging, Buildroot rootfs, FIT, full image,
  compressed image and extracted payloads. The strict report SHA-256 is
  `d201611d70a4922cc08a1d456bd14c2c2307d35104a6ae90ac42f00283d758c2`.
  Selected rootfs is
  `b840bd08f2c708b45b527d005719b6d5dc6a7b1ba66922b8e161b570a950c760`,
  full image `2b4cf8c4f9f4507a212441957a24dc33e01cf8b3283c1488a3f564f882af2ee1`,
  and 33,789,320-byte compressed image
  `a6069020dd92c024793cbb84500887a766f07263f8a6241b9462e6e0ca95dae0`.
  The duplicate B tree was removed after proof.
- The selected RC12 card now also passes its independent physical initial,
  expansion, runtime, two-reboot and final checks. Gate C subsequently booted
  a freshly rewritten published app `2.0.40`/raw.10 recovery card and passed
  exact state plus authenticated browser login. Returning the untouched RC12
  card preserved its MAC/SSH identity and passed final exact, runtime and
  browser checks.
- The installable signed raw.12 archive is
  `cf6bbef5599197f4b5ed926f22bed12352f2fdc275eb8f32fc8344d3ed7eae96`, requires app `2.0.42`
  and is signed by `hardened-system-prod-2026q3`; its exact verification report
  is `d6627d560c68f57425ef6ad60b3adc47231c82bd6918330c1897e9ac0bf795b7`.
  `.133` accepted the exact bundle from bridge/raw.11 using
  the stock updater. Boot-good/config restoration, exact runtime, an additional
  reboot, browser login, the 13-step regression suite with five reboots and a
  final exact freeze all pass with zero kernel alerts. Full hashes are recorded
  in the RC12 release notes and key-transition guide.
- Two independently salted AES-256 PKCS#8 backups restore to the production
  fingerprint, and an off-host ciphertext copy matches an accepted backup
  hash. `.133` successfully migrated from a clean app `2.0.41`/raw.11
  state, `.49` successfully migrated from app `2.0.40` on raw.12, and the
  downloaded published RC11 image booted as exact app `2.0.40`/raw.10 on
  recoverable hardware. Immediate trust bootstrap, exact legacy/new signature
  matrix, reboot persistence, SSH identity, account login and native/Rust
  runtime all pass with zero alerts. Exact report hashes are in
  [`rc12-final-physical-gates.md`](rc12-final-physical-gates.md).
  The
  project owner explicitly decided that retained `NOASSERTION` and
  `redistribution=disabled-pending-license-grant` provenance is a disclosed
  limitation of this experimental RC, not a publication blocker or a claim
  that the missing license metadata has been resolved.
- RC11 app/system and the raw.11 lab metadata all verify with the current
  bundled public key. Longrun metadata proves they were signed from host path
  `/home/w0w/Hardened_NanoKVM/build/release/system-update-signing-test.pem`;
  cleanup removed that file. A fingerprint scan found no matching private key
  in any NanoKVM project tree. `.133` contains the exact trusted public key but
  no matching private key under `/etc`, `/kvmapp`, `/root` or `/data`.
- Generated-build cleanup on 2026-08-25 removed 187,901,444,096 bytes of old
  standalone Buildroot outputs, duplicate B pipelines and superseded probes.
  Accepted/current A trees, reproducibility reports, source worktrees, caches
  and device reports were retained.
- The user may install an older/full app update while development is in
  progress. Before every test, verify `/kvmapp/version`, `/api/health`, the
  running backend path, and deployed file hashes. Re-deploy the current test
  build if the device was updated.

### Recovery kernel test device: current `10.0.87.45`

- Model used for validation: NanoKVM Cube.
- Current address is `10.0.87.45` under the accepted full final selected
  random-only image. Its rootfs commit marker is `06c8106`; exact selected
  kernel/rootfs identity and two post-expansion software boots pass. Before
  that final image, the accepted batch-2 rollback FIT booted at `.41` and
  passed its exact gate. Hardened-only failed offline, then the exact
  random-only FIT was restored and passed. The
  restored batch-2 image used `.48`, the rollback image used `.56`,
  earlier batch-1 acceptance used `.47`, and Phase 2 also once used `.48`.
  DHCP addresses are not durable device or image identities; verify host key
  and running hashes every time.
- Web and SSH use the same encrypted Project Memory test asset as `.133`;
  never place its value in commands, logs, docs, prompts or source.
- Current booted and accepted recovery kernel is the final selected
  random-only image; its config SHA-256 is
  `43ff885267b771646b2e02b6b05e72bbc1d07c1c68070849464c053d38480e2c`.
  The accepted rollback anchor remains Phase 3 batch 2, config SHA-256
  `e8e82ff139f0bd1e46d1467505b2b4a3b1bc59d2af54fa52c983e3da3320ae63`;
  `CONFIG_USER_NS=n`, no user-namespace proc surfaces, exact 57-module
  aggregate/provenance, ten reboots, physical batch-1 rollback, restoration and
  zero final alerts all pass. Current `.45` ED25519 fingerprint:
  `SHA256:KmtR7ZUL7fnhJ1pKuee58UMwIr4weHfATnQwg+9pn4g`.
- The batch-1 rollback boot at `.56` used ED25519 fingerprint
  `SHA256:5Kst9LJW5pn5IvYKI6P3KLBPhg1JZfL/4Vme+pHvTn0` and passed its exact
  config/module/provenance and functional gates before batch 2 was restored.
- SSH, HTTP/API, network, root/boot/data mounts, 57-module inventory and kernel
  log gates pass. The user waived repeating the physical HDMI/HID/button
  matrix on this device.
- Phase-2 hardware-tested recovery image SHA-256:
  `8d9b9e4e5e38c3309c8a8b0f3597747f53431dcabb314ca5fae7c0b4e425ccb5`.
- The hardware-tested kernel, `vmlinux`, DTB and FIT are byte-identical to the
  final fixed reproducible run A. The exact final SD container has not been
  written separately; its audited rootfs differences are non-semantic build
  padding/timestamps/provenance and are documented in the candidate guide.
- Phase-2 final reproducible image, recovery-media only:
  `build/latestbuildroot/kernel-5.10.265-fixed-repro-a/recovery/assembly/images/hardened-sg2002-port.img.xz`,
  SHA-256
  `223d1231a4eca31000098cd6601473cbe300c8c605122b6ddd755941168df761`.

### Legacy comparison device: `10.0.87.132`

- Model used for validation: NanoKVM Cube.
- Hostname: `primary`.
- Static network: `10.0.87.132/24`, gateway and DNS `10.0.87.5`.
- Web and SSH test credentials are not recorded in this repository. Use an
  explicitly authorized encrypted test asset when this comparison device is
  brought back into scope.
- It was used for release/UI comparison and raw-update work. Do not use it for
  native video/MMF experiments unless the user explicitly requests it.
- Read-only check on 2026-07-11: HTTPS health reported the Rust backend, app
  version was `2.0.32`, SSH login succeeded, and installed system version was
  `0.2.15-raw.1` on base `2026-06-29-12-08-d88d58.img`.
- Last recorded Tailscale state was `notLogin` with no assigned account/IP. A
  real peer test remains pending and that state should be rechecked before
  relying on it.

## Device Deployment Rules

### SSH and archive extraction

- Local `sshpass`: `/home/w0w/.local/bin/sshpass`.
- NanoKVM BusyBox `tar` does not support GNU `-z` and `tar -a` is not a
  reliable replacement for extraction.
- Extract a gzip app archive on-device with:

  ```sh
  gzip -dc package.tar.gz | tar -C /target -xf -
  ```

- For web-only test deploys, use an uncompressed tar:

  ```sh
  tar -cf web.tar -C web/dist .
  busybox tar -xf /tmp/web.tar -C /target/web
  ```

- Remove old `/tmp/nanokvm-web-*.tar` files before large web deploys. Device
  tmpfs has filled during previous iterations.
- Do not leave a required command/session running when handing work back.

### Rust/native build

Do not deploy a plain Rust cross-build for video testing. It can start but fail
with `Dynamic loading not supported` and leave the stream unusable. Build the
linked RISC-V backend:

```sh
server-rust/scripts/build-linked-libkvm.sh
```

If the local sysroot is unavailable, point `NANOKVM_SYSROOT_LIB` at a verified
NanoKVM runtime library directory as described in
[`rust-backend.md`](rust-backend.md).

Cargo does not rebuild `libkvm`/`libkvm_mmf`. For native source changes, use the
MaixCDK `support/sg2002/build` flow, copy the resulting `dl_lib` output into
`server-rust/native/dl_lib`, then build/package the linked Rust server. The
helper currently hard-codes `NanoKVM_PATH=~/NanoKVM`; change it to this checkout
before building. Full commands and the `update_lib` false-failure exit-status
warning are in [`build-notes.md`](build-notes.md).

Useful host checks:

```sh
cargo test --manifest-path server-rust/Cargo.toml
make web-app
server-rust/scripts/build-linked-libkvm.sh
scripts/validate-nanokvm-rootfs.sh <rootfs>
```

### Runtime restart caution

- Prefer a full clean reboot after changing native MMF/libkvm code.
- Repeated backend restarts have previously left CVI/ION/VB resources allocated
  and caused `already inited`, `fail to allocate ion memory`, and invalid-buffer
  errors.
- The linked Rust shutdown path calls `kvmv_deinit()`. The current native
  implementation stops and joins its workers, closes the camera, and forces
  complete MMF teardown so an active JPEG reference cannot leave VB/VENC
  initialized. The raw.9 controlled restart and full suite passed with zero
  expanded dmesg alerts on `10.0.87.133`.
- Keep remote syslog enabled during native work so evidence survives a device
  hang/reboot.

## Logs And Diagnostics

- Local unified syslog: `/tmp/hardened-syslog/messages` in RAM.
- Rust backend log: `/tmp/nanokvm-server.log`.
- `kvm_system` test log when redirected: `/tmp/kvm_system.log`.
- Raw update log: `/data/hardened-system-raw-update.log`.
- Remote syslog receiver explicitly authorized and active on the test device:
  `10.0.77.177:514` over UDP. Raw.8 and raw.9 transitions proved that the API
  config, generated syslogd/klogd defaults, and live daemon arguments survive
  raw updates while local tmpfs logging remains enabled.
- System Log API:
  - unified local stream: `/api/system-log/messages?kind=system`;
  - backend debug stream: `kind=backend`;
  - current kernel ring buffer: `kind=kernel`.
- Local syslog is intentionally tmpfs-only to avoid SD writes. Use remote
  syslog for crashes that may require power cycling.
- For native stability tests, inspect `dmesg` and syslog for at least:
  `oops`, `panic`, `segfault`, `module_put`, `fail to allocate ion`,
  `Invalid buffer`, `already inited`, VPSS errors, and VENC errors.

## Important Hardware Decisions

### USB HID and configfs

- USB wake-on-write is opt-in through `/boot/usb.wakeup`; explicit
  `/boot/usb.notwakeup` wins if both flags exist.
- The GUI Device page exposes the same setting through
  `GET/POST /api/hid/usb-wakeup`.
- Do not detach UDC and unlink/relink live HID configfs functions to change BIOS
  subclass or wakeup behavior. A live test on 133 caused a kernel oops in
  `tokio-rt-worker`/`module_put`.
- `/boot/BIOS` subclass testing broke normal keyboard behavior and was rolled
  back. Any future BIOS compatibility experiment must be applied at clean boot,
  not through live configfs topology changes.
- If keyboard input stops, first use the existing reset/HID recovery path and
  inspect configfs/UDC state. Do not immediately rebuild the gadget live.

### Virtual media

- Normal same-type media changes should eject the removable LUN by clearing
  `lun.0/file`, update `ro`/`cdrom`/`inquiry_string`, then insert the new file.
- Switching CD-ROM versus mass-storage type reconnects the USB gadget because
  many BIOS/boot menus cache the previous LUN type.
- `.iso` may be mounted as CD-ROM or mass storage for hybrid media.
- `.img` is mass-storage only and must pass MBR/GPT, FAT/exFAT superfloppy, or
  supported raw filesystem signature validation.
- Image listing is not filtered by selected mount type; uploaded media must
  remain visible without logout.
- Browser upload supports cancel/failure status and image-list refresh. Verify
  this behavior after backend/frontend changes because it has regressed before.

### HDMI/video

- WebRTC hotplug recovery handles RTCP PLI/FIR and temporarily requests a short
  GOP/keyframe. The user confirmed the original black-screen hotplug symptom was
  fixed on 133.
- Restricted and Paranoid firewall modes intentionally disable H.264 WebRTC.
  H.264 Direct and MJPEG remain the supported restrictive-mode paths.
- The resolution choices in the web video menu are capture/encoder output
  sizes, not EDID/remote-host display-mode changes. A low capture size can crop
  or scale a larger HDMI input; do not compensate with TouchSync coordinate
  calibration.

## Current Product Behavior

### Firewall

- `moderate` is the default.
- Moderate, Restricted, and Paranoid accept new inbound connections only from:
  - IPv4 RFC1918 `10/8`, `172.16/12`, `192.168/16`;
  - IPv4 link-local `169.254/16` and loopback `127/8`;
  - IPv6 ULA `fc00::/7`, link-local `fe80::/10`, and loopback `::1/128`.
- Baseline remains the open compatibility profile.
- Restricted permits local HTTPS/SSH and required outbound services but no
  WebRTC UDP.
- Paranoid permits local HTTPS only and intentionally blocks online updates.
- Restricted and Paranoid require working HTTPS before activation.

### Time and NTP

- `S49ntp` rebuilds `/etc/ntp.conf` from `/etc/kvm/time.json`, performs a
  one-shot `ntpdate -u` against the first configured server, then starts
  `ntpd`.
- The device correctly uses configured server `10.0.87.5`, but the last direct
  test received `no server suitable for synchronization found`. That was a
  server-side NTP suitability/configuration issue, not failure to consume the
  GUI setting.

### Mobile/tablet UI

- Mobile view is a Hardened addition, not present in the original project.
- Phones and touch tablets use TouchSync, a local cursor overlay, native mobile
  keyboard button, separate on-screen HID keyboard, auto-fit, pinch-to-zoom,
  and touch-drag panning.
- Appearance can force Mobile view in the current browser through
  `nano-kvm-layout-mode` localStorage state.
- At 100% scale, the KVM screen auto-fits the browser window on desktop and
  touch layouts. Higher manual scales remain scrollable/pannable.
- Do not reintroduce the old Trackpad/Direct mobile selector; TouchSync is the
  current default mobile pointer model.

### Authentication and sessions

- Login creates an in-memory server session plus HttpOnly `nano-kvm-token`
  cookie. Closing a tab/browser does not log out by itself.
- Logout clears the cookie/server session; session timeout expires it; backend
  restart clears the in-memory session map.
- Product images do not use `admin/admin` default bootstrap. Fresh images use
  first-account setup.

## Current Verification Baseline

- RC9 release checks passed locally: Rust tests, web production build, linked
  RISC-V build, package/rootfs validation, signed metadata verification, raw
  manifest checks, checksums, and SD image xz integrity.
- The post-RC9 fit/alignment changes that became RC9.1 were installed as a test
  payload on both 133 and 132.
- Playwright against both devices passed desktop `1200x800` and phone
  `393x873` checks for KVM fit and Appearance control alignment with no page
  errors.
- `/api/health` returned the Rust backend on both devices during that check.
- Those web-only checks reported application version `2.0.32` on-device; do
  not assume RC9.1 was installed on either device without rechecking.
- The native C/C++ audit findings have source fixes. Rebuilt native libraries
  passed full reboot, MJPEG, H.264 Direct, and controlled backend stop/start on
  `10.0.87.133`; `10.0.87.132` was not used for native testing.

## Immediate Next Work

1. Stress repeated HDMI hotplug and resolution changes on 133.
2. Exercise physical OLED/button behavior and Wi-Fi provisioning hardware.
3. Run a long dmesg/syslog soak and fault-injection coverage for vendor errors.
4. Validate positive Wi-Fi reconnect and OLED AP provisioning on a device with
   `wlan0`; 133 cannot currently validate that path.
5. Recheck Tailscale login and perform a real peer connection only after the
   selected test device is logged into a tailnet.

## Documentation Map

- Release/user overview: [`../README.md`](../README.md)
- Changelog: [`../CHANGELOG.md`](../CHANGELOG.md)
- Rust backend status/build: [`rust-backend.md`](rust-backend.md)
- Native audit: [`native-code-audit.md`](native-code-audit.md)
- Raw.9 physical/recovery/release acceptance:
  [`raw9-physical-acceptance-checklist.md`](raw9-physical-acceptance-checklist.md)
- Security inventory: [`security-risk-inventory.md`](security-risk-inventory.md)
- API inventory: [`backend-api-inventory.md`](backend-api-inventory.md)
- Migration strategy/history: [`kvm-system-rust-migration-plan.md`](kvm-system-rust-migration-plan.md)
- Build/device operations: [`build-notes.md`](build-notes.md)
- SD flashing: [`sd-card-flashing.md`](sd-card-flashing.md)
- Release history: [`release-archive.md`](release-archive.md)
- Raw/system update chronology: [`current-sysupgrade-build-trace.md`](current-sysupgrade-build-trace.md)

## Handoff Safety

- Keep code edits narrowly scoped; the worktree may contain user changes.
- Before a device write, verify the target IP and current installed version.
- Use 133 for native migration/audit fixes unless the user directs otherwise.
- Do not perform live HID configfs topology changes.
- Do not use GNU-only `tar` flags on NanoKVM BusyBox.
- Do not push a release or change update-channel metadata without an explicit
  user request.
- When publishing ordinary source/docs changes, verify the diff, stage only the
  intended files, and push the current commit to GitHub `main`.
