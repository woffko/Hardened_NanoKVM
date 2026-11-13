# SG2002 Vendor Kernel 5.10 Security Port Plan

Status date: 2026-08-26.

This plan covers the running SG2002 kernel and its modules. Buildroot
`2026.05.1` updates userspace, but its `5.10.258` userspace headers do not
modify or secure the retained vendor kernel. The main raw-update device at
`10.0.87.133` still runs `5.10.4-tag-`; the recovery-SD test device at
`10.0.87.45` now boots the accepted Phase 3 batch-3 `5.10.265-tag-` selected
image.

The target for the first current-kernel experiment is upstream longterm
`5.10.265`, published by kernel.org on 2026-08-19. A successful source merge or
build is not release evidence: the resulting kernel, device trees, and every
module must pass the complete recoverable-media and device acceptance matrix.

Phase 2 now passes the source, build, reproducibility and kernel/device boot
gates. The signed stable tag is merged, every conflict is resolved in bounded
commits, all 57 runtime modules are rebuilt, and two independent full
pipelines are byte-exact through the compressed SD image. The fixed kernel/FIT
booted on recovery media at `10.0.87.48`; exact artifacts, hashes, regression
root cause and the precise final-container evidence boundary are recorded in
[`kernel-5.10.265-recovery-candidate.md`](kernel-5.10.265-recovery-candidate.md).

## Verified Provenance

The reproducible audit is:

```sh
scripts/audit-vendor-kernel-5.10.sh
```

It writes its local evidence under
`build/latestbuildroot/kernel-5.10-security-audit/report/` and verifies the
official kernel archives before comparing source trees.

Current evidence:

- official Linux `5.10.4` archive SHA-256:
  `904e396c26e9992a16cd1cc989460171536bed7739bf36049f6eb020ee5d56ec`;
- T-Head source commit `b1313fe517ca3703119dcc99ef3bbf75ab42bcfb`,
  identified by its `Linux 5.10.4` commit, is content-identical to the official
  `5.10.4` source for the audit inventory;
- Milk-V commit `5c7dd7acc3624737c37e5db9390f5d24db6e9457` explicitly records importing
  that T-Head commit before the CVITEK port history;
- the pinned Sipeed SDK checkout is
  `d88d58feca49ef15f4cc7bd1f27dbf17dc25f85e`, but it is shallow and its
  initial `linux_5.10` commit is a source snapshot rather than the original
  patch history;
- official Linux `5.10.265` archive SHA-256:
  `d10cb9169e49da3d5f7154a01e450012486565fa9442e23d660b0581a3f92645`;
- the current vendor source differs from official `5.10.4` in 2,155 source
  paths: 1,867 additions, 282 modifications, and 6 deletions;
- upstream stable changes 15,410 paths between `5.10.4` and `5.10.265`;
- 140 exact paths are touched by both the vendor delta and the stable series.

The largest vendor additions are real source, not generated build output:
`arch/riscv` includes the vendor RISC-V vector 0.7 software implementation,
and `drivers/net` includes vendor wireless drivers. The audit deliberately
excludes the generated top-level `linux_5.10/build/` directory.

The 140 exact overlaps include high-risk runtime paths:

- 32 RISC-V architecture files;
- 25 USB files, including DWC2, configfs gadget, HID, mass storage, UVC, and
  UDC core paths;
- 9 MMC files;
- 7 network-core paths;
- 4 kernel-core paths;
- 3 I2C paths;
- 2 media/UVC paths.

This proves that replacing the tree or applying one opaque aggregate patch is
not a safe update procedure.

Phase 1 source provenance is now reconstructed beyond the original inventory:

- an isolated, non-shallow Sipeed `NanoKVM` history mirror contains 207 commits
  and 18 commits touching `linux_5.10`; pinned SDK commit `d88d58f` is an
  ancestor of the current branch, and its kernel subtree stops changing at
  Sipeed merge commit `8a20f93b`;
- an isolated, non-shallow official Milk-V `develop` history mirror contains
  384 commits and the exact import commit `5c7dd7a`, followed by the CVITEK and
  Milk-V kernel history;
- Milk-V `303ec5da` (`linux: version release v4.1.5`) is the nearest recorded
  source state to the first Sipeed snapshot, with a 147-path import gap;
- [`reconstruct-vendor-kernel-5.10-patch-stack.sh`](../scripts/reconstruct-vendor-kernel-5.10-patch-stack.sh)
  produces 24 reviewable binary-safe layers: 7 official/Milk-V layers and 17
  Sipeed layers including the import gap;
- every layer is checked against its source snapshot with `git write-tree`.
  The final reconstructed tree
  `a5854bd362b88c59d34bd4db9ff9ea876c6aebd4` exactly matches the pinned
  Sipeed `linux_5.10` subtree;
- patch-stack evidence is under
  `build/latestbuildroot/kernel-patch-stack-5.10.4-v2/report/`. All 24 patch
  checksums, manifest continuity, and the clean final worktree were verified.

The existing clean baseline build is also byte-exact for the covered outputs:
`Image`, `vmlinux`, 24/24 in-tree modules, and 3/3 CVITEK DTBs have zero
mismatches against the retained vendor output. Evidence is under
`build/latestbuildroot/kernel-baseline-5.10.4-v2/report/`.

Module provenance and external-module baseline reconstruction are now complete:

- [`audit-vendor-module-provenance.sh`](../scripts/audit-vendor-module-provenance.sh)
  inventories all 57 modules in the accepted raw.10 rootfs, including hashes,
  vermagic, license, dependencies, matching build outputs, and Kbuild `.mod`
  source-object lists;
- 24 modules are exact clean in-tree baseline outputs after the pinned
  `strip --strip-unneeded` packaging transform;
- 3 media modules are independently source-built and hardware-accepted;
- the remaining 30 modules map to concrete SDK build outputs and all source
  object lists resolve;
- [`rebuild-vendor-external-modules-5.10-baseline.sh`](../scripts/rebuild-vendor-external-modules-5.10-baseline.sh)
  rebuilds those 30 modules from an isolated source copy with the pinned board
  config, clean kernel baseline, and Xuantie toolchain. All 30 packaged SHA-256
  values match the accepted raw.10 bytes, while kernel baseline sentinels remain
  unchanged;
- evidence is under
  `build/latestbuildroot/module-provenance-raw10-v5/report/` and
  `build/latestbuildroot/external-modules-5.10.4-v3/report/`.

The vendor boot FIT is now independently reproducible as well:

- [`rebuild-vendor-boot-sd-5.10-baseline.sh`](../scripts/rebuild-vendor-boot-sd-5.10-baseline.sh)
  assembles the clean Image, clean board DTB, source-generated ramdisk, generated
  single-board ITS, and vendor `mkimage` output without copying accepted FIT
  payloads into the result;
- the current source-generated cpio has the same 25-entry ordering, modes,
  ownership, device metadata, links, and payloads as the accepted FIT ramdisk;
  only historical mtimes differed and are restored explicitly for the baseline;
- deterministic gzip and FIT creation reproduce boot.sd SHA-256
  `42ada02eee96aa18ea374497b5022951539addd7aadbd2b3331aa54b16915652`
  byte-for-byte;
- evidence is under `build/latestbuildroot/boot-sd-5.10.4-v3/report/`.

A recoverable-media candidate has been assembled locally without writing any
block device. It embeds the byte-exact reconstructed boot.sd, pinned fip.bin,
and accepted raw.10 rootfs. All three were extracted from the completed image
and compared with their inputs. The image is:

`build/latestbuildroot/recoverable-kernel-baseline-sd-v2/assembly/images/hardened-sg2002-port.img`

with SHA-256
`2bfb0b2000786a6860f069b235fe6026fc8e77f7132f0f72e284e725246cb92e`.
This is preparation evidence only, not permission to write an unidentified or
accepted device card.

The clean build also surfaced vendor-source warnings to triage separately:
GT9xx logs a `size_t` with `%d` instead of `%zu`; AIC8800 has a const-correctness
prototype mismatch and C90 declaration warning; RTL8733 DFS has misleading
indentation around independent diagnostics. These are not silently patched into
the accepted baseline because the current Cube lacks the corresponding Wi-Fi
and touchscreen hardware for validation.

## Current Kernel Configuration Findings

The inventory reads the final built `.config`, not only the board defconfig.

Already enabled:

- strong stack protector;
- seccomp and seccomp filters;
- loadable modules;
- user namespaces.

Disabled or absent:

- the security/LSM framework and restricted `dmesg`;
- `HARDENED_USERCOPY`;
- slab freelist randomisation and hardening;
- init-on-allocation and init-on-free defaults;
- strict kernel/module RWX and KASLR support;
- module signatures;
- BPF syscall/JIT, which is a useful attack-surface reduction;
- `/dev/kmem`, while `/dev/mem` remains enabled;
- `DEBUG_FS` remains enabled.

These switches must not all be flipped in one commit. Vendor media, USB, and
out-of-tree modules may depend on memory-layout, debugfs, `/dev/mem`, or old
usercopy behaviour. Each hardening group needs its own build and hardware
acceptance evidence.

## Remaining Inputs Before A Release Kernel Exists

1. If the exact fixed-run-A SD artifact is to be published, write that exact
   container to re-identified sacrificial media once. The kernel/FIT boot gate
   already passes; this is an exact-container release check, not permission to
   install it first through a raw update.
2. Complete Phase 3 configuration hardening as bounded candidates. Do not
   combine user namespaces, LSM, usercopy, slab, init-on-alloc/free, RWX,
   debugfs and `/dev/mem` changes into one untraceable build.
3. Build and accept a rollback-capable lab raw update only after the chosen
   hardened configuration passes recovery media.
4. Resolve redistribution terms for every retained boot, firmware and runtime
   input.
5. Define production signing-key custody before any release publication.

## Implementation Plan

### Phase 1: Reproduce The Existing Kernel

Status: source history reconstruction, the 24-layer patch stack, the byte-exact
kernel/in-tree-module/DTB rebuild, complete 57-module provenance, and the
30/30 byte-exact external-module rebuild are complete. The independent
`boot.sd` rebuild is also byte-exact. The unchanged baseline recovery image
booted on the secondary device before Phase 2 hardware boundary testing.

1. Create an isolated local kernel repository at official `v5.10.4`.
2. Import the CVITEK/Milk-V history as ordered commits where available.
3. Add the Sipeed changes after its snapshot as a second ordered layer.
4. Put any remaining snapshot-only difference in a named, reviewable synthetic
   commit; retain the full name-status and diffstat evidence.
5. Apply the exact NanoKVM board defconfig and the pinned vendor toolchain.
6. Rebuild kernel, DTS, and every module from a clean output directory.
7. Compare version, config, DTB structure, exported symbols, module vermagic,
   module inventory, and boot-image layout with the known-good vendor output.
8. Boot this still-`5.10.4` reconstruction from recoverable SD media and run
   the normal device gates. No stable merge starts until this baseline passes.

This phase separates build-system or provenance problems from changes caused
by the stable series.

### Phase 2: Merge Upstream Stable 5.10.265

Status: local source, build, module, FIT, rootfs, SD assembly and exact
reproducibility gates pass. The initial clean merge exposed a semantic duplicate
of `of_clk_init(NULL)` from vendor and stable histories; the fixed source commit
`479872f533fbcec3220fa0924b360e6d33e742c7` removes the duplicate and a build
guard enforces one include/one call. Its byte-identical kernel/FIT booted on
recovery media at `10.0.87.48` with modules, storage, network, SSH/API and
kernel-log gates passing.

1. Branch the passing reconstructed vendor kernel.
2. Merge the signed upstream `v5.10.265` tag, preserving upstream commit
   identity and the vendor patch layers. Do not use version-string-only CVE
   claims or copy a prebuilt kernel.
3. Resolve conflicts in bounded groups and commit each group separately:

   - RISC-V entry, MM, signal, module, cache, and vector 0.7 compatibility;
   - MMC/SD boot and data I/O;
   - DWC2 and USB core;
   - configfs gadget, HID, mass storage, UVC, and UDC lifecycle;
   - Ethernet/network core;
   - media, I2C, sensor, framebuffer, and watchdog;
   - remaining kernel, filesystem, crypto, and security paths.

4. For every conflict group, inspect the complete upstream stable history for
   that file. Choosing either the old vendor file or the new upstream file as a
   whole is not an acceptable resolution.
5. Build after every group. Run static module/config/DTB checks after every
   build and boot at least after RISC-V/MMC, USB, network, and media groups.
6. Rebuild all modules and `boot.sd` together. Never combine a new kernel with
   modules from `5.10.4-tag-`.

### Phase 3: Configuration Hardening

Configuration changes remain separate from the stable merge so failures are
attributable. Suggested batches are:

Status: batch 1 (`CONFIG_SECURITY_DMESG_RESTRICT=y`) has an exact one-option
config diff and two complete byte-identical clean pipelines through the
compressed recovery SD image. The debugfs audit found active CVITEK ION/MMF
consumers, so debugfs remains enabled. Recovery-device boot, the root versus
unprivileged dmesg boundary, and ten reboot/log cycles pass on `10.0.87.47`.
Batch 1 is accepted. Evidence and the image path are in
[`kernel-5.10.265-phase3-dmesg-restrict.md`](kernel-5.10.265-phase3-dmesg-restrict.md).

Batch 2 retains that option and disables `CONFIG_USER_NS`. Source, assembled
rootfs and live batch-1 consumer audits found no user-namespace consumer. The
cumulative generated-config diff contains exactly those two options, and two
complete clean pipelines from `473baf9` are byte-identical through the
compressed recovery SD image. Recovery boot at `10.0.87.41`, exact running
config/module/provenance identity, the user-namespace boundary and ten
reboot/log cycles pass. A physical boot of the prior batch-1 rollback image at
`10.0.87.56` also passes its exact config/module/provenance and runtime gates.
Batch 2 was restored at `10.0.87.48` and its strengthened identity/runtime gate
passed again. Batch 2 is accepted. Evidence and the exact image path are in
[`kernel-5.10.265-phase3-userns-disable.md`](kernel-5.10.265-phase3-userns-disable.md).

Batch 3 is scoped to `CONFIG_SLAB_FREELIST_RANDOM=y` and
`CONFIG_SLAB_FREELIST_HARDENED=y`. Its exact Kconfig proof has no cascaded
change, and two accepted-batch-2 tmpfs/VFS baseline runs establish fixed timing,
temperature and zero-alert comparison limits before candidate construction.
Two clean full pipelines from `97407be` are byte-identical through the
compressed recovery image; config delta and all build invariants pass.
The first exact recovery boot stopped before partition 2 was ever mounted and
before network identity was created. Boot files and the pristine rootfs match
run A exactly. Randomisation-only and hardened-only probes isolate the two new
options. Randomisation independently passes exact identity, performance and
ten reboot cycles; pointer hardening independently fails before network return
and is rejected. Two canonical random-only builds from `06c8106` match through
the compressed image. Physical batch-2 rollback, the complete final selected
image, exact `06c8106` rootfs identity and two post-expansion software boots
pass with zero kernel alerts. Batch 3 is accepted. See
[`kernel-5.10.265-phase3-slab-freelist.md`](kernel-5.10.265-phase3-slab-freelist.md).

1. enable restricted `dmesg` and audit required debugfs use;
2. disable user namespaces if no runtime consumer is found;
3. enable slab freelist randomisation/hardening;
4. enable init-on-allocation, then init-on-free after performance measurement;
5. enable `HARDENED_USERCOPY` and exercise every vendor driver path;
6. attempt strict kernel/module RWX only after confirming architecture and
   linker support;
7. introduce module signing only when every required module is reproducibly
   rebuilt and production key custody is defined;
8. remove `/dev/mem` and debugfs only after tracing actual vendor consumers.

Each batch needs a config diff, boot evidence, performance/temperature sample,
kernel-log review, and rollback result.

Batch 4 now has a tracked cumulative init-on-allocation-only fragment, an exact
one-line cross-toolchain Kconfig proof and two accepted batch-3 baseline runs
with 670/670 ms medians and zero alerts. Its fixed candidate
mean-of-medians limit is 770.5 ms. Two clean full candidate pipelines from
`f97d12d` are byte-exact through the compressed recovery image. The candidate
medians are 680/700 ms, exact identity and functional runtime pass, ten reboot
cycles pass, and exact rollback to batch 3 passes with zero alerts. The device
is left on batch 3. The complete selected A recovery-image boot remains;
HDMI/Wi-Fi/HID physical-matrix repetition was explicitly waived by the user and
is not claimed as new positive evidence. Init-on-free remains explicitly
outside this batch. See
[`kernel-5.10.265-phase3-init-on-alloc.md`](kernel-5.10.265-phase3-init-on-alloc.md).

### Phase 4: Recoverable-Media Acceptance

For every candidate selected for device testing:

- verify signed source/tag and all source/archive hashes;
- build from a clean tree and record compiler/binutils/config/DTB/module hashes;
- verify root, boot, and data partitions before and after boot;
- run at least ten cold or software reboot cycles with no oops, BUG, panic,
  hung-task, lockdep, RCU, USB, MMC, or filesystem alerts;
- test HTTPS, SSH, update checks, hostname/config restoration, and rollback;
- soak MJPEG and H.264 at all accepted resolutions and exercise HDMI reset,
  cable hotplug, and source mode changes;
- verify HID keyboard, mouse, paste, and host-visible reports;
- test the boot-created USB topology, RNDIS, removable media mount/eject, and
  host reboot/BIOS enumeration without live HID configfs relinking;
- test SD read/write integrity and power loss only on sacrificial media;
- verify I2C, LT6911, OLED/button, LEDs, sensor/hwmon, and watchdog behaviour;
- actuate GPIO/ATX only with explicit authorization for the attached host.

### Phase 5: Raw-Update And Release Gates

Only after the same kernel boots and passes from recovery media:

1. package a signed lab raw update with exact kernel/module/DTB provenance;
2. prove raw update, boot-good, rollback, and five additional reboot cycles;
3. repeat native, browser, video, USB, peripheral, and watchdog audits;
4. perform a clean independent rebuild from a reviewed committed source tree;
5. resolve vendor binary redistribution rights and credential-history cleanup;
6. publish only after explicit authorization.

## Current Decision

The Buildroot userspace port and fixed `5.10.265-tag-` kernel are successful lab
candidates. Phase 2 and Phase 3 batches 1, 2 and selected batch 3 pass their
kernel/device recovery gates. This is not yet a release kernel: the main
raw-update device still runs `5.10.4-tag-`, later configuration-hardening
batches remain recovery-media only, and raw-update rollback, production
signing and redistribution gates remain.

The randomisation-only probe passes exact runtime identity, the predeclared
performance limits and ten reboot cycles. Hardened-only independently fails to
return after reboot, so `CONFIG_SLAB_FREELIST_HARDENED` is rejected. Two clean
final builds from the canonical randomisation-only fragment at `06c8106` are
byte-exact through the compressed recovery image. Physical batch-2 rollback,
the complete final selected image, exact final-rootfs identity and two
post-expansion software boots pass. Batch 3 is accepted. The next independent
kernel action, init-on-allocation, now passes reproducibility, exact runtime,
performance, ten-reboot and batch-3 rollback gates. Its complete final RC12
selected A image also passes initial physical boot, storage expansion, exact
runtime, two post-expansion reboots and final runtime verification. Batch 4 is
accepted and the RC12 kernel scope is frozen. Init-on-free remains a later
separate decision outside RC12. Each subsequent batch keeps its own config
diff, recoverable-media boot, runtime regression and rollback evidence.
Enabling every hardening option at once would destroy failure attribution and
remains unacceptable.

The RC12 raw preflight now preserves the physically accepted rootfs and boot
partition bytes exactly and passes the format-2/app-first manifest verifier.
It remains deliberately unsigned. Publication still requires the private key
matching the already-deployed update public key; generating a new uncoordinated
key is not an acceptable substitute for online update compatibility. By
explicit project-owner decision, unresolved vendor `NOASSERTION` and
redistribution provenance remains a disclosed experimental-release limitation
rather than an RC12 blocker.
