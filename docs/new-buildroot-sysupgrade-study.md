# New Buildroot Sysupgrade Study

This branch tracks the feasibility work for building Hardened NanoKVM
sysupgrade images on a newer Buildroot or newer Sipeed SDK baseline.

Date checked: 2026-06-29.

## Question

Can the raw/system-update image path move from the current NanoKVM vendor SDK
baseline to a newer SDK or newer Buildroot without a full board port?

Short answer: not yet. The newest NanoKVM-compatible Sipeed SDK refs that were
checked are newer commits, but they still use Buildroot 2023.11.2 and
`linux_5.10`. The refs that look structurally different are not proven
NanoKVM/LT6911-ready, and the older `v4.1.0` branches are actually worse for
this target because they use Buildroot 2021.05 and do not expose the current
`sg2002_licheervnano_sd` NanoKVM board flow.

## Sources Checked

- SDK repository: `https://github.com/sipeed/LicheeRV-Nano-Build.git`
- Official Buildroot releases: `https://buildroot.org/download.html`
- Local pinned SDK baseline from `docs/vendor-sdk-build.md`
- Existing system-update packaging and raw image tooling in this repository

## SDK Ref Findings

| Ref | Commit | Buildroot | Kernel | NanoKVM target status | Result |
| --- | --- | --- | --- | --- | --- |
| `NanoKVM` | `d88d58feca49` | `2023.11.2` | `linux_5.10` | `sg2002_licheervnano_sd` present | Current pinned reproducible baseline. |
| `main` / `20260407` | `d4003f15b35d` | `2023.11.2` | `linux_5.10` | `sg2002_licheervnano_sd` present | Newer vendor snapshot, but not a newer Buildroot. |
| `20251230` | `61013d819e63` | `2023.11.2` | `linux_5.10` | `sg2002_licheervnano_sd` present | Newer than pinned baseline, still not a newer Buildroot. |
| `newsdk` | `488895334b8c` | submodule/patch SDK layout | `linux_5.10` | target appears to be introduced by patch flow, not directly proven | Experimental only; no obvious proven NanoKVM HDMI/LT6911 path from the shallow inspection. |
| `v4.1.0` | `6b39b28304bf` | `2021.05` | vendor tree | no current NanoKVM target; branch log says unused | Not a new Buildroot path. |
| `v4.1.0-licheervnano` | `9dea0f4692e9` | `2021.05` | vendor tree | LicheeRV Nano oriented, not current NanoKVM target | Not a new Buildroot path. |

The official Buildroot project has newer stable series than 2023.11, but that
does not by itself give a NanoKVM-ready BSP. Moving to official newer Buildroot
would be a board-port project, not a SDK ref bump.

## What Blocks A Drop-In New Buildroot

The NanoKVM base system depends on vendor-specific pieces that are not provided
by stock Buildroot:

- Sophgo SG2002/CVITEK kernel integration and device tree layout.
- LT6911 HDMI bridge/capture support.
- MMF/VENC userspace stack, libraries, reserved memory, and H.264 path.
- `libkvm.so` and capture/control ABI used by the backend.
- U-Boot/image layout expected by the current SD-card and raw-update tools.
- USB HID gadget, RNDIS/ACM, storage gadget, and init ordering.
- NanoKVM service layout under `/kvmapp`, `/etc/kvm`, `/data`, and boot scripts.
- GUI/backend assumptions about system identity, update status, and rollback.

These are all solvable, but they need bring-up and hardware validation. Treating
official Buildroot 2026.x as a direct replacement would likely produce an image
that boots at best, but does not have working video, H.264, HID, or update
recovery.

## Practical Tracks For This Branch

### Track A: Newer Vendor Snapshot

Use Sipeed `20260407`/`main` as a safer experimental vendor snapshot:

```sh
LICHEERV_NANO_SDK_REF=20260407 \
LICHEERV_NANO_SDK_SHA=d4003f15b35d43ad4842f427050ab2bba0114fa5 \
make vendor-sdk
```

Expected result: still Buildroot 2023.11.2, but with later Sipeed fixes. This
is the lowest-risk next build candidate for sysupgrade image work.

Required proof before shipping:

- `make vendor-sdk-stock` completes.
- Generated SD image boots on sacrificial media.
- Web, SSH, video, H.264, HID, paste, terminal, network, reboot, and hostname
  changes match the current Hardened baseline.
- The Hardened app can be injected and raw boot/rootfs images can be extracted
  from the resulting known-good SD image.

### Track B: Sipeed `newsdk` Probe

`newsdk` is a different patch/submodule workflow. It should be investigated in a
separate checkout under `build/vendor-newsdk`, not by replacing the pinned SDK
path in-place.

Initial probe sequence:

```sh
git clone --branch newsdk --recursive \
  https://github.com/sipeed/LicheeRV-Nano-Build.git \
  build/vendor-newsdk/LicheeRV-Nano-Build
cd build/vendor-newsdk/LicheeRV-Nano-Build
sh ./apply_patches.sh
source build/cvisetup.sh
defconfig sg2002_licheervnano_sd
build_all
```

Required proof before treating it as usable:

- Patch application is clean.
- `defconfig sg2002_licheervnano_sd` exists after patches.
- The resulting `.config`, DTS, kernel config, and userspace image still include
  the NanoKVM HDMI/LT6911 and multimedia pieces.
- A stock image boots and passes the same hardware baseline as Track A.

### Track C: Official New Buildroot Port

This is the real "new Buildroot" route. It should be a separate long-running
port after Track A and Track B are understood.

Minimum milestones:

1. Decide target Buildroot LTS/stable baseline.
2. Import or package the SG2002 vendor kernel, U-Boot, DTS, firmware, and MMF
   userspace stack.
3. Recreate the NanoKVM SD-card image layout.
4. Recreate `/kvmapp`, init, networking, USB gadget, and recovery/update paths.
5. Boot to SSH/web on sacrificial media.
6. Prove HDMI capture, MJPEG, H.264, HID, paste, terminal, and reboot soak.
7. Only then generate raw/system-update bundles.

## Current Recommendation

Do not promise a new Buildroot sysupgrade image yet. Start this branch with
Track A because it gives a reproducible Sipeed snapshot and keeps the known
NanoKVM target. Use Track B only as a probe. Treat Track C as a porting project
with its own acceptance tests and rollback media.

If the goal is security rather than a new distro baseline, the stronger
near-term path is to keep the proven Buildroot 2023.11.2 vendor SDK and apply a
curated userspace security backport set. That path is documented in
[buildroot-2023-security-backport-plan.md](buildroot-2023-security-backport-plan.md).
