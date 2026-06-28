# Vendor SDK Build Path

This document records the current source of truth for reproducible base-system
work. It is for future kernel/rootfs security-backport releases, not for the
current `kvmapp` application updater.

## Selected SDK Source

Verified on 2026-06-28 with `git ls-remote`:

- SDK: `https://github.com/sipeed/LicheeRV-Nano-Build.git`
- Initial branch: `NanoKVM`
- Initial pinned SDK SHA:
  `d88d58feca49ef15f4cc7bd1f27dbf17dc25f85e`
- Host tools: `https://github.com/sophgo/host-tools.git`
- Initial pinned host-tools SHA:
  `103c66f126fa98fcaa8b54f37fa06f6b293fd074`

The Sipeed repository also has newer refs such as `main`, `newsdk`,
`v4.1.0`, `v4.1.0-licheervnano`, and tags through `20260407`. The first stock
reproduction attempt should start from the explicit `NanoKVM` branch because
that branch is the clearest NanoKVM-specific vendor candidate. Newer refs can
be evaluated only after the `NanoKVM` branch produces a working stock image.

Community mainline Buildroot trees are useful research inputs, but they are not
the first update path. They need separate proof for CSI, MMF, H.264/VENC,
reserved memory, `libkvm.so`, USB HID gadget behavior, and NanoKVM web/backend
compatibility before they can replace the vendor stack.

## Bootstrap

The SDK checkout is intentionally outside tracked source under `build/vendor`.

```sh
make vendor-sdk
```

This runs:

```sh
scripts/bootstrap-vendor-sdk.sh
```

The script shallow-fetches the selected SDK and `host-tools`, checks out the
fetched refs detached, and fails if either HEAD does not match the pinned SHA.
The first bootstrap on the current build host used about 14 GiB before running
`build_all`, so keep substantially more free space available for the real
compile and generated images.
To intentionally move refs, override both the ref and expected SHA:

```sh
LICHEERV_NANO_SDK_REF=20260407 \
LICHEERV_NANO_SDK_SHA=d4003f15b35d43ad4842f427050ab2bba0114fa5 \
make vendor-sdk
```

## Stock Build

After bootstrap:

```sh
cd build/vendor/LicheeRV-Nano-Build
source build/cvisetup.sh
defconfig sg2002_licheervnano_sd
build_all
```

The `defconfig sg2002_licheervnano_sd` step was verified on 2026-06-28 against
the pinned refs above. It selects:

```text
PROJECT: sg2002_licheervnano_sd
Linux source folder: linux_5.10
Uboot source folder: u-boot-2021.10
Output path: install/soc_sg2002_licheervnano_sd
```

It currently emits a non-fatal `FLASH_SIZE_SHRINK` duplicate-setting warning
from the upstream defconfig.

The upstream README notes that `qt5svg` or `qt5base` can fail on the first
build on some hosts; in that case, retry `build_all`.

The first successful output must be treated as a stock image. Do not add
Hardened files until the stock image boots on test hardware and passes the
baseline checks below.

## Baseline Checks

On a stock SDK image, verify at minimum:

- boot reaches web UI and SSH;
- HDMI capture works in MJPEG and H.264 modes;
- keyboard, mouse, paste, and terminal behavior match the current baseline;
- Ethernet, mDNS hostname, TLS/HTTP behavior, and reboot survive multiple
  cycles;
- `/boot/ver`, `uname -a`, `/etc/os-release`, `/lib/modules`, and partition
  layout are recorded;
- `/kvmapp`, `/etc/kvm`, `/data`, `/tmp`, multimedia libraries, `libkvm.so`,
  and relevant device nodes match expectations.

Only after that should Hardened changes be added to the SDK output.

## First Real System Update Candidate

The first real GitHub system-update release should still be conservative:

1. Produce a stock SDK image and confirm the baseline.
2. Generate a rootfs-only hardening payload from a small file set.
3. Publish it as a signed `hardened-system-*` release.
4. Test check/download/install/confirm/rollback through the GUI.
5. Run reboot and video/HID soak before any kernel/dtb/module payload.

Kernel, dtb, module, or full-rootfs replacement should wait until the stock SDK
image is reproducible and the rollback path is tested with a reboot-required
bundle.
