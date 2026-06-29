# System Update Live Inventory

This file records live-device observations that affect future base-system
updates. It is separate from the application updater.

## 10.0.87.132 Snapshot

Captured on 2026-06-28 over SSH as `root`.

Identity:

```text
hostname: primary
kernel: Linux 5.10.4-tag- #39 PREEMPT Mon Feb 17 19:04:42 CST 2025 riscv64
cmdline: root=/dev/mmcblk0p2 rootwait rw console=ttyS0,115200 earlycon=sbi riscv.fwsz=0x80000 release loglevel=0
os-release: Buildroot 2023.11.2, VERSION=-g3649fe90d
/boot/ver: 2025-02-17-19-08-3649fe.img
/mnt/system/sdk-release: SDK_VERSION=musl_riscv64
```

Live partition and mount layout:

```text
/dev/mmcblk0p1  /boot  vfat   16.0M total, 11.4M used
/dev/mmcblk0p2  /      ext4    7.6G total, 840.5M used
/dev/mmcblk0p3  /data  exfat  21.2G total, 10.5G used
```

Block devices:

```text
mmcblk0    30,253,056 KiB
mmcblk0p1      16,384 KiB
mmcblk0p2   7,983,616 KiB
mmcblk0p3  22,252,544 KiB
```

Selected live hashes:

```text
a8882cd3bf1abd743e97c2a95335dcfff145ceed4a62bf62717db4c72a2edd7a  /boot/boot.sd
508c4034d26615d8483e74395f184b65c3312bdeb496b922fce550ccfe472ff5  /boot/fip.bin
28fb0d881d417a5b4cb6e751755c91ae71cca27d1a96abdda8ec1d343084da6d  /boot/ver
db59ebef59eb7e53a358625972d42e07ad2b767746fca423f884a4c27a1265c2  /mnt/system/sdk-release
```

## Stock SDK Comparison

The first locally reproduced stock SDK image came from pinned SDK SHA
`d88d58feca49ef15f4cc7bd1f27dbf17dc25f85e`.

Stock rootfs identity from `rawimages/rootfs.sd`:

```text
os-release: Buildroot 2023.11.2, VERSION=-gd88d58fec
/etc/hostname: licheervnano
/mnt/system/sdk-release: SDK_VERSION=musl_riscv64
```

Selected stock hashes:

```text
031da09b3e9c66e4e6c2e9b680409fa122a1f42a7d33508fd42edee342165aa6  rawimages/boot.sd
3af14eb57694606831f3f608aedf4af9e75641ecf89d8b73549fdc592f341b7f  fip.bin
4b94931d0b6d29f1c2a6e58039cb9611eba26a0443a98353dfbd0044257c32cb  rawimages/rootfs.sd
```

Vendor `upgrade.zip` inspection:

```text
upgrade.zip sha256: 289ae7e3cadfebc53f70be2a0903b75492efce3492c737426d526dd69683c60d
BOOT   80,960 KiB     boot.sd   sha256 32ef1c92ae9f6f2974c3efa0c0f80fa9e8f1b49e8ef8e8b2ac6dd30b4ed3cf05
ROOTFS 1,581,056 KiB  rootfs.sd sha256 c40280a77ad5f7727983b8aaa1a967fad16c7bb9f0e9d8ed30146956eb44a6f1
```

Important distinction:

- `upgrade.zip` `boot.sd` and `rootfs.sd` are vendor packed update images.
- `rawimages/rootfs.sd` is an ext4 filesystem image.
- The generated SD-card image contains a vfat boot partition with `fip.bin`,
  `rawimages/boot.sd`, and mode marker files.
- The stock SDK rootfs does not contain `/kvmapp`, `/etc/kvm`, NanoKVM init
  scripts, Hardened web assets, or backend switching files. It must not be used
  directly for GUI raw partition updates.

## Raw 0.1.0 Recovery Finding

On 2026-06-29, an SD card from a failed `hardened-system-0.1.0-raw.1` GUI raw
install was inspected offline. The boot partition marker was
`2026-06-28-19-11-d88d58.img`, and the rootfs was a stock Buildroot image from
the reproduced vendor SDK:

```text
os-release: Buildroot 2023.11.2, VERSION=-gd88d58fec
/etc/hostname: licheervnano
/kvmapp: missing
/etc/kvm/system-version.json: missing
/etc/init.d/S95nanokvm: missing
/etc/network/interfaces: loopback only
```

The rootfs filesystem was readable but marked with journal recovery/errors after
the failed boot. The main failure was the artifact contents, not just the
runtime raw writer: the release pipeline packaged a stock SDK rootfs. Raw
releases must now be built from a patched Hardened SD image and validated with
`scripts/validate-nanokvm-rootfs.sh` before publishing.

## Safety Conclusions

Do not treat the vendor `partition_sd.xml` as the live installed-device layout.
The live device has a third `/data` partition and a larger root partition, while
the vendor OTA describes only BOOT and ROOTFS.

Do not enable raw partition writes from the GUI on non-lab devices until there
is a partition-aware installer with explicit device identity checks, enough
`/data` backup space, power-loss handling, and a tested recovery path. Raw
updates remain SD-card-recovery-only even after rootfs content validation.

Near-term safe update paths:

- continue using signed file-level bundles for `/kvmapp`, `/etc/kvm`, and small
  known rootfs files;
- consider boot-file updates only after stock-image hardware validation and a
  tested `/boot` backup/rollback path;
- keep full ROOTFS replacement out of the GUI until raw image rollback is
  designed and tested on sacrificial hardware.
