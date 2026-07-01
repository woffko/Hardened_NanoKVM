# SD Card Flashing Guide

This guide covers writing a Hardened NanoKVM SD-card image to microSD media.
It is for full SD-card images such as:

```text
Hardened_NanoKVM_*_rust.img.xz
```

Application update archives such as `hardened-nanokvm-kvmapp-*.tar.gz` are not
SD-card images. Install those through the web GUI updater instead.

## Before You Start

- Use a known-good microSD card, ideally 16 GB or larger.
- Download the latest published SD image from the Hardened release page:
  <https://github.com/woffko/Hardened_NanoKVM/releases>
- If both `.img` and `.img.xz` are available, prefer `.img.xz`; the tools below
  can write it directly or stream-decompress it.
- Writing an image destroys all data on the selected card.
- Pick the target disk carefully. A wrong disk name can overwrite your computer
  drive.

Current release note: the latest published full SD-card image is the RC3
`2.0.25` image with matching raw system version `0.2.17-raw.1`. It includes the
current Hardened app, raw-system update support, and the
`Buildroot 2023.11.3 package backports` security-backport baseline.

## Windows: Balena Etcher

Balena Etcher is the safest default option on Windows because it handles `.xz`
images and reduces the chance of selecting the wrong disk.

1. Download and install Balena Etcher from <https://etcher.balena.io/>.
2. Download the Hardened NanoKVM `.img.xz` SD-card image from GitHub Releases.
3. Insert the microSD card into your card reader.
4. Open Balena Etcher.
5. Click **Flash from file** and select the downloaded `.img.xz`.
6. Click **Select target** and choose the microSD card.
7. Click **Flash**.
8. Wait for Etcher to finish validation.
9. Safely eject the card from Windows.
10. Insert the card into NanoKVM and power the device.

On a fresh Hardened image, open the device in a browser and complete the
first-boot account setup. If you flashed an older beta SD image first, update
the application to the latest app release through **Settings > Check for
Updates**.

## Linux

The most reliable Linux path is to stream-decompress the image directly to the
whole block device with `xzcat` and `dd`.

Identify the card:

```sh
lsblk -o NAME,SIZE,MODEL,TRAN,MOUNTPOINTS
```

Unmount any mounted partitions on the card. Replace `/dev/sdX` with the real
device name, for example `/dev/sdb` or `/dev/mmcblk0`:

```sh
sudo umount /dev/sdX* 2>/dev/null || true
```

Write the image:

```sh
xzcat Hardened_NanoKVM_*.img.xz | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress
sync
```

For an uncompressed `.img`:

```sh
sudo dd if=Hardened_NanoKVM_*.img of=/dev/sdX bs=4M conv=fsync status=progress
sync
```

Eject the card:

```sh
sudo eject /dev/sdX
```

Do not write to a partition such as `/dev/sdX1`; write to the whole card device
such as `/dev/sdX`.

## macOS

Find the SD card:

```sh
diskutil list
```

Unmount it. Replace `N` with the disk number, for example `disk4`:

```sh
diskutil unmountDisk /dev/diskN
```

Install `xz` if needed:

```sh
brew install xz
```

Write the compressed image. Use the raw device `rdiskN` for better speed:

```sh
xzcat Hardened_NanoKVM_*.img.xz | sudo dd of=/dev/rdiskN bs=4m status=progress
sync
```

For an uncompressed `.img`:

```sh
sudo dd if=Hardened_NanoKVM_*.img of=/dev/rdiskN bs=4m status=progress
sync
```

Eject it:

```sh
diskutil eject /dev/diskN
```

macOS may show a warning that the card is unreadable after flashing. That is
normal for Linux partitions; eject it instead of initializing it.

## FreeBSD

Find the card:

```sh
camcontrol devlist
gpart show
```

The card will usually appear as `/dev/da0`, `/dev/da1`, or `/dev/mmcsd0`.
Unmount any mounted partitions first:

```sh
mount | grep '/dev/da0'
sudo umount /dev/da0p1 2>/dev/null || true
sudo umount /dev/da0p2 2>/dev/null || true
sudo umount /dev/da0p3 2>/dev/null || true
```

Write a compressed image:

```sh
xzcat Hardened_NanoKVM_*.img.xz | sudo dd of=/dev/da0 bs=4m conv=sync
sync
```

For an uncompressed `.img`:

```sh
sudo dd if=Hardened_NanoKVM_*.img of=/dev/da0 bs=4m conv=sync
sync
```

If your card is `/dev/mmcsd0`, use that whole-disk device instead of `/dev/da0`.
Do not write to a partition such as `/dev/da0p1`.

After writing, remove the card only after `sync` returns.

## First Boot Checklist

1. Connect Ethernet and power.
2. Find the IP address from your router DHCP leases, mDNS, or the NanoKVM OLED.
3. Open the web UI in a browser.
4. Complete first-boot account setup if prompted.
5. Go to **Settings > Check for Updates** and install the latest application
   release candidate if the SD image contains an older app.
6. Keep a known-good recovery SD image nearby before testing raw system updates.
