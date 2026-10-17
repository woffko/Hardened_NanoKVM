# File-backed USB storage migration (development)

This describes the audit-remediation branch, not the published RC12 artifacts.
The complete C1 fix is not yet release-ready: authenticated raw restore, private
app staging and interrupted-install recovery remain separate required gates.

## Intended behavior

- USB storage exports a selected ISO/IMG file, never `/dev/mmcblk0p3`, even
  read-only. Eject leaves the drive empty. Disk toggle enables/disables an empty
  drive; it does not expose the SD data filesystem.
- `/boot/usb.disk0` is only an enable flag. Its old contents and `usb.disk0.ro`
  cannot select a backing device. Startup closes any pre-existing LUN before
  accepting API requests. A target's prevent-removal lock causes disconnection
  and a migration error, not continued raw export.
- Only `/data/media` is user media storage. Legacy `image_directory: /data`
  maps there; other roots are rejected. Symlink components, hardlink aliases,
  cross-filesystem files and locally loop-attached images are not exportable.
- Top-level legacy ISO/IMG files move into `media` without overwriting existing
  names. Colliding originals stay in `/data`; nested directories and service
  trees are not imported. No legacy cache/preserve directory is deleted.
- Mount, eject, reconnect, virtual-device changes, HID reset/recovery and final
  upload publication share one backend lock. A second operation gets a conflict;
  loss of the requesting HTTP connection does not cancel a running switch.
  An active backing image cannot be replaced or deleted through the media API.

Writable IMG remains supported. It belongs to the target while exported;
NanoKVM must not mount the same file locally. Detach local loop devices first.

## Upgrade precautions

An old app's upload path cannot be secured retroactively by the new app.
Before installing the eventual fix, disconnect target USB data and verify
independent management networking/power. Do not disconnect the sole USB network
management path without preparing another channel.

New boot scripts mount FAT/exFAT with root ownership, file mask `0177`, directory
mask `0077`, and `nosuid,nodev,noexec`. The backend checks effective mount options,
not a successful command alone. Vendor FAT/exFAT cannot change these masks by
remounting. The app-only transition therefore uses a normal unmount/mount before
API writers start. It never forces/lazily unmounts a busy filesystem; a busy or
failed transition requires recovery/reboot and does not open management APIs.

The full device acceptance must still prove file mount/eject/reconnect, HID and
USB network continuity, masks after reboot, legacy-flag handling and all switch
failure paths. Host fixtures alone do not establish those properties.

An installation already compromised through an old writable raw LUN needs a
trusted SD reflash and a separately planned secret rotation. Closing the LUN
cannot undo prior disclosure or make old preserved executable/configuration
data trustworthy.
