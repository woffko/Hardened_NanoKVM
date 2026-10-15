# NanoKVM Native Runtime Assets

This directory contains the native NanoKVM runtime pieces used by the Rust
backend.

- `dl_lib/` is packaged to the device as `/kvmapp/server/dl_lib`.
- `include/` contains the C ABI header used by the Rust FFI bindings.

The corresponding native sources are under `support/sg2002/additional/kvm`,
`kvm_mmf`, `vision`, and `peripheral`. The Rust FFI mutex serializes calls made
by Rust, but native capture/detection threads still have their own lifecycle.
Known native lifecycle, VENC, bounds, and hardware-error findings are tracked in
[`docs/native-code-audit.md`](../../docs/native-code-audit.md).

The Rust server is the only supported backend for these runtime assets.

## libkvm.so: removed video NEEDED entry

`dl_lib/libkvm.so` originally declared `DT_NEEDED` on
`libopencv_video.so.409`, which in this build's OpenCV pulls in a chain
(`video`→`dnn`+`calib3d`; `calib3d`→`features2d`+`flann`; `dnn`→`protobuf`)
of 6 additional non-redistributable vendor libraries. Verified via
`readelf --dyn-syms` that `libkvm.so` calls nothing from any of them: its
184 undefined function symbols were checked against video's exports
directly (zero overlap) and against the full export set unique to
video/dnn/calib3d/features2d/flann as a group, not also provided by
core/imgproc/imgcodecs/highgui (still zero overlap, 978 candidate symbols
checked). This points to the dependency being a MaixCDK build-convention
artifact (linking a common library set), not a real call path.

Patched with `patchelf --remove-needed libopencv_video.so.409 dl_lib/libkvm.so`.
This only edits the ELF dynamic section (verified: file size and the full
184-symbol undefined-symbol set are unchanged) -- no code is modified.
`libkvm.so` now needs only `core`/`highgui`/`imgcodecs`/`imgproc` from
OpenCV, matching the exact 4 modules `sipeed/NanoKVM` (the GPL-3.0
upstream) ships in its own `server/dl_lib/`, rather than the 9 this fork's
vendor-runtime staging previously carried. `libkvm_mmf.so` never needed
any OpenCV module.

Not yet verified on real hardware -- this is static analysis (symbol-table
comparison), not a device boot/video test. If HDMI capture or any vision
feature breaks after this change, this is the first thing to revert.

## /mnt/system/usr: pruned to the one file dl_lib doesn't cover

`/mnt/system/usr/bin` (CVITEK sample/test binaries: `sample_vcodec`,
`sample_venc`, `sample_vdec`, `ive_stress`, `sensor_test`, `test_mmf`, etc.)
and most of `/mnt/system/usr/lib` (the same CVI/ISP/audio libraries already
present in `dl_lib`, plus `libov_ov2685.so`, `libraw_replay.so`,
`libsample.so`, and 5 `libsns_*.so` sensor plugins for sensors this
hardware doesn't have -- only the LT6911 HDMI bridge is real here) look
like unpruned vendor SDK carry-forward, not load-bearing content.

Provenance: same as the loaders and `auto.sh` above -- extracted wholesale
via `debugfs rdump /mnt/system` from `make vendor-sdk-stock`'s own build
output in `scripts/prepare-latest-buildroot-sg2002-vendor-runtime.sh`,
frozen into the vendor-runtime staging bundle, carried forward unchanged
since.

`/etc/init.d/S95nanokvm` does wire `/mnt/system/usr/lib` and
`/mnt/system/usr/lib/3rd` into the native library search path
(`NANOKVM_NATIVE_LIBRARY_PATH`, passed to the musl loader's
`--library-path` when launching the server, `kvm_system`, and
`nanokvm-hwmon`) -- so it's not simply unreferenced, it's a deliberate
fallback. But `/kvmapp/server/dl_lib` is checked first in that same path
and already contains every file `/mnt/system/usr/lib` and its `3rd/`
subdirectory (`libcli.so`, `libini.so`) have, except exactly the
suspect files above -- so the fallback never actually gets exercised for
anything these binaries need.

Compared the 22 overlapping libraries byte-for-byte on the same rootfs:
16 are identical between `dl_lib` and `/mnt/system/usr/lib`, but 6
(`libcvi_bin.so`, `libsys.so`, `libvdec.so`, `libvpu.so`, `libmisc.so`,
`libosdc.so`) are the same name and size but substantively different
content -- e.g. `libsys.so` differs in 38,510 of 60,472 bytes, far
beyond a timestamp/build-id difference. So `/mnt/system/usr/lib` isn't
simply "the same files copied twice"; it looks like a separate, older
snapshot of the vendor SDK's own libraries that happens to share
names/sizes with what got curated into `dl_lib`. Doesn't change the
functional conclusion (`dl_lib` still wins the search-path race
regardless of which build variant sits in the fallback), but it's a
more accurate description than "duplicate."

Checked for a `dlopen()`-style indirect reference (the one thing static
`strings`/symbol analysis can miss) in `libkvm.so`, `libkvm_mmf.so`,
`kvm_system`, and `nanokvm-hwmon`, plus every script under `/etc` and
`/kvmapp/system` and this repo's own tracked source
(`server-rust`, `web`, `support/sg2002`, `scripts`): zero genuine hits.
The one grep match (`support/sg2002/additional/sophgo-middleware/v2/sample/common/sample_common_sensor.c`)
is a false positive -- a self-referential filename comment and header
include, unrelated to the `/mnt/system/usr/bin` executables.

**Acted on, narrower than "drop it entirely."** Checking `dl_lib`'s actual
file listing against `/mnt/system/usr/lib`'s turned up one exception to
the above: `libsns_lt6911.so`, the sensor plugin for the LT6911 HDMI
bridge -- this device's one real sensor -- has no copy anywhere in
`dl_lib`, unlike every other file in `/mnt/system/usr/lib`. Deleting it
along with the rest would have risked the one thing this device actually
does (HDMI capture), for no size benefit worth that risk.

`hardened-sg2002-vendor-runtime.mk` now removes `/mnt/system/usr/bin`
entirely and prunes `/mnt/system/usr/lib` (including the `3rd/`
subdirectory) down to exactly `libsns_lt6911.so`. Everything *removed* is
either proven redundant (shadowed by `dl_lib` in the library search order)
or has no reference anywhere in this repo's tracked source. The retained
file's own provenance is now fully resolved too -- see "libc.so, GCC
runtime, loaders, and libsns_lt6911.so" below; it no longer comes from
raw.12 either. Not yet verified on real hardware; if HDMI capture breaks
after this change, this is still the first thing to check.
