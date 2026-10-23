# Native C/C++ Code Audit

Last reviewed: 2026-07-11

## Scope And Status

Hardened NanoKVM uses the Rust `NanoKVM-Server`, but video capture and part of
the hardware support remain native:

- `support/sg2002/additional/kvm/`: `libkvm` C ABI and capture coordination;
- `support/sg2002/additional/kvm_mmf/`: CVI/MMF video and encoder integration;
- `support/sg2002/additional/vision/`: camera and image wrappers;
- `support/sg2002/additional/peripheral/`: I2C and other device access;
- `support/sg2002/kvm_system/`: retained OLED, button, Wi-Fi provisioning, and
  compatibility helper;
- `support/sg2002/additional/sophgo-middleware/`: vendor sensor/MMF support;
- `tools/nanokvm_update_edid/`: LT6911 EDID utility.

The Rust FFI mutex serializes calls made by Rust, but it does not serialize the
internal `libkvm` detection/watchdog threads against frame reads. The findings
below are therefore relevant to the shipped Rust backend.

The numbered list below preserves the original audit findings. All 26 findings
now have source fixes in the current working tree. The rebuilt native libraries
were tested on `10.0.87.133`; `10.0.87.132` was not used. Remaining release
coverage is listed under **Remediation Verification**.

## Priority 0: Crash, Corruption, Or Device-Wedge Risk

1. **Camera restart races with frame capture.** The HDMI detection thread calls
   `cam->restart()` without `vi_mutex`, while `kvmv_read_img()` can be inside
   `cam->read()`. `Camera::restart()` deletes and recreates `_impl`, so hotplug
   or resolution detection can cause concurrent teardown/use-after-free.
   See [kvm_vision.cpp:421](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L421),
   [kvm_vision.cpp:448](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L448),
   [kvm_vision.cpp:1770](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L1770),
   and [maix_camera.cpp:178](../support/sg2002/additional/vision/src/maix_camera.cpp#L178).

2. **`kvmv_deinit()` tears down live threads.** Initialization does not retain
   or join either `pthread_t`. Deinit destroys `vi_mutex` before setting the
   exit flag, then closes camera/MMF state and frees output buffers while the
   detection and watchdog threads can still access them. See
   [kvm_vision.cpp:1622](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L1622)
   and [kvm_vision.cpp:1907](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L1907).

3. **VENC error paths have dangling pointers, leaks, and possible double
   frees.** `mmf_venc_pop()` allocates `pstPack`, leaks it on query failure,
   frees it without nulling on several failures, and can free pack metadata
   after acquiring a stream without releasing that stream. The caller then
   invokes `mmf_venc_free()` and channel deletion against inconsistent state.
   See [kvm_mmf.cpp:2279](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L2279),
   [kvm_mmf.cpp:2294](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L2294),
   [kvm_mmf.cpp:2308](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L2308),
   and [kvm_vision.cpp:1592](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L1592).

4. **`free_all_kvmv_data()` accesses one element beyond its array.** The loop
   uses `i <= kvmv_data_buffer_size` for a four-element array and can call
   `free()` on adjacent global data. See
   [kvm_vision.cpp:1897](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L1897).

5. **Configuration readers write/read outside stack buffers.** `get_hdmi_mode()`
   declares `RW_Data[2]` and writes `RW_Data[2] = 0`. HDMI state is read as two
   bytes and passed to `atoi()` without guaranteed termination. Width/height
   files are read using their full `ftell()` size into a fixed 35-byte array.
   See [kvm_vision.cpp:282](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L282),
   [kvm_vision.cpp:1187](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L1187),
   [kvm_vision.cpp:335](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L335),
   and [kvm_vision.cpp:1392](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L1392).

6. **The H.264 NV21 stride copy uses the frame height as the destination row.**
   The loop variable is `h0`, but the destination is `stride * h`. When stride
   differs from width, every row overwrites the same location and the encoder
   receives a corrupted frame. See
   [kvm_mmf.cpp:2218](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L2218).

7. **No-signal automatic resolution detection is an unbounded busy loop.** On
   HDMI state `2`, an unsigned loop counter is decremented and then incremented
   by the `for` loop, so it never progresses. There is no sleep or exit check,
   and every iteration launches shell parsing through `popen()`. See
   [kvm_vision.cpp:410](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L410).

8. **I2C failures are blindly dereferenced.** `I2C::readfrom()` can return
   `nullptr`, but active LT6911 call sites dereference returned `Bytes` objects
   without checking. Two early `readfrom()` failure paths also leak their
   allocated `Bytes`. See
   [kvm_vision.cpp:553](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L553)
   and [maix_i2c.cpp:158](../support/sg2002/additional/peripheral/port/maixcam/maix_i2c.cpp#L158).

9. **JPEG and stream output allocations are unchecked.** `to_jpeg()` can fail,
   but its result is passed to `jpg_dump()`. The JPEG and H.264 dump helpers use
   `malloc()` results immediately in `memcpy()`. See
   [kvm_vision.cpp:1469](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L1469)
   and [kvm_vision.cpp:1832](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L1832).

## Priority 1: High Reliability And Resource-Lifetime Risk

10. **`get_vi_state()` and `chack_ion()` do not safely parse proc/debugfs
    output.** `get_vi_state()` does not check `popen()` and can consume
    uninitialized FPS/counter values. `chack_ion()` calls `pclose(NULL)` on one
    failure and parses uninitialized data at fixed character positions. A false
    positive reaches the software watchdog's unconditional `reboot`. See
    [kvm_vision.cpp:217](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L217)
    and [kvm_vision.cpp:466](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L466).

11. **ION leak cleanup can overflow stack buffers and truncate physical
    addresses.** Three unbounded `%s` conversions target 20-byte arrays, and a
    parsed address is cast through 32-bit `unsigned int` before assignment to a
    64-bit field. See
    [kvm_mmf.cpp:278](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L278).

12. **VB leak cleanup exits the subsystem before using it.** The parser calls
    `CVI_SYS_Exit()` and `CVI_VB_Exit()`, then calls VB handle/release APIs for
    blocks found in the same record. See
    [kvm_mmf.cpp:333](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L333).

13. **MMF mappings have unchecked and mismatched lifetime handling.** The
    return value from `CVI_SYS_MmapCache()` is not checked. One contiguous
    mapping is later passed to `CVI_SYS_Munmap()` as separate base and derived
    plane ranges instead of one matching mapping lifetime. See
    [kvm_mmf.cpp:441](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L441)
    and [kvm_mmf.cpp:465](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L465).

14. **Channel bounds checks happen too late or use the wrong comparison.** VI
    frame pop reads `vi_chn_is_inited[ch]` before validating `ch`; frame free
    has no validation; mirror/flip accepts `ch == MMF_VI_MAX_CHN` and negative
    channels; VENC functions also omit negative-channel checks. See
    [kvm_mmf.cpp:1420](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L1420),
    [kvm_mmf.cpp:1998](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L1998),
    and [kvm_mmf.cpp:2038](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L2038).

15. **VENC initialization does not roll back partial setup.** Failures after
    `CVI_VENC_CreateChn()` return without consistently stopping/destroying the
    channel and pool. Reinitialization can then fail against resources left in
    the driver. See
    [kvm_mmf.cpp:2068](../support/sg2002/additional/kvm_mmf/src/kvm_mmf.cpp#L2068).

16. **Shared native state has C++ data races.** `kvmv_cfg`, `kvm_sys_state`, and
    `kvm_oled_state` are plain fields read and written by several threads and
    signal handlers without consistent locking or atomics. This is undefined
    behavior and is especially risky on RISC-V's weak memory model. See
    [kvm_vision.cpp:114](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L114)
    and [config.h:40](../support/sg2002/kvm_system/main/include/config.h#L40).

17. **Crash handling performs unsafe teardown from signal context.** The
    SIGSEGV/SIGBUS/etc. handler logs, deinitializes MMF, and calls `exit()`, none
    of which is async-signal-safe. It can deadlock or hide the original fault.
    SIGKILL registration can never work. The camera destructor can also throw
    through `err::check_raise()`, which can terminate the process. See
    [maix_camera_mmf.hpp:30](../support/sg2002/additional/vision/port/maixcam/maix_camera_mmf.hpp#L30)
    and [maix_camera_mmf.hpp:104](../support/sg2002/additional/vision/port/maixcam/maix_camera_mmf.hpp#L104).

## Priority 2: Retained Helper, Vendor Parser, And Tooling Bugs

18. **Button input ignores failed/partial reads and can use an uninitialized
    press timestamp.** The three pthread entry functions also fall off without
    returning a `void *`; the target compiler confirms these warnings. See
    [main.cpp:66](../support/sg2002/kvm_system/main/src/main.cpp#L66).

19. **`kvm_system` can hang during shutdown when OLED is absent.** Main always
    waits for `oled_thread_running == -1`, but only a successfully started OLED
    thread writes that value. See
    [main.cpp:213](../support/sg2002/kvm_system/main/src/main.cpp#L213).

20. **OLED Ethernet rendering consumes uninitialized stack data and has a
    switch fallthrough.** State `1` passes an uninitialized byte as a C string;
    state `2` immediately falls through and clears the network error indicator.
    See [oled_ui.cpp:208](../support/sg2002/kvm_system/main/lib/oled_ui/oled_ui.cpp#L208).

21. **QR rendering leaks both the QR object and BMP buffer.** Repeated Wi-Fi/AP
    QR page use grows the helper process. See
    [oled_ui.cpp:97](../support/sg2002/kvm_system/main/lib/oled_ui/oled_ui.cpp#L97).

22. **Wi-Fi status rewrites an SD-backed file every polling cycle.** The helper
    launches `system("echo ...")` for `/kvmapp/kvm/wifi_state` even when the
    state did not change, causing process churn and unnecessary SD writes. See
    [system_state.cpp:686](../support/sg2002/kvm_system/main/lib/system_state/system_state.cpp#L686).

23. **Vendor sensor INI parsers can overflow an eight-byte stack buffer.**
    `parse_lane_id()` and `parse_pn_swap()` copy a token of up to 29 bytes into
    `char buf[8]`. See
    [sample_common_sensor.c:1807](../support/sg2002/additional/sophgo-middleware/v2/sample/common/sample_common_sensor.c#L1807).

24. **The EDID utility silently accepts oversized input by truncation.** It
    reads at most 256 bytes and does not verify EOF. Its cached I2C page offset
    is updated before the page-select write succeeds, so a retry can use the
    wrong page after a transient failure. See
    [nanokvm_update_edid.c:27](../tools/nanokvm_update_edid/nanokvm_update_edid.c#L27)
    and [nanokvm_update_edid.c:104](../tools/nanokvm_update_edid/nanokvm_update_edid.c#L104).

25. **The native debug wrapper drops all variadic arguments.** When debug is
    enabled, `printf(format)` interprets `%d`, `%s`, and similar conversions
    without corresponding arguments. Production currently initializes native
    logging with debug disabled, but enabling it is undefined behavior. See
    [kvm_vision.cpp:121](../support/sg2002/additional/kvm/src/kvm_vision.cpp#L121).

26. **The standalone vision test can free an uninitialized pointer.** Every
    third loop iteration leaves the return value/frame pointer unset, then
    prints and frees them. This is test-only, not the shipped server path. See
    [kvm_vision_test/main.cpp:43](../support/sg2002/kvm_vision_test/main/src/main.cpp#L43).

## Verification Performed

- Reviewed all tracked C/C++ sources and separated active project code from
  vendor libraries, utilities, and test-only code.
- Ran the retained RISC-V target compiler over `kvm_system` with `-Wextra`,
  `-Wformat=2`, bounds/string warnings, duplicated-branch checks, and related
  diagnostics. It completed and confirmed missing pthread returns and several
  logic warnings. The normal project build currently uses only `-Wall`.
- Ran host GCC/Clang static analysis over the standalone EDID/libqr C code. It
  did not report additional analyzer findings; that does not cover native MMF
  runtime behavior or thread races.
- `cppcheck` and `clang-tidy` were not installed in the review environment.
- No native binaries were rebuilt, no device was modified, and no hardware
  runtime test was performed for this audit.

The statements above describe the audit checkpoint before remediation.

## Remediation Verification

Completed on 2026-07-11:

- rebuilt `libkvm.so`, `libkvm_mmf.so`, `kvm_system`, and the EDID utility with
  the target RISC-V toolchain;
- synchronized the vendored sensor-name table with the active MaixCDK
  `SAMPLE_SNS_TYPE_E`; this fixed a clean-build LT6911 numeric-ID mismatch that
  prevented VI initialization;
- passed all Rust tests: 145 library, 6 hwmon, and 2 server tests;
- built the statically linked RISC-V Rust backend and final application archive;
- deployed the final native libraries to `10.0.87.133`, verified their hashes,
  and performed a full reboot;
- authenticated MJPEG returned a valid multipart JPEG stream (16,011,661 bytes
  sampled, JPEG marker `ff d8 ff`);
- H.264 Direct completed the WebSocket upgrade and returned SPS/PPS/IDR data
  (1,617,945 bytes sampled; first native frame 144,175 bytes);
- controlled backend stop/start replaced PID 766 with PID 1117, reinitialized
  VI/VPSS, and returned stable HTTPS health afterward.

Final tested native hashes:

- `libkvm.so`: `8ebe4ba3ce537bd95b1ca819e20d43aa623442e5972cc29a4328f8b66a740bde`;
- `libkvm_mmf.so`: `be269c595b454930abeb9bb05eb67ec708894eb2df1650c4d99ee1162e1e3f2d`.

Still required before release: repeated HDMI hotplug and resolution changes,
physical OLED/button behavior, fault injection for vendor failure paths, and a
long-running dmesg/syslog soak.

### EDID utility: read and save before erasing (2026-10-23)

`nanokvm_update_edid` used to erase the LT6911 flash before it checked the
chip, kept no copy of the EDID it replaced, and stopped after a failed write
with the flash erased. It now:

- reads the current EDID with the chip's own read sequence before anything is
  erased, and stops unless the result is an erased flash or an EDID header
  whose base block checksum is valid, which a wrong `hdmi_version` would not
  return;
- saves that EDID to a new file `/data/edid-backup-<seconds>.bin` (mode 0600,
  fsynced) and stops if it cannot;
- writes the new EDID and reads it back; on any failure it writes the saved
  EDID again, verifies it, and otherwise names the backup to write before a
  reboot.

The chip-specific register sequences are unchanged. `scripts/test-nanokvm-update-edid.sh`
builds the utility for the host against a model of the LT6911UXC registers
(`tools/nanokvm_update_edid/test-fake-bus.c`) and covers an update, a chip
without an EDID, an erased chip, a write that fails after the erase, and a
missing backup directory.

The committed RISC-V binary was the vendor build: neither the current source
nor the upstream 413cdd9 source reproduces it, and it lacked the earlier input
and page-offset fixes. It is now built from this source with the MaixCDK
Xuantie GCC 10.2.0 toolchain (`riscv64-unknown-linux-musl-gcc
-I<toolchain>/sysroot/usr/include -march=rv64gc`), which gives the same bytes
from any directory: sha256
`cfdda07b503d22ce47f56ea926bfedc243a911935c74121522f17ba61597e347`. It has not
been run on hardware. Flashing a real device is a destructive check that
needs its own approval and a recovery path. The tool still shares the I2C bus
with `kvm_system` without a common lock.

### libkvm: no C++ exception past the C interface (2026-10-23)

The vendor camera, encoder and I2C wrappers report failures as C++
exceptions: `err::check_raise` in the H.264 encoder setup, and
`cam->restart`, `cam->set_resolution`, `cam->hmirror` and `cam->close`. One
thrown inside `kvmv_read_img`, `kvmv_init`, `kvmv_deinit` or a worker thread
reached `std::terminate` and could leave `vi_mutex` held. Now:

- every lock of `vi_mutex` goes through a scoped guard that releases it on any
  exit, including an exception;
- `kvmv_read_img` returns `IMG_VENC_ERROR` with no data;
- a throwing camera setup in `kvmv_init` leaves video stopped and both locks
  free;
- a throwing camera close in `kvmv_deinit` is reported as an incomplete
  shutdown, the same as a worker that does not stop: the camera and MMF
  state stay as they are, and a later `kvmv_init` refuses;
- the HDMI detection and watchdog threads end with a log line instead of
  terminating the backend, and a throwing restart from the detection thread
  only fails that restart.

`scripts/test-kvm-vision-exceptions.sh` builds the real `kvm_vision.cpp` for
the host against stand-ins for the vendor API that throw on request (under
`support/sg2002/additional/kvm/test/`). The stand-ins also replace `system()`,
so no shell command of the code under test runs on the host. Six cases cover
both workers, a resolution change, the encoder setup, the camera setup and
the camera close. The previous source, and each fix taken out alone, end the
test with `std::terminate` or a held `vi_mutex`.

MaixCDK compiles the copy in `MaixCDK/components/kvm`, which must equal this
source. Rebuilding the unchanged source reproduced the committed library
byte for byte (sha256 `4f86642e…`). The new `server-rust/native/dl_lib/libkvm.so`,
sha256 `1f32d768f6f4dd7e7221d9c191589499b127b2793b65e55be17cb3386f4af105`,
has the same exported and imported symbols, NEEDED libraries and SONAME, and
no RPATH. It has not run on hardware. Still open: the global `camera::Camera`
is constructed when the library loads, outside any boundary; an image already
read is leaked when a later step throws; the camera state after a vendor
exception is left to the existing restart path. Device acceptance needs
MJPEG, H.264, resolution changes, HDMI hotplug and a backend restart.

## Recommended Repair Order

1. Introduce explicit native lifecycle ownership: retain thread handles, stop
   and join threads, then destroy the mutex/camera/MMF state.
2. Put restart, resolution changes, frame reads, and deinit behind the same
   lifecycle lock and state machine.
3. Fix VENC stream ownership/error cleanup and the NV21 row-copy index; add
   failure-injection tests around query/get/release paths.
4. Fix all definite array bounds, null checks, and allocation checks.
5. Replace proc/debugfs fixed-position parsers and remove reboot decisions from
   ambiguous parse failures.
6. Fix retained `kvm_system` races, SD-write polling, OLED/button bugs, and QR
   leaks without expanding its responsibilities.
7. Rebuild the linked Rust/native package, deploy to `10.0.87.133`, and test
   MJPEG, H.264 Direct, HDMI hotplug, repeated resolution changes, stream-mode
   switching, controlled backend restart, OLED/button behavior, and long-run
   dmesg/syslog health before publishing another release.
