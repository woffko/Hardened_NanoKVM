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

`dl_lib/libkvm.so` and `dl_lib/libkvm_mmf.so` are built with MaixCDK from those
sources and from two more files: `peripheral/port/maixcam/maix_i2c.cpp` and the
vendor file `sophgo-middleware/v2/sample/common/sample_common_sensor.c`. The
application build only copies the committed libraries, so a source can change
without them. `library-sources.sha256` records every source and both libraries
as they were at the last rebuild, and `scripts/native-library-sources.sh check`
(a host test) fails when either side has moved since. After a rebuild, commit
the libraries and run `scripts/native-library-sources.sh write`.

`kvm_system` is built from `support/sg2002/kvm_system` the same way and is not
committed: each application build names the binary it packages.

The Rust server is the only supported backend for these runtime assets.
