//! Compile-bound static native programs, not install/launch authorization.
use crate::update::restore_binding::{self, NativeRuntime};
use std::io;

#[inline(never)]
fn frame(runtime: NativeRuntime) -> &'static [u8] {
    let bytes: &[u8] = match runtime {
        NativeRuntime::Owner => {
            include_bytes!(concat!(env!("OUT_DIR"), "/nanokvm-native-owner.binding"))
        }
        NativeRuntime::Broker => {
            include_bytes!(concat!(env!("OUT_DIR"), "/nanokvm-native-broker.binding"))
        }
        NativeRuntime::Client => {
            include_bytes!(concat!(env!("OUT_DIR"), "/nanokvm-native-ctl.binding"))
        }
        NativeRuntime::Recovery => {
            include_bytes!(concat!(env!("OUT_DIR"), "/nanokvm-native-recovery.binding"))
        }
    };
    std::hint::black_box(bytes)
}

pub(crate) fn image(runtime: NativeRuntime) -> io::Result<&'static [u8]> {
    restore_binding::validate_native(frame(runtime), runtime)
        .map(|binding| binding.image)
        .map_err(|_| {
            // Build-input names are diagnostics, never runtime env selectors.
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid embedded {} ({})",
                    runtime.filename(),
                    runtime.variable()
                ),
            )
        })
}

pub fn check_embedded() -> io::Result<()> {
    for runtime in restore_binding::NATIVE_RUNTIMES {
        let _ = image(runtime)?;
    }
    Ok(())
}
