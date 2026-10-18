//! Compile-bound app recovery bytes. Independent rootfs installation and early
//! consumer gates are still separate work; this is not bootstrap readiness.

use super::restore_binding;
use std::io;

/// Only a trusted backend build supplies these immutable bytes. No runtime
/// pathname, manifest, environment variable or bundled helper is a fallback.
/// This checks framing/ELF/build consistency, not a release RSA signature.
pub fn embedded_recovery() -> io::Result<&'static [u8]> {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/app-recovery.binding"));
    let binding = restore_binding::validate_app_recovery(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid embedded app recovery"))?;
    Ok(binding.image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_recovery_has_no_path_fallback() {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/app-recovery.binding"));
        if bytes.is_empty() {
            assert!(embedded_recovery().is_err());
        } else {
            let expected = restore_binding::validate_app_recovery(bytes).unwrap();
            assert_eq!(embedded_recovery().unwrap(), expected.image);
            assert!(restore_binding::validate(bytes).is_err());
        }
    }
}
