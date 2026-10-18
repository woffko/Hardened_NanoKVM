//! Build/runtime shared framing, not a signature or a trust decision. Only
//! bytes embedded by the trusted backend build are runtime helper authority.

use sha2::{Digest, Sha256};
use std::io;

pub const MAGIC: &[u8; 8] = b"NKSSHRT1";
pub const APP_RECOVERY_MAGIC: &[u8; 8] = b"NKAPPBT1";
pub const HEADER: usize = 48;
pub const MAX_HELPER: u64 = 32 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidBinding;

pub struct Binding<'a> {
    pub image: &'a [u8],
    pub digest: [u8; 32],
}

pub fn validate(bytes: &[u8]) -> Result<Binding<'_>, InvalidBinding> {
    validate_domain(bytes, MAGIC)
}

pub fn validate_app_recovery(bytes: &[u8]) -> Result<Binding<'_>, InvalidBinding> {
    validate_domain(bytes, APP_RECOVERY_MAGIC)
}

fn validate_domain<'a>(bytes: &'a [u8], magic: &[u8; 8]) -> Result<Binding<'a>, InvalidBinding> {
    if bytes.len() < HEADER || &bytes[..8] != magic {
        return Err(InvalidBinding);
    }
    let size = u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| InvalidBinding)?);
    if !(64..=MAX_HELPER).contains(&size) || bytes.len() as u64 != HEADER as u64 + size {
        return Err(InvalidBinding);
    }
    let digest: [u8; 32] = bytes[16..HEADER].try_into().map_err(|_| InvalidBinding)?;
    let image = &bytes[HEADER..];
    if <[u8; 32]>::from(Sha256::digest(image)) != digest {
        return Err(InvalidBinding);
    }
    check_static_rv64(size, |buffer, offset| {
        let start = usize::try_from(offset).map_err(|_| io::ErrorKind::InvalidData)?;
        let end = start
            .checked_add(buffer.len())
            .ok_or(io::ErrorKind::InvalidData)?;
        let source = image.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?;
        buffer.copy_from_slice(source);
        Ok(())
    })?;
    Ok(Binding { image, digest })
}

// Bounded reads only, shared with anonymous-file capture. No allocation, path
// lookup, dynamic interpreter/table, or architecture fallback.
pub fn check_static_rv64(
    size: u64,
    mut read_at: impl FnMut(&mut [u8], u64) -> io::Result<()>,
) -> Result<(), InvalidBinding> {
    if !(64..=MAX_HELPER).contains(&size) {
        return Err(InvalidBinding);
    }
    let mut header = [0; 64];
    read_at(&mut header, 0).map_err(|_| InvalidBinding)?;
    let u16_at = |n| u16::from_le_bytes([header[n], header[n + 1]]);
    let phoff = u64::from_le_bytes(header[32..40].try_into().map_err(|_| InvalidBinding)?);
    let count = u16_at(56);
    if &header[..7] != b"\x7fELF\x02\x01\x01"
        || u16_at(16) != 2
        || u16_at(18) != 243
        || header[20..24] != 1_u32.to_le_bytes()
        || u16_at(52) != 64
        || u16_at(54) != 56
        || !(1..=128).contains(&count)
        || phoff < 64
        || phoff
            .checked_add(u64::from(count) * 56)
            .is_none_or(|end| end > size)
    {
        return Err(InvalidBinding);
    }
    let mut load = false;
    let mut program = [0; 56];
    for n in 0..count {
        read_at(&mut program, phoff + u64::from(n) * 56).map_err(|_| InvalidBinding)?;
        match u32::from_le_bytes(program[..4].try_into().map_err(|_| InvalidBinding)?) {
            1 => {
                let u64_at = |n| {
                    program[n..n + 8]
                        .try_into()
                        .map(u64::from_le_bytes)
                        .map_err(|_| InvalidBinding)
                };
                let offset = u64_at(8)?;
                let address = u64_at(16)?;
                let filesz = u64_at(32)?;
                let memsz = u64_at(40)?;
                let align = u64_at(48)?;
                if offset.checked_add(filesz).is_none_or(|end| end > size)
                    || memsz < filesz
                    || address.checked_add(memsz).is_none()
                    || (align > 1
                        && (!align.is_power_of_two() || address % align != offset % align))
                {
                    return Err(InvalidBinding);
                }
                load = true;
            }
            2 | 3 => return Err(InvalidBinding),
            _ => {}
        }
    }
    if load { Ok(()) } else { Err(InvalidBinding) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> Vec<u8> {
        let mut image = vec![0; 120];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        image[16..18].copy_from_slice(&2_u16.to_le_bytes());
        image[18..20].copy_from_slice(&243_u16.to_le_bytes());
        image[20..24].copy_from_slice(&1_u32.to_le_bytes());
        image[32..40].copy_from_slice(&64_u64.to_le_bytes());
        image[52..54].copy_from_slice(&64_u16.to_le_bytes());
        image[54..56].copy_from_slice(&56_u16.to_le_bytes());
        image[56..58].copy_from_slice(&1_u16.to_le_bytes());
        image[64..68].copy_from_slice(&1_u32.to_le_bytes());
        image
    }
    fn envelope(image: &[u8]) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&(image.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&Sha256::digest(image));
        bytes.extend_from_slice(image);
        bytes
    }

    #[test]
    fn exact_binding_and_no_trailer_or_corruption() {
        let image = image();
        let mut bytes = envelope(&image);
        let binding = validate(&bytes).unwrap();
        assert_eq!(binding.image, image);
        assert_eq!(binding.digest, <[u8; 32]>::from(Sha256::digest(&image)));
        bytes.push(0);
        assert!(validate(&bytes).is_err());
        bytes.pop();
        bytes[HEADER] ^= 1;
        assert!(validate(&bytes).is_err());
    }

    #[test]
    fn app_and_ssh_domains_cannot_substitute_for_each_other() {
        let image = image();
        let ssh = envelope(&image);
        let mut app = ssh.clone();
        app[..8].copy_from_slice(APP_RECOVERY_MAGIC);
        assert!(validate_app_recovery(&ssh).is_err());
        assert!(validate(&app).is_err());
        assert_eq!(validate_app_recovery(&app).unwrap().image, image);
        app.push(0);
        assert!(validate_app_recovery(&app).is_err());
        app.pop();
        app[HEADER] ^= 1;
        assert!(validate_app_recovery(&app).is_err());
    }

    #[test]
    fn malformed_and_unbounded_framing_fails_closed() {
        for bytes in [vec![], vec![0; HEADER], MAGIC.to_vec()] {
            assert!(validate(&bytes).is_err());
        }
        let valid = envelope(&image());
        for size in [0, 63, MAX_HELPER + 1, u64::MAX] {
            let mut bytes = valid.clone();
            bytes[8..16].copy_from_slice(&size.to_le_bytes());
            assert!(validate(&bytes).is_err());
        }
        for length in [HEADER, valid.len() - 1] {
            assert!(validate(&valid[..length]).is_err());
        }
    }

    #[test]
    fn hash_cannot_authorize_dynamic_or_foreign_elf() {
        for (offset, value) in [
            (4, 1),
            (5, 2),
            (16, 3),
            (18, 62),
            (52, 63),
            (54, 55),
            (56, 0),
        ] {
            let mut elf = image();
            elf[offset] = value;
            assert!(validate(&envelope(&elf)).is_err());
        }
        for kind in [0_u32, 2, 3] {
            let mut elf = image();
            elf[64..68].copy_from_slice(&kind.to_le_bytes());
            assert!(validate(&envelope(&elf)).is_err());
        }
        let mut elf = image();
        elf[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(validate(&envelope(&elf)).is_err());
    }

    #[test]
    fn load_ranges_and_alignment_are_checked() {
        for (offset, value) in [(72, u64::MAX), (96, 121), (112, 3)] {
            let mut elf = image();
            elf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(validate(&envelope(&elf)).is_err());
        }
        let mut elf = image();
        elf[96..104].copy_from_slice(&1_u64.to_le_bytes()); // filesz > memsz
        assert!(validate(&envelope(&elf)).is_err());
        let mut elf = image();
        elf[80..88].copy_from_slice(&1_u64.to_le_bytes());
        elf[112..120].copy_from_slice(&4096_u64.to_le_bytes());
        assert!(validate(&envelope(&elf)).is_err());
        let mut elf = image();
        elf[80..88].copy_from_slice(&u64::MAX.to_le_bytes());
        elf[104..112].copy_from_slice(&1_u64.to_le_bytes());
        assert!(validate(&envelope(&elf)).is_err());
    }
}
