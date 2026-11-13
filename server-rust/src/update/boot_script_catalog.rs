//! Bounded top-level catalog inspection, NOT provenance or upgrade authority.
//!
//! The caller must keep a protected authenticated backend stable. An FD and
//! matching frames do not provide immutable-source, install or exec permission.

use super::{boot_script_binding as binding, helper_family};
pub use binding::{ROLES, Role};
use std::{fs::File, io, os::unix::fs::FileExt};

const CHUNK: usize = 64 * 1024;
const MAX_MARKERS: usize = 64;
const MAX_HASH_BYTES: u64 = 8 * binding::MAX_SCRIPT as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Member {
    role: Role,
    start: u64,
    end: u64,
    size: u64,
    sha256: [u8; 32],
}

impl Member {
    pub(super) fn payload_range(&self) -> std::ops::Range<u64> {
        self.start + binding::HEADER as u64..self.end
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// Four unambiguous, nonoverlapping top-level script frames, in fixed order.
/// No pathname, extraction method, execution or mutation capability is exposed.
#[derive(Debug, Eq, PartialEq)]
pub struct Catalog {
    members: [Member; 4],
}

impl Catalog {
    pub fn members(&self) -> &[Member; 4] {
        &self.members
    }

    pub(super) fn contains_region(&self, start: u64, end: u64) -> bool {
        self.members
            .iter()
            .any(|member| member.start <= start && start < end && end <= member.end)
    }

    pub(super) fn overlaps(&self, start: u64, end: u64) -> bool {
        self.members
            .iter()
            .any(|member| start < member.end && member.start < end)
    }
}

/// The complete helper family is checked first. Frames inside those images are
/// not the outer backend's catalog. All reads are positional and fixed-buffer;
/// source I/O errors propagate, including when a marker later proves invalid.
pub fn inspect(backend: &File) -> io::Result<Catalog> {
    let metadata = backend.metadata()?;
    if !metadata.is_file() {
        return Err(invalid());
    }
    let size = metadata.len();
    let helpers = helper_family::inspect(backend)?;
    let catalog = inspect_in_family(backend, size, &helpers)?;
    if backend.metadata()?.len() != size {
        return Err(invalid());
    }
    Ok(catalog)
}

// Internal scan reuse only. The enclosing inspector binds this same pinned FD,
// size and helper family and performs its own final metadata check. Not authority.
pub(super) fn inspect_in_family(
    backend: &File,
    size: u64,
    helpers: &helper_family::Family,
) -> io::Result<Catalog> {
    inspect_with(size, helpers, |out, offset| {
        backend.read_exact_at(out, offset)
    })
}

fn inspect_with(
    size: u64,
    helpers: &helper_family::Family,
    mut read_at: impl FnMut(&mut [u8], u64) -> io::Result<()>,
) -> io::Result<Catalog> {
    if !(64..=helper_family::MAX_BACKEND_BYTES).contains(&size) {
        return Err(invalid());
    }
    let mut found: [Option<Member>; 4] = [None; 4];
    let mut markers = [0; 4];
    let mut hash_remaining = MAX_HASH_BYTES;
    let mut scan = [0; CHUNK + 7];
    let mut frame = [0; binding::HEADER + binding::MAX_SCRIPT];
    let mut offset = 0;
    while offset < size {
        let count = (size - offset).min(CHUNK as u64) as usize;
        let available = (size - offset).min(scan.len() as u64) as usize;
        read_at(&mut scan[..available], offset)?;
        for start in 0..count {
            if scan[start] != b'N' || available - start < 8 {
                continue;
            }
            let Some(index) = ROLES
                .iter()
                .position(|role| &scan[start..start + 8] == role.magic())
            else {
                continue;
            };
            let start = offset + start as u64;
            if helpers.contains_offset(start) {
                continue;
            }
            markers[index] += 1;
            if markers[index] > MAX_MARKERS {
                return Err(invalid());
            }
            if let Some(member) = inspect_member(
                ROLES[index],
                start,
                size,
                &mut read_at,
                &mut frame,
                &mut hash_remaining,
            )? {
                if helpers.overlaps(member.start, member.end)
                    || found[index].is_some()
                    || found
                        .iter()
                        .flatten()
                        .any(|other| member.start < other.end && other.start < member.end)
                {
                    return Err(invalid());
                }
                found[index] = Some(member);
            }
        }
        offset += count as u64;
    }
    let [Some(recovery), Some(ethernet), Some(wifi), Some(nanokvm)] = found else {
        return Err(invalid());
    };
    Ok(Catalog {
        members: [recovery, ethernet, wifi, nanokvm],
    })
}

fn inspect_member(
    role: Role,
    start: u64,
    backend_size: u64,
    read_at: &mut impl FnMut(&mut [u8], u64) -> io::Result<()>,
    frame: &mut [u8; binding::HEADER + binding::MAX_SCRIPT],
    hash_remaining: &mut u64,
) -> io::Result<Option<Member>> {
    let Some(body_start) = start
        .checked_add(binding::HEADER as u64)
        .filter(|end| *end <= backend_size)
    else {
        return Ok(None);
    };
    read_at(&mut frame[..binding::HEADER], start)?;
    if &frame[..8] != role.magic() {
        return Err(invalid());
    }
    let size = u64::from_le_bytes(frame[8..16].try_into().map_err(|_| invalid())?);
    let Some(end) = body_start
        .checked_add(size)
        .filter(|end| *end <= backend_size)
    else {
        return Ok(None);
    };
    if !(1..=binding::MAX_SCRIPT as u64).contains(&size) {
        return Ok(None);
    }
    *hash_remaining = hash_remaining.checked_sub(size).ok_or_else(invalid)?;
    let length = binding::HEADER + size as usize;
    read_at(&mut frame[binding::HEADER..length], body_start)?;
    if binding::validate(&frame[..length], role).is_err() {
        return Ok(None);
    }
    Ok(Some(Member {
        role,
        start,
        end,
        size,
        sha256: frame[16..binding::HEADER]
            .try_into()
            .map_err(|_| invalid())?,
    }))
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or ambiguous backend boot script catalog",
    )
}

#[cfg(test)]
#[path = "boot_script_catalog_tests.rs"]
mod tests;
