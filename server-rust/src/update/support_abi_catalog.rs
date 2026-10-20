//! Scoped ABI consistency diagnostics, NOT trusted source or install authority.
//!
//! A backend FD is not immutable. Protected provenance and retained runtime/
//! writer ownership remain required before any later support-file mutation.

use super::{boot_script_catalog, helper_family, support_abi as abi};
use std::{fs::File, io, os::unix::fs::FileExt};

const CHUNK: usize = 64 * 1024;
const MAX_MARKERS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Member {
    declaration: abi::Declaration,
    start: u64,
    end: u64,
}

impl Member {
    pub fn declaration(&self) -> abi::Declaration {
        self.declaration
    }
}

/// One backend and five image-local declarations, in fixed role order.
/// No offsets, extraction, command selection or mutation capability is public.
#[derive(Debug, Eq, PartialEq)]
pub struct Catalog {
    members: [Member; 6],
}

impl Catalog {
    pub fn members(&self) -> &[Member; 6] {
        &self.members
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityError {
    UnknownOrIncompatible,
    UnsupportedTransition,
}

// The only external entry supplies the executing build's constant. No caller
// can provide a fake running-broker version via an ID, descriptor or path.
pub(crate) fn check_transition(
    predecessor: &Catalog,
    successor: &Catalog,
) -> Result<(), CompatibilityError> {
    check_with_live(predecessor, successor, abi::CURRENT)
}

fn check_with_live(
    predecessor: &Catalog,
    successor: &Catalog,
    live: abi::Epochs,
) -> Result<(), CompatibilityError> {
    if live != abi::CURRENT
        || [predecessor, successor].into_iter().any(|catalog| {
            catalog
                .members
                .iter()
                .any(|member| member.declaration.epochs != live)
        })
    {
        return Err(CompatibilityError::UnknownOrIncompatible);
    }
    if live.support_transition == 0 {
        return Err(CompatibilityError::UnsupportedTransition);
    }
    Ok(())
}

/// Validate helper/script scopes first, then scan each structural marker once.
/// Unknown checksum-valid declarations fail closed; invalid literals are bounded.
/// Unknown group epochs remain visible and fail the separate compatibility check.
pub fn inspect(backend: &File) -> io::Result<Catalog> {
    let metadata = backend.metadata()?;
    if !metadata.is_file() {
        return Err(invalid());
    }
    let size = metadata.len();
    let helpers = helper_family::inspect(backend)?;
    let scripts = boot_script_catalog::inspect_in_family(backend, size, &helpers)?;
    let catalog = inspect_in_catalogs(backend, size, &helpers, &scripts)?;
    if backend.metadata()?.len() != size {
        return Err(invalid());
    }
    Ok(catalog)
}

// Reuse only under a caller's same pinned FD, size and stable-source checks.
// These catalogs are consistency diagnostics, not immutable-source authority.
pub(super) fn inspect_in_catalogs(
    backend: &File,
    size: u64,
    helpers: &helper_family::Family,
    scripts: &boot_script_catalog::Catalog,
) -> io::Result<Catalog> {
    inspect_with(size, helpers, scripts, |out, offset| {
        backend.read_exact_at(out, offset)
    })
}

fn scope(offset: u64, helpers: &helper_family::Family) -> usize {
    helpers
        .members()
        .iter()
        .position(|member| member.image_range().contains(&offset))
        .map_or(0, |index| index + 1)
}

fn check_region(
    index: usize,
    start: u64,
    end: u64,
    helpers: &helper_family::Family,
    scripts: &boot_script_catalog::Catalog,
) -> io::Result<()> {
    let valid = if index == 0 {
        !helpers.overlaps(start, end) && !scripts.overlaps(start, end)
    } else {
        let range = helpers.members()[index - 1].image_range();
        range.start <= start && start < end && end <= range.end
    };
    if valid { Ok(()) } else { Err(invalid()) }
}

fn inspect_with(
    size: u64,
    helpers: &helper_family::Family,
    scripts: &boot_script_catalog::Catalog,
    mut read_at: impl FnMut(&mut [u8], u64) -> io::Result<()>,
) -> io::Result<Catalog> {
    if !(64..=helper_family::MAX_BACKEND_BYTES).contains(&size) {
        return Err(invalid());
    }
    let mut found: [Option<Member>; 6] = [None; 6];
    let mut markers = [0; 6];
    let mut scan = [0; CHUNK + 7];
    let mut frame = [0; abi::BYTES];
    let mut offset = 0;
    while offset < size {
        let count = (size - offset).min(CHUNK as u64) as usize;
        let available = (size - offset).min(scan.len() as u64) as usize;
        read_at(&mut scan[..available], offset)?;
        for local in 0..count {
            if scan[local] != abi::MAGIC[0]
                || available - local < abi::MAGIC.len()
                || &scan[local..local + abi::MAGIC.len()] != abi::MAGIC
            {
                continue;
            }
            let start = offset + local as u64;
            let index = scope(start, helpers);
            markers[index] += 1;
            if markers[index] > MAX_MARKERS {
                return Err(invalid());
            }
            let Some(end) = start
                .checked_add(abi::BYTES as u64)
                .filter(|end| *end <= size)
            else {
                continue;
            };
            // Only wholly enclosed script data is opaque. A checksummed
            // declaration crossing its boundary must reach check_region.
            if scripts.contains_region(start, end) {
                continue;
            }
            read_at(&mut frame, start)?;
            if &frame[..8] != abi::MAGIC {
                return Err(invalid());
            }
            if !abi::checksummed(&frame) {
                continue;
            }
            let declaration = abi::decode(&frame).map_err(|_| invalid())?;
            check_region(index, start, end, helpers, scripts)?;
            if declaration.role != abi::ROLES[index]
                || found[index].is_some()
                || found
                    .iter()
                    .flatten()
                    .any(|other| start < other.end && other.start < end)
            {
                return Err(invalid());
            }
            found[index] = Some(Member {
                declaration,
                start,
                end,
            });
        }
        offset += count as u64;
    }
    let [
        Some(backend),
        Some(app),
        Some(owner),
        Some(broker),
        Some(client),
        Some(recovery),
    ] = found
    else {
        return Err(invalid());
    };
    Ok(Catalog {
        members: [backend, app, owner, broker, client, recovery],
    })
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or ambiguous support ABI catalog",
    )
}

#[cfg(test)]
#[path = "support_abi_catalog_tests.rs"]
mod tests;
#[cfg(test)]
pub(crate) use tests::catalog_fixture;
