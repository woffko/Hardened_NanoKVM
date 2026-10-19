//! Bounded inspection of backend-embedded app/native helper bindings.
//!
//! This is a consistency check, NOT release authentication, executable upgrade
//! authority or an immutable snapshot. The installation owner must supply an
//! already authenticated, protected candidate and keep its bytes stable. A
//! returned family never permits replacing /usr/libexec or starting a process.

use super::{
    restore_binding::{self, NativeRuntime},
    restore_fs,
};
use rustix::fs::OFlags;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io,
    os::unix::fs::{FileExt, MetadataExt},
    path::Path,
};

pub const MAX_BACKEND_BYTES: u64 = 128 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
const MAX_MARKERS: usize = 64;
// Includes invalid-but-plausible frames, not just the five selected images.
// This bounds adversarial overlapping frames independently of marker count.
const MAX_HASH_BYTES: u64 = 2 * MAX_BACKEND_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    AppRecovery,
    NativeOwner,
    NativeBroker,
    NativeClient,
    NativeRecovery,
}

pub const ROLES: [Role; 5] = [
    Role::AppRecovery,
    Role::NativeOwner,
    Role::NativeBroker,
    Role::NativeClient,
    Role::NativeRecovery,
];

impl Role {
    pub fn filename(self) -> &'static str {
        match self.native() {
            Some(native) => native.filename(),
            None => "nanokvm-app-recovery",
        }
    }

    fn native(self) -> Option<NativeRuntime> {
        match self {
            Self::AppRecovery => None,
            Self::NativeOwner => Some(NativeRuntime::Owner),
            Self::NativeBroker => Some(NativeRuntime::Broker),
            Self::NativeClient => Some(NativeRuntime::Client),
            Self::NativeRecovery => Some(NativeRuntime::Recovery),
        }
    }

    fn magic(self) -> &'static [u8; 8] {
        self.native()
            .map_or(restore_binding::APP_RECOVERY_MAGIC, NativeRuntime::magic)
    }

    fn maximum(self) -> u64 {
        if self == Self::AppRecovery {
            restore_binding::MAX_HELPER
        } else {
            restore_binding::MAX_NATIVE_HELPER
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Member {
    role: Role,
    // Whole frame range, retained to reject cross-role nesting/overlap. These
    // offsets are deliberately not a public executable/extraction capability.
    start: u64,
    end: u64,
    size: u64,
    sha256: [u8; 32],
}

impl Member {
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

/// All five unambiguous, nonoverlapping, static RV64 members. This contains
/// diagnostics only: no writable paths, launch method or migration permission.
#[derive(Debug, Eq, PartialEq)]
pub struct Family {
    members: [Member; 5],
}

impl Family {
    pub fn members(&self) -> &[Member; 5] {
        &self.members
    }
}

/// Inspect a pinned regular file without moving its shared cursor. Working
/// memory is fixed (~128 KiB), irrespective of backend/helper sizes. The caller
/// must own source immutability; an open FD alone does not freeze file contents.
pub fn inspect(backend: &File) -> io::Result<Family> {
    let metadata = backend.metadata()?;
    if !metadata.is_file() {
        return Err(invalid());
    }
    inspect_with(metadata.len(), |buffer, offset| {
        backend.read_exact_at(buffer, offset)
    })
}

/// Called only inside the opaque AppCandidate factory after authenticated
/// archive checks/private extraction. No helper installation, process start,
/// stage adoption, alias repair or new signature claim is performed here.
pub(crate) fn check_candidate(path: &Path) -> io::Result<()> {
    let root = restore_fs::open_root(path, true)?;
    let device = root.metadata()?.dev();
    let uid = nix::unistd::geteuid().as_raw();
    check_directory(&root, uid, device)?;
    for name in ["server", "backends", "system", "system/bin"] {
        let directory = restore_fs::open_beneath(&root, name, OFlags::RDONLY | OFlags::DIRECTORY)?;
        check_directory(&directory, uid, device)?;
    }
    let backend = candidate_file(
        &root,
        "server/NanoKVM-Server",
        MAX_BACKEND_BYTES,
        uid,
        device,
    )?;
    let family = inspect(&backend)?;
    let backup = candidate_file(
        &root,
        "backends/NanoKVM-Server.rust",
        MAX_BACKEND_BYTES,
        uid,
        device,
    )?;
    if !same_bytes(&backend, &backup)? {
        return Err(invalid());
    }
    for member in family.members() {
        let helper = candidate_file(
            &root,
            &format!("system/bin/{}", member.role().filename()),
            member.size(),
            uid,
            device,
        )?;
        if hash_file(&helper, member.size())? != *member.sha256() {
            return Err(invalid());
        }
    }
    Ok(())
}

fn check_directory(directory: &File, uid: u32, device: u64) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.dev() != device
        || metadata.mode() & 0o7022 != 0
    {
        return Err(invalid());
    }
    Ok(())
}

fn candidate_file(
    root: &File,
    name: &str,
    maximum: u64,
    uid: u32,
    device: u64,
) -> io::Result<File> {
    // O_PATH rejects special files before a data open, without blocking on a
    // FIFO or invoking a candidate device. open_beneath rejects all aliases.
    let identity = restore_fs::open_beneath(root, name, OFlags::PATH)?.metadata()?;
    let safe = |metadata: &std::fs::Metadata| {
        metadata.is_file()
            && metadata.uid() == uid
            && metadata.dev() == device
            && metadata.nlink() == 1
            && metadata.mode() & 0o7022 == 0
            && metadata.len() > 0
            && metadata.len() <= maximum
    };
    if !safe(&identity) {
        return Err(invalid());
    }
    let file = restore_fs::open_beneath(root, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
    let metadata = file.metadata()?;
    if !safe(&metadata) || metadata.ino() != identity.ino() || metadata.len() != identity.len() {
        return Err(invalid());
    }
    Ok(file)
}

fn same_bytes(left: &File, right: &File) -> io::Result<bool> {
    let size = left.metadata()?.len();
    if !(64..=MAX_BACKEND_BYTES).contains(&size) || right.metadata()?.len() != size {
        return Ok(false);
    }
    let mut left_buffer = [0; CHUNK];
    let mut right_buffer = [0; CHUNK];
    let mut offset = 0;
    while offset < size {
        let count = (size - offset).min(CHUNK as u64) as usize;
        left.read_exact_at(&mut left_buffer[..count], offset)?;
        right.read_exact_at(&mut right_buffer[..count], offset)?;
        if left_buffer[..count] != right_buffer[..count] {
            return Ok(false);
        }
        offset += count as u64;
    }
    Ok(left.metadata()?.len() == size && right.metadata()?.len() == size)
}

fn hash_file(file: &File, size: u64) -> io::Result<[u8; 32]> {
    if file.metadata()?.len() != size {
        return Err(invalid());
    }
    let mut buffer = [0; CHUNK];
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < size {
        let count = (size - offset).min(CHUNK as u64) as usize;
        file.read_exact_at(&mut buffer[..count], offset)?;
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    if file.metadata()?.len() != size {
        return Err(invalid());
    }
    Ok(hash.finalize().into())
}

fn inspect_with(
    size: u64,
    mut read_at: impl FnMut(&mut [u8], u64) -> io::Result<()>,
) -> io::Result<Family> {
    if !(64..=MAX_BACKEND_BYTES).contains(&size) {
        return Err(invalid());
    }
    let mut found: [Option<Member>; 5] = [None; 5];
    let mut markers = [0; 5];
    let mut hash_remaining = MAX_HASH_BYTES;
    let mut buffer = [0; CHUNK + 7];
    let mut hash_buffer = [0; CHUNK];
    let mut offset = 0;
    while offset < size {
        // Seven lookahead bytes find a marker spanning two chunks without
        // rescanning/counting it twice. Headers/images use independent reads.
        let count = (size - offset).min(CHUNK as u64) as usize;
        let available = (size - offset).min(buffer.len() as u64) as usize;
        read_at(&mut buffer[..available], offset)?;
        for start in 0..count {
            if buffer[start] != b'N' || available - start < 8 {
                continue;
            }
            let Some(index) = ROLES
                .iter()
                .position(|role| &buffer[start..start + 8] == role.magic())
            else {
                continue;
            };
            markers[index] += 1;
            if markers[index] > MAX_MARKERS {
                return Err(invalid());
            }
            if let Some(member) = inspect_member(
                ROLES[index],
                offset + start as u64,
                size,
                &mut read_at,
                &mut hash_buffer,
                &mut hash_remaining,
            )? {
                if found[index].is_some()
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
    let [
        Some(app),
        Some(owner),
        Some(broker),
        Some(client),
        Some(recovery),
    ] = found
    else {
        return Err(invalid());
    };
    Ok(Family {
        members: [app, owner, broker, client, recovery],
    })
}

fn inspect_member(
    role: Role,
    start: u64,
    backend_size: u64,
    read_at: &mut impl FnMut(&mut [u8], u64) -> io::Result<()>,
    buffer: &mut [u8; CHUNK],
    hash_remaining: &mut u64,
) -> io::Result<Option<Member>> {
    let image_start = start
        .checked_add(restore_binding::HEADER as u64)
        .ok_or_else(invalid)?;
    if image_start > backend_size {
        return Ok(None);
    }
    let mut header = [0; restore_binding::HEADER];
    read_at(&mut header, start)?;
    // A changed source is not an invalid-literal marker to ignore.
    if &header[..8] != role.magic() {
        return Err(invalid());
    }
    let size = u64::from_le_bytes(header[8..16].try_into().map_err(|_| invalid())?);
    let Some(end) = image_start
        .checked_add(size)
        .filter(|end| *end <= backend_size)
    else {
        return Ok(None);
    };
    if !(64..=role.maximum()).contains(&size) {
        return Ok(None);
    }
    *hash_remaining = hash_remaining.checked_sub(size).ok_or_else(invalid)?;
    let expected: [u8; 32] = header[16..].try_into().map_err(|_| invalid())?;
    let mut hash = Sha256::new();
    let mut offset = image_start;
    while offset < end {
        let count = (end - offset).min(buffer.len() as u64) as usize;
        read_at(&mut buffer[..count], offset)?;
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    if <[u8; 32]>::from(hash.finalize()) != expected {
        return Ok(None);
    }
    // Preserve source I/O failure rather than treating a failed read as a
    // harmless invalid ELF literal. There is no alternate-family fallback.
    let mut io_error = None;
    let elf = restore_binding::check_static_rv64(size, |out, relative| {
        match read_at(out, image_start + relative) {
            Ok(()) => Ok(()),
            Err(error) => {
                io_error = Some(error);
                Err(io::ErrorKind::Other.into())
            }
        }
    });
    if let Some(error) = io_error {
        return Err(error);
    }
    if elf.is_err() {
        return Ok(None);
    }
    Ok(Some(Member {
        role,
        start,
        end,
        size,
        sha256: expected,
    }))
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or ambiguous backend helper family",
    )
}

#[cfg(test)]
#[path = "helper_family_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) use tests::candidate_files_fixture;
