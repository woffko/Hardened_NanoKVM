//! Private immutable helper capture. Expected hash is trusted caller input,
//! NEVER a hash supplied by p3/the helper itself. This is not a signature API.

use super::{JobError, Result};
use crate::update::{restore_capsule::create_private_spool, restore_fs};
use rustix::fs::{Mode, OFlags, PROC_SUPER_MAGIC, fchmod, fcntl_getfl, fstatfs, openat};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileExt, MetadataExt},
            process::CommandExt,
        },
    },
    path::Path,
    process::Command,
};

const MAX_HELPER: u64 = 32 * 1024 * 1024;

// No Clone, writable FD/path accessor or arbitrary command constructor.
pub struct PinnedSshHelper {
    pub(super) file: File,
}

impl PinnedSshHelper {
    /// Exact size/hash MUST originate from the authenticated release/build
    /// authority. rootfs O_TMPFILE only; no named/exFAT/p3 code staging fallback.
    /// Snapshot closes source mutation TOCTOU, not malicious local root.
    pub fn capture(
        source: &mut impl Read,
        size: u64,
        expected: &[u8; 32],
        private_root: &Path,
    ) -> Result<Self> {
        if !(64..=MAX_HELPER).contains(&size) {
            return Err(JobError::Helper);
        }
        let mut writable = create_private_spool(private_root).map_err(|_| JobError::Helper)?;
        let mut hash = Sha256::new();
        let mut remaining = size;
        let mut buffer = [0; 64 * 1024];
        while remaining != 0 {
            let limit = remaining.min(buffer.len() as u64) as usize;
            let n = source
                .read(&mut buffer[..limit])
                .map_err(|_| JobError::Helper)?;
            if n == 0 {
                return Err(JobError::Helper);
            }
            writable
                .write_all(&buffer[..n])
                .map_err(|_| JobError::Helper)?;
            hash.update(&buffer[..n]);
            remaining -= n as u64;
        }
        let actual: [u8; 32] = hash.finalize().into();
        let mut probe = [0_u8; 1];
        let eof = loop {
            match source.read(&mut probe) {
                Ok(n) => break n == 0,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(JobError::Helper),
            }
        };
        if !eof || actual != *expected {
            return Err(JobError::Helper);
        }
        check_static_rv64(&writable, size)?;
        fchmod(&writable, Mode::RUSR | Mode::XUSR).map_err(|_| JobError::Helper)?;
        writable.sync_all().map_err(|_| JobError::Helper)?;
        let file = readonly(&writable, size)?;
        drop(writable); // independent O_RDONLY, not dup/try_clone of O_RDWR
        Ok(Self { file })
    }

    pub(super) fn command(&self) -> Result<Command> {
        // Deliberate proc-fd exec of our OWN still-open anonymous inode. ELF
        // exec opens it before CLOEXEC closes the fd. Scripts are not accepted.
        procfs()?;
        let mut command = Command::new(format!("/proc/self/fd/{}", self.file.as_raw_fd()));
        command
            .arg0("nanokvm-ssh-sandbox")
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/")
            .current_dir("/");
        Ok(command)
    }
}

fn procfs() -> Result<File> {
    let directory =
        restore_fs::open_root(Path::new("/proc"), false).map_err(|_| JobError::Helper)?;
    if fstatfs(&directory).map_err(|_| JobError::Helper)?.f_type != PROC_SUPER_MAGIC {
        return Err(JobError::Helper);
    }
    Ok(directory)
}

fn readonly(source: &File, size: u64) -> Result<File> {
    let before = source.metadata().map_err(|_| JobError::Helper)?;
    if !before.is_file()
        || before.nlink() != 0
        || before.len() != size
        || before.uid() != nix::unistd::geteuid().as_raw()
        || before.mode() & 0o7777 != 0o500
    {
        return Err(JobError::Helper);
    }
    let file: File = openat(
        &procfs()?,
        format!("self/fd/{}", source.as_raw_fd()).as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| JobError::Helper)?
    .into();
    let after = file.metadata().map_err(|_| JobError::Helper)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.len() != size
        || after.nlink() != 0
        || fcntl_getfl(&file).map_err(|_| JobError::Helper)? & OFlags::ACCMODE != OFlags::RDONLY
    {
        return Err(JobError::Helper);
    }
    // A caller may have closed one of its stdio FDs. Pin above fd2 so Command's
    // stdio setup cannot replace the executable descriptor before execve.
    Ok(rustix::io::fcntl_dupfd_cloexec(&file, 3)
        .map_err(|_| JobError::Helper)?
        .into())
}

fn check_static_rv64(file: &File, size: u64) -> Result<()> {
    let mut header = [0; 64];
    file.read_exact_at(&mut header, 0)
        .map_err(|_| JobError::Helper)?;
    let u16_at = |n| u16::from_le_bytes([header[n], header[n + 1]]);
    let phoff = u64::from_le_bytes(header[32..40].try_into().map_err(|_| JobError::Helper)?);
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
        return Err(JobError::Helper);
    }
    let mut load = false;
    let mut program = [0; 56];
    for n in 0..count {
        file.read_exact_at(&mut program, phoff + u64::from(n) * 56)
            .map_err(|_| JobError::Helper)?;
        match u32::from_le_bytes(program[..4].try_into().map_err(|_| JobError::Helper)?) {
            1 => load = true,
            2 | 3 => return Err(JobError::Helper), // no dynamic table/interpreter
            _ => {}
        }
    }
    if load { Ok(()) } else { Err(JobError::Helper) }
}

#[cfg(test)]
impl PinnedSshHelper {
    pub(crate) fn host_fixture(source: &Path, staging: &Path) -> Self {
        // Unit-only ELF/architecture bypass for exact installed host executables.
        // Production capture above always requires trusted hash +static RV64.
        let mut input = File::open(source).unwrap();
        let size = input.metadata().unwrap().len();
        let mut writable = create_private_spool(staging).unwrap();
        std::io::copy(&mut input, &mut writable).unwrap();
        fchmod(&writable, Mode::RUSR | Mode::XUSR).unwrap();
        let file = readonly(&writable, size).unwrap();
        drop(writable);
        PinnedSshHelper { file }
    }
}
