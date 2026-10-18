//! Private immutable helper capture. Expected hash is trusted caller input,
//! NEVER a hash supplied by p3/the helper itself. This is not a signature API.

use super::{JobError, Result};
use crate::update::{restore_binding, restore_capsule::create_private_spool, restore_fs};
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

// Keep the exact envelope contiguous in the backend for host-side packaging
// verification. The optimizer barrier is safe; a missing/ambiguous envelope
// fails the packaging gate rather than selecting a mutable runtime fallback.
#[inline(never)]
fn embedded_binding() -> &'static [u8] {
    std::hint::black_box(
        include_bytes!(concat!(env!("OUT_DIR"), "/ssh-runtime.binding")).as_slice(),
    )
}

// No Clone, writable FD/path accessor or arbitrary command constructor.
pub struct PinnedSshHelper {
    pub(super) file: File,
}

impl PinnedSshHelper {
    /// Linked device startup and packaging both require this exact envelope.
    /// Checking it does not grant an update/restore authorization.
    pub fn check_embedded() -> Result<()> {
        restore_binding::validate(embedded_binding()).map_err(|_| JobError::Helper)?;
        Ok(())
    }

    /// Build-bound bytes only. No p3 file, runtime environment variable or
    /// unsigned manifest can supply/replace this authority. The backend itself
    /// still requires the protected app-slot/signed-build trust boundary.
    pub fn embedded(private_root: &Path) -> Result<Self> {
        let binding =
            restore_binding::validate(embedded_binding()).map_err(|_| JobError::Helper)?;
        let mut image = binding.image;
        Self::capture(
            &mut image,
            binding.image.len() as u64,
            &binding.digest,
            private_root,
        )
    }

    /// Exact size/hash MUST originate from the authenticated release/build
    /// authority. rootfs O_TMPFILE only; no named/exFAT/p3 code staging fallback.
    /// Snapshot closes source mutation TOCTOU, not malicious local root.
    pub(crate) fn capture(
        source: &mut impl Read,
        size: u64,
        expected: &[u8; 32],
        private_root: &Path,
    ) -> Result<Self> {
        if !(64..=restore_binding::MAX_HELPER).contains(&size) {
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
        restore_binding::check_static_rv64(size, |buffer, offset| {
            writable.read_exact_at(buffer, offset)
        })
        .map_err(|_| JobError::Helper)?;
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
