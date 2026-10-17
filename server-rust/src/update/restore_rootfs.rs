//! Exact-image native preflight view, NOT release authorization or a restore.
//! Only a fresh privileged child may enter. Its mount/network namespaces change
//! irreversibly; never call this from the HTTP server or a thread pool. The
//! caller must supply an authenticated immutable ROOTFS snapshot, not merely a
//! readonly file, and close all writable aliases before descriptor transfer.

use super::{
    raw_transport::ImageReader,
    restore_fs,
    restore_native::{self, AccountFiles},
};
use nix::{
    mount::{MntFlags, MsFlags, mount, umount2},
    sched::{CloneFlags, unshare},
    sys::{prctl, signal::Signal},
    unistd::{geteuid, getppid},
};
use rustix::fs::{
    Dir, Mode, OFlags, PROC_SUPER_MAGIC, ResolveFlags, StatVfsMountFlags, fstatfs, fstatvfs,
    openat2,
};
use std::{
    fs::{self, File},
    io::{self, Read},
    marker::PhantomData,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
    rc::Rc,
};
use zeroize::Zeroizing;

#[path = "restore_rootfs_loop.rs"]
mod loop_device;

#[derive(Debug, thiserror::Error)]
pub enum RootfsError {
    #[error("rootfs view requires a fresh privileged process and live parent lease")]
    Process,
    #[error("rootfs view requires an owned anonymous readonly aligned image")]
    Image,
    #[error("rootfs view requires a private empty rootfs mountpoint")]
    Layout,
    #[error("rootfs view namespace isolation failed")]
    Namespace,
    #[error("rootfs view readonly autoclear loop binding failed")]
    Device,
    #[error("rootfs view readonly ext4 mount failed")]
    Mount,
    #[error("rootfs native account or login-path requirements are invalid")]
    Accounts,
    #[error("rootfs view I/O failed")]
    Io(#[from] io::Error),
}

/// No Debug/Clone/serde: even factory account files use zeroizing storage.
pub struct RootfsAccounts {
    passwd: Zeroizing<Vec<u8>>,
    group: Zeroizing<Vec<u8>>,
    shadow: Zeroizing<Vec<u8>>,
    gshadow: Option<Zeroizing<Vec<u8>>>,
}

impl RootfsAccounts {
    pub fn as_files(&self) -> AccountFiles<'_> {
        AccountFiles {
            passwd: &self.passwd,
            group: &self.group,
            shadow: &self.shadow,
            gshadow: self.gshadow.as_deref().map(|bytes| bytes.as_slice()),
        }
    }
}

/// A readonly exact-image mount in this child's private namespace. No root fd,
/// backing path or device handle escapes. Not Send/Sync; namespace lifetime is
/// process-scoped. Dropping detaches only this mount; AUTOCLEAR releases the loop
/// once our mount/fd refs close. The child must exit on any setup/teardown error.
pub struct RootfsView {
    root: File,
    _device: loop_device::ReadonlyLoop,
    _process_scoped: PhantomData<Rc<()>>,
}

impl RootfsView {
    pub fn mount(
        image: ImageReader,
        mountpoint: &Path,
        expected_parent: u32,
    ) -> Result<Self, RootfsError> {
        require_fresh_process(expected_parent)?;
        // Unshare before opening the mount target: old-namespace proc-fds must
        // not be used as mount sources/targets in the new namespace.
        unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET)
            .map_err(|_| RootfsError::Namespace)?;
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_PRIVATE | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|_| RootfsError::Namespace)?;
        let procfs =
            restore_fs::open_root(Path::new("/proc"), false).map_err(|_| RootfsError::Namespace)?;
        if fstatfs(&procfs).map_err(io::Error::from)?.f_type != PROC_SUPER_MAGIC {
            return Err(RootfsError::Namespace);
        }
        let target = restore_fs::open_root(mountpoint, true).map_err(|_| RootfsError::Layout)?;
        check_mountpoint(&target)?;
        let (backing, size) = image.into_rootfs_backing();
        let device = loop_device::ReadonlyLoop::attach(backing, size)?;
        let source = format!("/proc/self/fd/{}", device.device.as_raw_fd());
        let target_fd = format!("/proc/self/fd/{}", target.as_raw_fd());
        mount(
            Some(source.as_str()),
            target_fd.as_str(),
            Some("ext4"),
            MsFlags::MS_RDONLY | MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("noload"),
        )
        .map_err(|_| RootfsError::Mount)?;
        // A proc-fd of the original directory still identifies the covered
        // underlying mount. Reopen through the checked absolute caller path,
        // then require the exact loop block-device identity and ext4 type.
        let root = match restore_fs::open_root(mountpoint, false) {
            Ok(root) => root,
            Err(_) => {
                let _ = umount2(mountpoint, MntFlags::MNT_DETACH);
                return Err(RootfsError::Mount);
            }
        };
        let verified = (|| {
            Ok::<_, RootfsError>(
                root.metadata()?.dev() == device.device.metadata()?.rdev()
                    && fstatfs(&root).map_err(io::Error::from)?.f_type as u64
                        == u64::from(linux_raw_sys::general::EXT4_SUPER_MAGIC)
                    && fstatvfs(&root).map_err(io::Error::from)?.f_flag.contains(
                        StatVfsMountFlags::RDONLY
                            | StatVfsMountFlags::NODEV
                            | StatVfsMountFlags::NOSUID
                            | StatVfsMountFlags::NOEXEC,
                    ),
            )
        })();
        if !matches!(verified, Ok(true)) {
            let _ = umount2(mountpoint, MntFlags::MNT_DETACH);
            return Err(RootfsError::Mount);
        }
        Ok(Self {
            root,
            _device: device,
            _process_scoped: PhantomData,
        })
    }

    /// Read only fixed native account paths from the pinned image, with no
    /// symlinks or nested mounts. No live /etc, target/ tree or p3 fallback.
    pub fn accounts(&self) -> Result<RootfsAccounts, RootfsError> {
        read_accounts(&self.root)
    }

    /// Check preserved root home/shell against the signed target filesystem.
    /// Shell symlinks (e.g. /bin/sh -> busybox) resolve only INSIDE this image.
    /// This is metadata preflight, not a real SSH login or native syntax test.
    pub fn check_root_login_paths(&self, restored: &AccountFiles<'_>) -> Result<(), RootfsError> {
        check_root_login_paths(&self.root, restored)
    }
}

impl Drop for RootfsView {
    fn drop(&mut self) {
        // Lazy detach is deliberate: this guard's root fd still pins the mount.
        // Namespace teardown on child exit is the final cleanup backstop. Never
        // issue LOOP_CLR_FD or operate on a path selected by uploaded metadata.
        let target = format!("/proc/self/fd/{}", self.root.as_raw_fd());
        let _ = umount2(target.as_str(), MntFlags::MNT_DETACH);
    }
}

fn require_fresh_process(expected_parent: u32) -> Result<(), RootfsError> {
    if !geteuid().is_root()
        || expected_parent <= 1
        || getppid().as_raw() as u32 != expected_parent
        || fs::read_dir("/proc/self/task")
            .map_err(|_| RootfsError::Process)?
            .count()
            != 1
    {
        return Err(RootfsError::Process);
    }
    prctl::set_pdeathsig(Signal::SIGKILL).map_err(|_| RootfsError::Process)?;
    if getppid().as_raw() as u32 != expected_parent {
        return Err(RootfsError::Process);
    }
    Ok(())
}

fn check_mountpoint(directory: &File) -> Result<(), RootfsError> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7077 != 0 {
        return Err(RootfsError::Layout);
    }
    for entry in Dir::read_from(directory).map_err(io::Error::from)? {
        let entry = entry.map_err(io::Error::from)?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Err(RootfsError::Layout);
        }
    }
    Ok(())
}

fn read_accounts(root: &File) -> Result<RootfsAccounts, RootfsError> {
    let tables = RootfsAccounts {
        passwd: read_table(root, "etc/passwd", false)?.ok_or(RootfsError::Accounts)?,
        group: read_table(root, "etc/group", false)?.ok_or(RootfsError::Accounts)?,
        shadow: read_table(root, "etc/shadow", false)?.ok_or(RootfsError::Accounts)?,
        gshadow: read_table(root, "etc/gshadow", true)?,
    };
    restore_native::validate(&tables.as_files()).map_err(|_| RootfsError::Accounts)?;
    Ok(tables)
}

fn read_table(
    root: &File,
    path: &str,
    optional: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, RootfsError> {
    let mut file = match restore_fs::open_beneath(root, path, OFlags::RDONLY | OFlags::NONBLOCK) {
        Ok(file) => file,
        Err(error) if optional && error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RootfsError::Accounts),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
        || metadata.len() > restore_native::MAX_TABLE_BYTES as u64
    {
        return Err(RootfsError::Accounts);
    }
    let mut bytes = Zeroizing::new(vec![0; metadata.len() as usize]);
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0; 1])? != 0 {
        return Err(RootfsError::Accounts);
    }
    Ok(Some(bytes))
}

fn check_root_login_paths(root: &File, restored: &AccountFiles<'_>) -> Result<(), RootfsError> {
    restore_native::validate(restored).map_err(|_| RootfsError::Accounts)?;
    let passwd = std::str::from_utf8(restored.passwd).map_err(|_| RootfsError::Accounts)?;
    let row = passwd
        .lines()
        .find(|line| line.starts_with("root:"))
        .ok_or(RootfsError::Accounts)?;
    let mut fields = row.split(':');
    let home = fields.nth(5).ok_or(RootfsError::Accounts)?;
    let shell = fields.next().ok_or(RootfsError::Accounts)?;
    let home: File = openat2(
        root,
        home,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| RootfsError::Accounts)?
    .into();
    let home_meta = home.metadata()?;
    if home_meta.uid() != 0 || home_meta.mode() & 0o7022 != 0 || home_meta.mode() & 0o100 == 0 {
        return Err(RootfsError::Accounts);
    }
    let shell: File = openat2(
        root,
        shell,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| RootfsError::Accounts)?
    .into();
    let executable = shell.metadata()?;
    if !executable.is_file()
        || executable.uid() != 0
        || executable.mode() & 0o7022 != 0
        || executable.mode() & 0o100 == 0
    {
        return Err(RootfsError::Accounts);
    }
    Ok(())
}

#[cfg(test)]
#[path = "restore_rootfs_tests.rs"]
mod tests;
