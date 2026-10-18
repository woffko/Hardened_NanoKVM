//! Named control endpoint beneath a protected, locked journal directory.
use rustix::{
    fs::{AtFlags, FileType, Mode, Stat, chmodat, statat, unlinkat},
    net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, bind, connect as socket_connect,
        listen, socket_with,
    },
};
use std::{
    fs::File,
    io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::MetadataExt,
            net::{UnixListener, UnixStream},
        },
    },
};
const NAME: &str = "control.sock";

pub(crate) struct Endpoint {
    pub(crate) listener: UnixListener,
    directory: File,
    identity: (u64, u64),
}

fn entry(directory: &File, uid: u32, device: u64) -> io::Result<Option<Stat>> {
    let s = match statat(directory, NAME, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(s) => s,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if FileType::from_raw_mode(s.st_mode) != FileType::Socket
        || s.st_uid != uid
        || s.st_dev != device
        || s.st_nlink != 1
        || s.st_mode & 0o7777 != 0o600
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(Some(s))
}

fn address(directory: &File) -> io::Result<SocketAddrUnix> {
    // bind/connect have no *at variant. This proc-fd path pins the already
    // validated directory; it is not a caller-selected filesystem pathname.
    SocketAddrUnix::new(format!("/proc/self/fd/{}/{}", directory.as_raw_fd(), NAME))
        .map_err(Into::into)
}

impl Endpoint {
    pub(crate) fn bind(parent: &File, uid: u32, device: u64) -> io::Result<Self> {
        let directory = parent.try_clone()?;
        // The journal lease, not PID/socket absence, authorizes stale cleanup.
        // Active/Maintenance/ambiguous same-boot stores never reach this call.
        if entry(&directory, uid, device)?.is_some() {
            unlinkat(&directory, NAME, AtFlags::empty())?;
        }
        let fd = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        bind(&fd, &address(&directory)?)?;
        let s = statat(&directory, NAME, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(s.st_mode) != FileType::Socket
            || s.st_uid != uid
            || s.st_dev != device
            || s.st_nlink != 1
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // Own the exact inode before any remaining fallible setup.
        let endpoint = Self {
            listener: UnixListener::from(fd),
            directory,
            identity: (s.st_dev, s.st_ino),
        };
        // No process-global umask change that could alter later native files.
        // The pinned directory is private root0700; hostile root is not sandboxed.
        chmodat(
            &endpoint.directory,
            NAME,
            Mode::RUSR | Mode::WUSR,
            AtFlags::empty(),
        )?;
        let s = entry(&endpoint.directory, uid, device)?.ok_or(io::ErrorKind::NotFound)?;
        if (s.st_dev, s.st_ino) != endpoint.identity {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        listen(&endpoint.listener, 16)?;
        Ok(endpoint)
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if let Ok(s) = statat(&self.directory, NAME, AtFlags::SYMLINK_NOFOLLOW)
            && FileType::from_raw_mode(s.st_mode) == FileType::Socket
            && (s.st_dev, s.st_ino) == self.identity
        {
            let _ = unlinkat(&self.directory, NAME, AtFlags::empty());
        }
    }
}

pub(crate) fn connect(directory: &File, uid: u32) -> io::Result<UnixStream> {
    let device = directory.metadata()?.dev();
    entry(directory, uid, device)?.ok_or(io::ErrorKind::NotFound)?;
    let fd = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    // EAGAIN/in-progress is a bounded connect failure, never a sent request.
    socket_connect(&fd, &address(directory)?)?;
    Ok(UnixStream::from(fd))
}
