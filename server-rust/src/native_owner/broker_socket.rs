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
        fd::{AsRawFd, OwnedFd},
        unix::{fs::MetadataExt, net::UnixStream},
    },
};
#[derive(Clone, Copy)]
enum Kind {
    Control,
    AppInstall,
    PicoJob,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Control => "control.sock",
            Self::AppInstall => "app-install.sock",
            Self::PicoJob => "picoclaw-job.sock",
        }
    }
    fn socket_type(self) -> SocketType {
        match self {
            Self::Control => SocketType::STREAM,
            Self::AppInstall | Self::PicoJob => SocketType::SEQPACKET,
        }
    }
}

pub(crate) struct Endpoint {
    pub(crate) listener: OwnedFd,
    directory: File,
    identity: (u64, u64),
    kind: Kind,
}

fn entry(directory: &File, uid: u32, device: u64, kind: Kind) -> io::Result<Option<Stat>> {
    let s = match statat(directory, kind.name(), AtFlags::SYMLINK_NOFOLLOW) {
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

fn address(directory: &File, kind: Kind) -> io::Result<SocketAddrUnix> {
    // bind/connect have no *at variant. This proc-fd path pins the already
    // validated directory; it is not a caller-selected filesystem pathname.
    SocketAddrUnix::new(format!(
        "/proc/self/fd/{}/{}",
        directory.as_raw_fd(),
        kind.name()
    ))
    .map_err(Into::into)
}

impl Endpoint {
    pub(crate) fn bind(parent: &File, uid: u32, device: u64) -> io::Result<Self> {
        Self::bind_kind(parent, uid, device, Kind::Control)
    }

    pub(crate) fn bind_install(parent: &File, uid: u32, device: u64) -> io::Result<Self> {
        Self::bind_kind(parent, uid, device, Kind::AppInstall)
    }

    pub(crate) fn bind_picoclaw_job(parent: &File, uid: u32, device: u64) -> io::Result<Self> {
        Self::bind_kind(parent, uid, device, Kind::PicoJob)
    }

    fn bind_kind(parent: &File, uid: u32, device: u64, kind: Kind) -> io::Result<Self> {
        let directory = parent.try_clone()?;
        // The journal lease, not PID/socket absence, authorizes stale cleanup.
        // Active/Maintenance/ambiguous same-boot stores never reach this call.
        if entry(&directory, uid, device, kind)?.is_some() {
            unlinkat(&directory, kind.name(), AtFlags::empty())?;
        }
        let fd = socket_with(
            AddressFamily::UNIX,
            kind.socket_type(),
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        bind(&fd, &address(&directory, kind)?)?;
        let s = statat(&directory, kind.name(), AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(s.st_mode) != FileType::Socket
            || s.st_uid != uid
            || s.st_dev != device
            || s.st_nlink != 1
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // Own the exact inode before any remaining fallible setup.
        let endpoint = Self {
            listener: fd,
            directory,
            identity: (s.st_dev, s.st_ino),
            kind,
        };
        // No process-global umask change that could alter later native files.
        // The pinned directory is private root0700; hostile root is not sandboxed.
        chmodat(
            &endpoint.directory,
            kind.name(),
            Mode::RUSR | Mode::WUSR,
            AtFlags::empty(),
        )?;
        let s = entry(&endpoint.directory, uid, device, kind)?.ok_or(io::ErrorKind::NotFound)?;
        if (s.st_dev, s.st_ino) != endpoint.identity {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        listen(&endpoint.listener, 16)?;
        Ok(endpoint)
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if let Ok(s) = statat(&self.directory, self.kind.name(), AtFlags::SYMLINK_NOFOLLOW)
            && FileType::from_raw_mode(s.st_mode) == FileType::Socket
            && (s.st_dev, s.st_ino) == self.identity
        {
            let _ = unlinkat(&self.directory, self.kind.name(), AtFlags::empty());
        }
    }
}

pub(crate) fn connect(directory: &File, uid: u32) -> io::Result<UnixStream> {
    connect_kind(directory, uid, Kind::Control).map(UnixStream::from)
}

pub(crate) fn connect_install(directory: &File, uid: u32) -> io::Result<OwnedFd> {
    connect_kind(directory, uid, Kind::AppInstall)
}

pub(crate) fn connect_picoclaw_job(directory: &File, uid: u32) -> io::Result<OwnedFd> {
    connect_kind(directory, uid, Kind::PicoJob)
}

fn connect_kind(directory: &File, uid: u32, kind: Kind) -> io::Result<OwnedFd> {
    let device = directory.metadata()?.dev();
    entry(directory, uid, device, kind)?.ok_or(io::ErrorKind::NotFound)?;
    let fd = socket_with(
        AddressFamily::UNIX,
        kind.socket_type(),
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    // EAGAIN/in-progress is a bounded connect failure, never a sent request.
    socket_connect(&fd, &address(directory, kind)?)?;
    Ok(fd)
}
