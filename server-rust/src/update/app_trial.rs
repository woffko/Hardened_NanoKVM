//! Read-only backend startup under the independent installer's retained freeze.
//! A private parent channel is startup authority, never app health by itself.

use super::restore_fs;
use crate::{AppError, Result, config::Config};
use rustix::fs::OFlags;
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, net::UnixStream},
    },
    path::{Component, Path},
    time::Duration,
};
use zeroize::Zeroizing;

pub mod wire {
    use std::io;
    pub const BYTES: usize = 32;
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Event {
        Begin = 1,
        Ready = 2,
        Commit = 3,
    }
    pub fn frame(event: Event, transaction: [u8; 16]) -> io::Result<[u8; BYTES]> {
        if transaction == [0; 16] {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(b"NKAPPT01");
        bytes[8] = event as u8;
        bytes[16..].copy_from_slice(&transaction);
        Ok(bytes)
    }
    pub fn parse(bytes: &[u8; BYTES], event: Event) -> io::Result<[u8; 16]> {
        if &bytes[..8] != b"NKAPPT01"
            || bytes[8] != event as u8
            || bytes[9..16] != [0; 7]
            || bytes[16..] == [0; 16]
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        bytes[16..]
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData.into())
    }
}

/// No Clone or arbitrary descriptor/path constructor. A retained private root
/// parent grants only frozen reads and a transaction-bound startup handshake.
pub struct Startup {
    channel: UnixStream,
    transaction: [u8; 16],
}
impl Startup {
    /// Called before creating the async runtime. Remove the original fd0 alias
    /// so future descendants cannot retain the private startup channel.
    pub fn adopt_stdin() -> io::Result<Self> {
        if !nix::unistd::geteuid().is_root() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let fd = rustix::io::dup(std::io::stdin())?;
        rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
        let channel = UnixStream::from(fd);
        let peer = rustix::net::sockopt::socket_peercred(&channel)?;
        if !peer.uid.is_root()
            || peer.pid.as_raw_nonzero().get() != nix::unistd::getppid().as_raw()
            || !channel.local_addr()?.is_unnamed()
            || !channel.peer_addr()?.is_unnamed()
            || rustix::net::sockopt::socket_type(&channel)? != rustix::net::SocketType::STREAM
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let null = File::open("/dev/null")?;
        nix::unistd::dup2(null.as_raw_fd(), 0).map_err(io::Error::from)?;
        Self::receive(channel)
    }

    fn receive(mut channel: UnixStream) -> io::Result<Self> {
        channel.set_read_timeout(Some(Duration::from_secs(2)))?;
        channel.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut bytes = [0; wire::BYTES];
        channel.read_exact(&mut bytes)?;
        let transaction = wire::parse(&bytes, wire::Event::Begin)?;
        Ok(Self {
            channel,
            transaction,
        })
    }

    pub fn configuration(&self) -> Result<Config> {
        Config::read_trial(self)
    }

    pub fn tls_configuration(&self, config: &Config) -> Result<tokio_rustls::rustls::ServerConfig> {
        let cert = self
            .read_state(Path::new(&config.cert.crt), 128 * 1024)?
            .ok_or_else(|| AppError::Config("trial TLS certificate is absent".into()))?;
        let key = self
            .read_state(Path::new(&config.cert.key), 64 * 1024)?
            .ok_or_else(|| AppError::Config("trial TLS identity is absent".into()))?;
        crate::http::tls::server_config_from_pem(&cert, &key)
            .map_err(|_| AppError::Config("invalid trial TLS identity".into()))
    }

    /// Call only after all listeners and required runtime initialization exist.
    /// No general HTTP route may run before the matching Commit arrives. This
    /// acknowledgement is startup readiness, NOT device/physical acceptance.
    pub fn ready_and_wait_commit(mut self) -> io::Result<()> {
        self.channel
            .write_all(&wire::frame(wire::Event::Ready, self.transaction)?)?;
        self.channel
            .set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut bytes = [0; wire::BYTES];
        self.channel.read_exact(&mut bytes)?;
        if wire::parse(&bytes, wire::Event::Commit)? != self.transaction {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }

    pub(crate) fn read_state(&self, path: &Path, limit: u64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        read_state(path, limit)
            .map_err(|_| AppError::Config("trial startup requires protected existing state".into()))
    }
}

fn protected_directory(file: &File, device: u64) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_dir() || m.uid() != 0 || m.dev() != device || m.mode() & 0o7022 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

fn read_state(path: &Path, limit: u64) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    if !path.is_absolute() || limit == 0 || limit > 1024 * 1024 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut parent = File::open("/")?;
    let device = parent.metadata()?.dev();
    protected_directory(&parent, device)?;
    for (depth, component) in path
        .parent()
        .ok_or(io::ErrorKind::InvalidInput)?
        .components()
        .enumerate()
    {
        match component {
            Component::RootDir => {}
            Component::Normal(name) if depth <= 32 => {
                parent = restore_fs::open_beneath(
                    &parent,
                    name.to_str().ok_or(io::ErrorKind::InvalidInput)?,
                    OFlags::RDONLY | OFlags::DIRECTORY,
                )?;
                protected_directory(&parent, device)?;
            }
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        }
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(io::ErrorKind::InvalidInput)?;
    let pinned = match restore_fs::open_beneath(&parent, name, OFlags::PATH) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let m = pinned.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.dev() != device
        || m.nlink() != 1
        || m.mode() & 0o7022 != 0
        || m.len() > limit
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut file = restore_fs::open_beneath(&parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
    let actual = file.metadata()?;
    if (
        actual.dev(),
        actual.ino(),
        actual.mode(),
        actual.uid(),
        actual.nlink(),
        actual.len(),
    ) != (m.dev(), m.ino(), m.mode(), m.uid(), m.nlink(), m.len())
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(m.len() as usize));
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != m.len() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(bytes))
}

#[cfg(test)]
#[path = "app_trial_tests.rs"]
mod tests;
