//! One-shot PUBLIC raw-image descriptor transport, not update authorization.
//! The sender must own already authenticated immutable image snapshots with
//! every writable alias closed. Readonly/nlink checks cannot prove that origin,
//! detect malicious local root, or protect a raw-exported backing filesystem.
//! No partition writing, native runtime execution or restore secret transfer.

use rustix::{
    fs::{OFlags, fcntl_getfl},
    io::{FdFlags, fcntl_getfd, fcntl_setfd},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType, recvmsg,
        sendmsg, socketpair,
        sockopt::{Timeout, set_socket_timeout, socket_domain, socket_peercred, socket_type},
    },
};
use std::{
    fs::File,
    io::{self, IoSlice, IoSliceMut, Read, Seek, SeekFrom},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::{FileExt, MetadataExt},
    },
    process::Stdio,
    time::Duration,
};

const MAGIC: &[u8; 8] = b"NKRAW001";
const VERSION_BYTES: usize = 64;
const CONTEXT_BYTES: usize = 8 + 16 + 1 + VERSION_BYTES + 2 * 8;
const RECORD_BYTES: usize = CONTEXT_BYTES + 2 * 16;
pub(super) const MAX_IMAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("invalid public raw transfer context")]
    Context,
    #[error("raw transfer requires the expected local sequenced-packet peer")]
    Channel,
    #[error("invalid or truncated raw transfer record/descriptors")]
    Record,
    #[error("raw transfer input is not an anonymous readonly owned image")]
    Image,
    #[error("public raw transfer I/O failed")]
    Io(#[from] io::Error),
}

/// Public context supplied by the trusted transaction, never deserialized from
/// p3. This is a binding value, not a signature/ticket or permission to write.
#[derive(Clone, PartialEq, Eq)]
pub struct TransferContext {
    transaction: [u8; 16],
    version: [u8; VERSION_BYTES],
    version_length: u8,
    sizes: [u64; 2],
}

impl TransferContext {
    /// Fixed public helper CLI fields; no descriptor numbers or secrets.
    pub(super) fn append_helper_arguments(&self, command: &mut std::process::Command) {
        let mut transaction = String::with_capacity(32);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.transaction {
            transaction.push(HEX[(byte >> 4) as usize] as char);
            transaction.push(HEX[(byte & 15) as usize] as char);
        }
        // new() admits only ASCII version bytes; the field remains private.
        use std::os::unix::ffi::OsStrExt;
        let version = std::ffi::OsStr::from_bytes(&self.version[..self.version_length as usize]);
        command
            .arg("--transaction")
            .arg(transaction)
            .arg("--version")
            .arg(version)
            .arg("--boot-size")
            .arg(self.sizes[0].to_string())
            .arg("--rootfs-size")
            .arg(self.sizes[1].to_string());
    }

    pub fn new(
        transaction: [u8; 16],
        version: &str,
        sizes: [u64; 2],
    ) -> Result<Self, TransferError> {
        if transaction == [0; 16]
            || version.is_empty()
            || version.len() > VERSION_BYTES
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || sizes
                .iter()
                .any(|size| *size == 0 || *size > MAX_IMAGE_BYTES)
            || sizes[0]
                .checked_add(sizes[1])
                .is_none_or(|size| size > MAX_IMAGE_BYTES)
        {
            return Err(TransferError::Context);
        }
        let mut encoded_version = [0; VERSION_BYTES];
        encoded_version[..version.len()].copy_from_slice(version.as_bytes());
        Ok(Self {
            transaction,
            version: encoded_version,
            version_length: version.len() as u8,
            sizes,
        })
    }

    fn encode(&self) -> [u8; CONTEXT_BYTES] {
        let mut bytes = [0; CONTEXT_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&self.transaction);
        bytes[24] = self.version_length;
        bytes[25..25 + VERSION_BYTES].copy_from_slice(&self.version);
        for (out, size) in bytes[25 + VERSION_BYTES..]
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(self.sizes)
        {
            out.copy_from_slice(&size.to_be_bytes());
        }
        bytes
    }
}

pub struct ImageSender {
    socket: OwnedFd,
}
pub struct ImageReceiver {
    socket: OwnedFd,
}

/// No listening pathname or port. Both endpoints are CLOEXEC until the child
/// endpoint is explicitly moved into Command's stdin by into_stdio().
pub fn channel() -> Result<(ImageSender, ImageReceiver), TransferError> {
    let (sender, receiver) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;
    prepare_socket(&sender, nix::unistd::getpid().as_raw() as u32)?;
    prepare_socket(&receiver, nix::unistd::getpid().as_raw() as u32)?;
    Ok((
        ImageSender { socket: sender },
        ImageReceiver { socket: receiver },
    ))
}

impl ImageSender {
    /// Consumes the sender and BOOT/ROOTFS files even on failure. Success means
    /// queued, NOT accepted by the child, written, restored or committed. A job
    /// owner must inspect the child/transaction's actual terminal result.
    pub fn send(self, expected: &TransferContext, images: [File; 2]) -> Result<(), TransferError> {
        let identities = [
            check_image(&images[0], expected.sizes[0])?,
            check_image(&images[1], expected.sizes[1])?,
        ];
        if identities[0] == identities[1] {
            return Err(TransferError::Image);
        }
        let mut record = [0; RECORD_BYTES];
        record[..CONTEXT_BYTES].copy_from_slice(&expected.encode());
        for (out, identity) in record[CONTEXT_BYTES..]
            .as_chunks_mut::<16>()
            .0
            .iter_mut()
            .zip(identities)
        {
            out[..8].copy_from_slice(&identity[0].to_be_bytes());
            out[8..].copy_from_slice(&identity[1].to_be_bytes());
        }
        let descriptors = [images[0].as_fd(), images[1].as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err(TransferError::Record);
        }
        let count = sendmsg(
            &self.socket,
            &[IoSlice::new(&record)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .map_err(io::Error::from)?;
        if count != RECORD_BYTES {
            return Err(TransferError::Record);
        }
        Ok(())
    }
}

impl ImageReceiver {
    pub fn into_stdio(self) -> Stdio {
        self.socket.into()
    }

    /// The endpoint for a process that makes it its own stdin before exec,
    /// as the broker does for the raw writer.
    pub fn into_socket(self) -> OwnedFd {
        self.socket
    }

    /// Adopt an owned duplicate of the child's stdin socket. The fresh helper
    /// must redirect/close its original stdin alias separately; this function
    /// never changes process-global stdio or closes unrelated descriptors.
    /// SO_PEERCRED identifies the pair creator, not the PID after fork/exec.
    pub fn adopt(socket: OwnedFd, expected_peer_pid: u32) -> Result<Self, TransferError> {
        // The fresh child should duplicate stdin atomically with
        // F_DUPFD_CLOEXEC. Also enforce the owned endpoint flag here.
        prepare_socket(&socket, expected_peer_pid)?;
        Ok(Self { socket })
    }

    /// Process exactly one fixed packet, then close this endpoint. Extra queued
    /// messages never become commands/inputs; socket close drops their queued
    /// SCM_RIGHTS references. No EOF/second-packet authentication is claimed.
    pub fn receive(self, expected: &TransferContext) -> Result<[ImageReader; 2], TransferError> {
        let mut record = [0; RECORD_BYTES];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let received = recvmsg(
            &self.socket,
            &mut [IoSliceMut::new(&mut record)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )
        .map_err(io::Error::from)?;
        if received.bytes != RECORD_BYTES
            || received
                .flags
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            || record[..CONTEXT_BYTES] != expected.encode()
        {
            return Err(TransferError::Record);
        }
        let mut images: [Option<File>; 2] = [None, None];
        let mut count = 0;
        for message in ancillary.drain() {
            let RecvAncillaryMessage::ScmRights(descriptors) = message else {
                return Err(TransferError::Record);
            };
            for descriptor in descriptors {
                if count == images.len() {
                    return Err(TransferError::Record);
                }
                images[count] = Some(descriptor.into());
                count += 1;
            }
        }
        let [Some(boot), Some(rootfs)] = images else {
            return Err(TransferError::Record);
        };
        let files = [boot, rootfs];
        let mut previous = None;
        for ((file, size), encoded) in files
            .iter()
            .zip(expected.sizes)
            .zip(record[CONTEXT_BYTES..].as_chunks::<16>().0)
        {
            let identity = check_image(file, size)?;
            let mut actual = [0; 16];
            actual[..8].copy_from_slice(&identity[0].to_be_bytes());
            actual[8..].copy_from_slice(&identity[1].to_be_bytes());
            if actual != *encoded || previous == Some(identity) {
                return Err(TransferError::Image);
            }
            previous = Some(identity);
        }
        let [boot, rootfs] = files;
        Ok([
            ImageReader {
                file: boot,
                size: expected.sizes[0],
                position: 0,
            },
            ImageReader {
                file: rootfs,
                size: expected.sizes[1],
                position: 0,
            },
        ])
    }
}

fn prepare_socket(socket: &OwnedFd, expected_peer_pid: u32) -> Result<(), TransferError> {
    let peer = socket_peercred(socket).map_err(io::Error::from)?;
    if expected_peer_pid == 0
        || socket_domain(socket).map_err(io::Error::from)? != AddressFamily::UNIX
        || socket_type(socket).map_err(io::Error::from)? != SocketType::SEQPACKET
        || peer.pid.as_raw_nonzero().get() as u32 != expected_peer_pid
        || peer.uid.as_raw() != nix::unistd::geteuid().as_raw()
    {
        return Err(TransferError::Channel);
    }
    let flags = fcntl_getfd(socket).map_err(io::Error::from)?;
    fcntl_setfd(socket, flags | FdFlags::CLOEXEC).map_err(io::Error::from)?;
    for kind in [Timeout::Recv, Timeout::Send] {
        set_socket_timeout(socket, kind, Some(SOCKET_TIMEOUT)).map_err(io::Error::from)?;
    }
    Ok(())
}

fn check_image(file: &File, size: u64) -> Result<[u64; 2], TransferError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 0
        || metadata.len() != size
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7022 != 0
        || fcntl_getfl(file).map_err(io::Error::from)? & OFlags::ACCMODE != OFlags::RDONLY
        || !fcntl_getfd(file)
            .map_err(io::Error::from)?
            .contains(FdFlags::CLOEXEC)
    {
        return Err(TransferError::Image);
    }
    Ok([metadata.dev(), metadata.ino()])
}

/// Bounded readonly image cursor. pread avoids shared-open-description offset
/// races introduced by SCM_RIGHTS/dup; no File/FD/write/Clone API escapes.
pub struct ImageReader {
    file: File,
    size: u64,
    position: u64,
}

impl ImageReader {
    // Crate-internal ownership transfer to the fixed readonly loop adapter.
    // No descriptor/path/Clone API is exposed to native commands or callers.
    pub(super) fn into_rootfs_backing(self) -> (File, u64) {
        (self.file, self.size)
    }

    // Crate-internal transfer to the raw writer, which writes the image whole.
    pub(super) fn into_file(self) -> File {
        self.file
    }
}

impl Read for ImageReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let limit = (self.size - self.position).min(out.len() as u64) as usize;
        if limit == 0 {
            return Ok(0);
        }
        let count = self.file.read_at(&mut out[..limit], self.position)?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for ImageReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => self.size.checked_add_signed(delta),
        }
        .filter(|position| *position <= self.size)
        .ok_or(io::ErrorKind::InvalidInput)?;
        self.position = position;
        Ok(position)
    }
}

#[cfg(test)]
#[path = "raw_transport_tests.rs"]
mod tests;
