//! Raw system-update handoff to the independent broker: the retained update and
//! writer exclusions plus the two authenticated read-only image snapshots.
//! Admission transfer only. The broker re-reads the prepared ticket on p1; a
//! queued packet is neither an accepted write nor a restore authorization.

use super::{
    app_install_lease::{Error, Files, check_lease, prepare, protected},
    operation::UpdateOwner,
    operation_lock::Domain,
    raw_transport::MAX_IMAGE_BYTES,
    restore_fs,
    state_writers::WriterDrain,
};
use rustix::{
    fs::{OFlags, fcntl_getfl},
    io::{FdFlags, fcntl_getfd},
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags, recvmsg, sendmsg, sockopt::socket_peercred,
    },
};
use std::{
    fs::File,
    io::{self, IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

const MAGIC: &[u8; 8] = b"NKRAWL01";
const DESCRIPTORS: usize = 5;
const IDENTITIES: usize = 104;
const BYTES: usize = IDENTITIES + DESCRIPTORS * 16;

/// The images and their digests from the authenticated manifest, in BOOT,
/// ROOTFS order. The snapshots are anonymous read-only files.
pub struct RawImages {
    pub files: [File; 2],
    pub sizes: [u64; 2],
    pub sha256: [[u8; 32]; 2],
}

/// One raw install's retained frontend owner, its three exported leases and the
/// two image snapshots. No Clone or descriptor access is exposed.
pub struct RawHandoff {
    files: Files,
    images: RawImages,
    transaction: [u8; 16],
    _owner: UpdateOwner,
}

impl RawHandoff {
    pub(super) fn new(
        transaction: [u8; 16],
        images: RawImages,
        update: File,
        mut writers: WriterDrain,
        owner: UpdateOwner,
    ) -> crate::Result<Self> {
        let [admission, activity] = writers.transfer_aliases()?;
        Ok(Self {
            files: Files {
                activity,
                admission,
                update,
            },
            images,
            transaction,
            _owner: owner,
        })
    }

    pub fn transaction(&self) -> [u8; 16] {
        self.transaction
    }
}

pub struct RawSender {
    socket: OwnedFd,
}

impl RawSender {
    /// Connect to the independent fixed broker's raw endpoint. A successful
    /// send means queued only; the broker decides from the ticket on p1.
    pub fn connect_broker() -> Result<Self, Error> {
        let socket = crate::native_owner::broker::raw_install::connect_peer()?;
        let peer = socket_peercred(&socket).map_err(io::Error::from)?;
        prepare(&socket, peer.pid.as_raw_nonzero().get() as u32, 0)?;
        Ok(Self { socket })
    }

    /// Consumes once, including on error. Do not resubmit an ambiguous send.
    pub fn send(self, handoff: RawHandoff) -> Result<(), Error> {
        send(&self.socket, &handoff)
    }
}

fn send(socket: &OwnedFd, handoff: &RawHandoff) -> Result<(), Error> {
    let (bytes, wire) = encode(handoff)?;
    transmit(socket, &bytes, &wire.map(File::as_fd))
}

fn encode(handoff: &RawHandoff) -> Result<([u8; BYTES], [&File; DESCRIPTORS]), Error> {
    let RawImages {
        files: images,
        sizes,
        sha256,
    } = &handoff.images;
    if handoff.transaction == [0; 16] || !valid_sizes(*sizes) || sha256.contains(&[0; 32]) {
        return Err(Error::Record);
    }
    let mut bytes = [0; BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(&handoff.transaction);
    bytes[24..32].copy_from_slice(&sizes[0].to_be_bytes());
    bytes[32..40].copy_from_slice(&sizes[1].to_be_bytes());
    bytes[40..72].copy_from_slice(&sha256[0]);
    bytes[72..104].copy_from_slice(&sha256[1]);
    let [update, admission, activity] = handoff.files.wire();
    let wire = [update, admission, activity, &images[0], &images[1]];
    for (encoded, file) in bytes[IDENTITIES..]
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .zip(wire)
    {
        *encoded = identity(file)?;
    }
    Ok((bytes, wire))
}

fn transmit(socket: &OwnedFd, bytes: &[u8], descriptors: &[BorrowedFd<'_>]) -> Result<(), Error> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(DESCRIPTORS))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return Err(Error::Record);
    }
    if sendmsg(
        socket,
        &[IoSlice::new(bytes)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(io::Error::from)?
        != bytes.len()
    {
        return Err(Error::Record);
    }
    Ok(())
}

/// Owns the three accepted exclusions and both images. Close-only Drop.
/// Not a ticket, signature or permission to write a partition.
pub struct RawAccepted {
    leases: Files,
    images: RawImages,
    transaction: [u8; 16],
}

/// The accepted exclusions, apart from the images. Close-only Drop: keep it to
/// the exec boundary, where close-on-exec releases them.
pub struct RawExclusions {
    _leases: Files,
}

impl RawAccepted {
    pub fn transaction(&self) -> [u8; 16] {
        self.transaction
    }
    pub fn sizes(&self) -> [u64; 2] {
        self.images.sizes
    }
    pub fn sha256(&self) -> [[u8; 32]; 2] {
        self.images.sha256
    }
    /// The images for the writer and the exclusions to keep until exec.
    pub fn into_parts(self) -> (RawExclusions, [File; 2]) {
        (
            RawExclusions {
                _leases: self.leases,
            },
            self.images.files,
        )
    }
}

/// One bounded nonblocking incoming raw offer, as for app installs.
pub struct RawIncoming {
    socket: OwnedFd,
    parent: File,
    uid: u32,
    consumed: bool,
}

impl RawIncoming {
    pub fn open(socket: OwnedFd) -> Result<Self, Error> {
        if !nix::unistd::geteuid().is_root() {
            return Err(Error::Channel);
        }
        for path in ["/", "/etc"] {
            protected(&restore_fs::open_root(Path::new(path), true)?, 0, false)?;
        }
        Self::at_parent(
            socket,
            restore_fs::open_root(Path::new("/etc/kvm"), true)?,
            0,
        )
    }

    fn at_parent(socket: OwnedFd, parent: File, uid: u32) -> Result<Self, Error> {
        protected(&parent, uid, false)?;
        let peer = socket_peercred(&socket).map_err(io::Error::from)?;
        prepare(&socket, peer.pid.as_raw_nonzero().get() as u32, uid)?;
        let flags = fcntl_getfl(&socket).map_err(io::Error::from)?;
        rustix::fs::fcntl_setfl(&socket, flags | OFlags::NONBLOCK).map_err(io::Error::from)?;
        Ok(Self {
            socket,
            parent,
            uid,
            consumed: false,
        })
    }

    pub fn poll(&mut self) -> Result<Option<RawAccepted>, Error> {
        if self.consumed {
            return Err(Error::Record);
        }
        match receive_packet(&self.socket, &self.parent, self.uid) {
            Err(Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            result => {
                self.consumed = true;
                result.map(Some)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(socket: OwnedFd, parent: File, uid: u32) -> Result<Self, Error> {
        Self::at_parent(socket, parent, uid)
    }
}

fn receive_packet(socket: &OwnedFd, parent: &File, uid: u32) -> Result<RawAccepted, Error> {
    protected(parent, uid, false)?;
    let mut bytes = [0; BYTES];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(DESCRIPTORS))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let packet = recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(io::Error::from)?;
    let sizes = [
        u64::from_be_bytes(bytes[24..32].try_into().map_err(|_| Error::Record)?),
        u64::from_be_bytes(bytes[32..40].try_into().map_err(|_| Error::Record)?),
    ];
    let sha256: [[u8; 32]; 2] = [
        bytes[40..72].try_into().map_err(|_| Error::Record)?,
        bytes[72..104].try_into().map_err(|_| Error::Record)?,
    ];
    if packet.bytes != BYTES
        || packet
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || &bytes[..8] != MAGIC
        || bytes[8..24] == [0; 16]
        || !valid_sizes(sizes)
        || sha256.contains(&[0; 32])
    {
        return Err(Error::Record);
    }
    let mut files: [Option<File>; DESCRIPTORS] = Default::default();
    let mut count = 0;
    for message in ancillary.drain() {
        let RecvAncillaryMessage::ScmRights(descriptors) = message else {
            return Err(Error::Record);
        };
        for descriptor in descriptors {
            if count == DESCRIPTORS {
                return Err(Error::Record);
            }
            files[count] = Some(descriptor.into());
            count += 1;
        }
    }
    let [
        Some(update),
        Some(admission),
        Some(activity),
        Some(boot),
        Some(rootfs),
    ] = files
    else {
        return Err(Error::Record);
    };
    let identities = bytes[IDENTITIES..].as_chunks::<16>().0;
    let leases = Files {
        activity,
        admission,
        update,
    };
    for ((file, domain), encoded) in leases
        .wire()
        .into_iter()
        .zip([
            Domain::Update,
            Domain::WriterAdmission,
            Domain::WriterActivity,
        ])
        .zip(identities)
    {
        check_lease(file, domain, encoded, parent, uid)?;
    }
    for ((image, size), encoded) in [&boot, &rootfs]
        .into_iter()
        .zip(sizes)
        .zip(&identities[3..])
    {
        check_image(image, size, encoded, uid)?;
    }
    Ok(RawAccepted {
        leases,
        images: RawImages {
            files: [boot, rootfs],
            sizes,
            sha256,
        },
        transaction: bytes[8..24].try_into().map_err(|_| Error::Record)?,
    })
}

/// An authenticated snapshot: an anonymous regular file of `uid`, writable by
/// no one else, opened read-only and close-on-exec, of exactly the declared
/// size and identity. The writer's transport checks the same before it writes.
fn check_image(file: &File, size: u64, encoded: &[u8; 16], uid: u32) -> Result<(), Error> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 0
        || metadata.uid() != uid
        || metadata.mode() & 0o7022 != 0
        || metadata.len() != size
        || identity(file)? != *encoded
        || fcntl_getfl(file).map_err(io::Error::from)? & OFlags::ACCMODE != OFlags::RDONLY
        || !fcntl_getfd(file)
            .map_err(io::Error::from)?
            .contains(FdFlags::CLOEXEC)
    {
        return Err(Error::Admission);
    }
    Ok(())
}

fn identity(file: &File) -> Result<[u8; 16], Error> {
    let metadata = file.metadata()?;
    let mut identity = [0; 16];
    identity[..8].copy_from_slice(&metadata.dev().to_be_bytes());
    identity[8..].copy_from_slice(&metadata.ino().to_be_bytes());
    Ok(identity)
}

fn valid_sizes(sizes: [u64; 2]) -> bool {
    sizes
        .iter()
        .all(|size| (1..=MAX_IMAGE_BYTES).contains(size))
        && sizes[0]
            .checked_add(sizes[1])
            .is_some_and(|total| total <= MAX_IMAGE_BYTES)
}

#[cfg(test)]
#[path = "raw_install_lease_tests.rs"]
mod tests;
