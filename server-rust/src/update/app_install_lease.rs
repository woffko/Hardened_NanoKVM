//! App installer admission transfer only, NOT candidate or swap authority.
//! No installer is activated by sending/receiving these fixed lease descriptors.

use super::{
    operation::UpdateOwner, operation_lock::Domain, restore_fs, state_writers::WriterDrain,
};
use rustix::{
    fs::{FlockOperation, OFlags, fcntl_getfl, flock},
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
    io::{self, IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    process::Stdio,
    time::Duration,
};

const MAGIC: &[u8; 8] = b"NKAPPL01";
const BYTES: usize = 72;
const TIMEOUT: Duration = Duration::from_secs(2);
const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);
const TAKEN: u8 = b'T';
const REFUSED: u8 = b'R';

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("install lease requires the expected root local peer")]
    Channel,
    #[error("install lease packet or descriptors are invalid")]
    Record,
    #[error("install lease does not match fixed protected admission")]
    Admission,
    #[error("install lease transfer failed; outcome must be inspected")]
    Io(#[from] io::Error),
}

// Release activity, admission, and finally update exclusion. These are shared
// open descriptions: NEVER explicitly flock(UNLOCK) an exported alias.
pub(super) struct Files {
    pub(super) activity: File,
    pub(super) admission: File,
    pub(super) update: File,
}
impl Files {
    pub(super) fn wire(&self) -> [&File; 3] {
        [&self.update, &self.admission, &self.activity]
    }
}

/// One fixed app operation's retained frontend owner and three exported leases.
/// No Clone, descriptor/path access or arbitrary program API is exposed.
pub struct Handoff {
    files: Files,
    transaction: [u8; 16],
    _owner: UpdateOwner,
}
impl Handoff {
    pub(super) fn new(
        transaction: [u8; 16],
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
            transaction,
            _owner: owner,
        })
    }

    /// Public operation identity, not a secret or installation authorization.
    pub fn transaction(&self) -> [u8; 16] {
        self.transaction
    }
}

pub struct Sender {
    socket: OwnedFd,
}
pub struct Receiver {
    socket: OwnedFd,
}

/// Anonymous, CLOEXEC, finite-time SEQPACKET endpoints for a fixed fresh worker.
/// Receiving root peer credentials is not executable/candidate attestation.
pub fn channel() -> Result<(Sender, Receiver), Error> {
    if !nix::unistd::geteuid().is_root() {
        return Err(Error::Channel);
    }
    pair()
}

fn pair() -> Result<(Sender, Receiver), Error> {
    let (sender, receiver) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;
    let pid = nix::unistd::getpid().as_raw() as u32;
    prepare(&sender, pid, nix::unistd::geteuid().as_raw())?;
    prepare(&receiver, pid, nix::unistd::geteuid().as_raw())?;
    Ok((Sender { socket: sender }, Receiver { socket: receiver }))
}

impl Sender {
    /// Connect to the independent fixed broker. A successful send still means
    /// queued only; inspect canonical transaction state, never resubmit blindly.
    pub fn connect_broker() -> Result<Self, Error> {
        let socket = crate::native_owner::broker::app_install::connect_peer()?;
        let peer = socket_peercred(&socket).map_err(io::Error::from)?;
        prepare(&socket, peer.pid.as_raw_nonzero().get() as u32, 0)?;
        Ok(Self { socket })
    }

    /// Consumes once, including on error. Taken does NOT mean installed or
    /// healthy. Do not retry an ambiguous offer as a new install.
    pub fn offer(self, handoff: Handoff) -> Result<Answer, Error> {
        send(&self.socket, &handoff.transaction, &handoff.files)?;
        // A connected endpoint is nonblocking, which would read as no answer.
        let flags = fcntl_getfl(&self.socket).map_err(io::Error::from)?;
        rustix::fs::fcntl_setfl(&self.socket, flags - OFlags::NONBLOCK).map_err(io::Error::from)?;
        set_socket_timeout(&self.socket, Timeout::Recv, Some(ANSWER_TIMEOUT))
            .map_err(io::Error::from)?;
        let mut answer = [0];
        Ok(
            match rustix::net::recv(&self.socket, &mut answer, RecvFlags::empty()) {
                Ok((1, _)) if answer[0] == TAKEN => Answer::Taken,
                Ok((1, _)) if answer[0] == REFUSED => Answer::Refused(handoff),
                _ => Answer::Unknown,
            },
        )
    }

    #[cfg(test)]
    pub fn send(self, handoff: Handoff) -> Result<(), Error> {
        send(&self.socket, &handoff.transaction, &handoff.files)
    }

    #[cfg(test)]
    pub(crate) fn fixture(socket: OwnedFd, uid: u32) -> Result<Self, Error> {
        let peer = socket_peercred(&socket).map_err(io::Error::from)?;
        prepare(&socket, peer.pid.as_raw_nonzero().get() as u32, uid)?;
        Ok(Self { socket })
    }
}

fn send(socket: &OwnedFd, transaction: &[u8; 16], files: &Files) -> Result<(), Error> {
    if *transaction == [0; 16] {
        return Err(Error::Record);
    }
    let mut bytes = [0; BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(transaction);
    let wire = files.wire();
    for (encoded, file) in bytes[24..].as_chunks_mut::<16>().0.iter_mut().zip(wire) {
        let m = file.metadata()?;
        encoded[..8].copy_from_slice(&m.dev().to_be_bytes());
        encoded[8..].copy_from_slice(&m.ino().to_be_bytes());
    }
    let descriptors = wire.map(File::as_fd);
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(Error::Record);
    }
    if sendmsg(
        socket,
        &[IoSlice::new(&bytes)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(io::Error::from)?
        != BYTES
    {
        return Err(Error::Record);
    }
    Ok(())
}

/// What an installer said about one offer. `Unknown` is one that closed without
/// a word, as an older build does, or did not answer in time: inspect the
/// transaction, never submit again.
pub enum Answer {
    Taken,
    /// Nothing started. Keep the handoff until the record is withdrawn.
    Refused(Handoff),
    Unknown,
}

/// Owns all three accepted kernel exclusions; Drop is close-only.
/// Not a signed receipt, candidate identity, native stop or permission to swap.
pub struct Accepted {
    _files: Files,
    transaction: [u8; 16],
}
impl Accepted {
    pub fn transaction(&self) -> [u8; 16] {
        self.transaction
    }
}

impl Receiver {
    pub fn into_stdio(self) -> Stdio {
        self.socket.into()
    }

    /// expected_peer_pid is the socketpair creator (normally the parent), not
    /// the post-exec worker PID. No process-global descriptor mutation occurs.
    /// A fresh worker must separately redirect/close its original stdin alias
    /// before receive/exec; otherwise it can retain queued descriptor rights.
    pub fn adopt(socket: OwnedFd, expected_peer_pid: u32) -> Result<Self, Error> {
        if !nix::unistd::geteuid().is_root() {
            return Err(Error::Channel);
        }
        prepare(&socket, expected_peer_pid, 0)?;
        Ok(Self { socket })
    }

    pub fn receive(self, expected: [u8; 16]) -> Result<Accepted, Error> {
        if !nix::unistd::geteuid().is_root() {
            return Err(Error::Channel);
        }
        for path in ["/", "/etc"] {
            protected(&restore_fs::open_root(Path::new(path), true)?, 0, false)?;
        }
        let parent = restore_fs::open_root(Path::new("/etc/kvm"), true)?;
        receive(&self.socket, expected, &parent, 0)
    }
}

fn receive(
    socket: &OwnedFd,
    expected: [u8; 16],
    parent: &File,
    uid: u32,
) -> Result<Accepted, Error> {
    if expected == [0; 16] {
        return Err(Error::Record);
    }
    receive_packet(socket, Some(expected), parent, uid)
}

/// One bounded nonblocking incoming offer. The parent is pinned before any
/// packet/rights are accepted; root credentials are not candidate authority.
pub(crate) struct Incoming {
    socket: OwnedFd,
    parent: File,
    uid: u32,
    consumed: bool,
}
impl Incoming {
    pub(crate) fn open(socket: OwnedFd) -> Result<Self, Error> {
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

    pub(crate) fn poll(&mut self) -> Result<Option<Accepted>, Error> {
        if self.consumed {
            return Err(Error::Record);
        }
        match receive_packet(&self.socket, None, &self.parent, self.uid) {
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

    /// Best effort: a peer that is gone loses nothing by not hearing this.
    pub(crate) fn answer(&self, taken: bool) {
        let answer = [if taken { TAKEN } else { REFUSED }];
        let _ = rustix::net::send(&self.socket, &answer, SendFlags::NOSIGNAL);
    }

    #[cfg(test)]
    pub(crate) fn fixture(socket: OwnedFd, parent: File, uid: u32) -> Result<Self, Error> {
        Self::at_parent(socket, parent, uid)
    }
}

fn receive_packet(
    socket: &OwnedFd,
    expected: Option<[u8; 16]>,
    parent: &File,
    uid: u32,
) -> Result<Accepted, Error> {
    protected(parent, uid, false)?;
    let mut bytes = [0; BYTES];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let packet = recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(io::Error::from)?;
    if packet.bytes != BYTES
        || packet
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || &bytes[..8] != MAGIC
        || bytes[8..24] == [0; 16]
        || expected.is_some_and(|id| bytes[8..24] != id)
    {
        return Err(Error::Record);
    }
    let mut files: [Option<File>; 3] = [None, None, None];
    let mut count = 0;
    for message in ancillary.drain() {
        let RecvAncillaryMessage::ScmRights(descriptors) = message else {
            return Err(Error::Record);
        };
        for descriptor in descriptors {
            if count == files.len() {
                return Err(Error::Record);
            }
            files[count] = Some(descriptor.into());
            count += 1;
        }
    }
    let [Some(update), Some(admission), Some(activity)] = files else {
        return Err(Error::Record);
    };
    let files = Files {
        activity,
        admission,
        update,
    };
    let wire = files.wire();
    for ((file, domain), encoded) in wire
        .into_iter()
        .zip([
            Domain::Update,
            Domain::WriterAdmission,
            Domain::WriterActivity,
        ])
        .zip(bytes[24..].as_chunks::<16>().0)
    {
        check_lease(file, domain, encoded, parent, uid)?;
    }
    Ok(Accepted {
        _files: files,
        transaction: bytes[8..24].try_into().map_err(|_| Error::Record)?,
    })
}

/// One received exclusion: the exact protected directory of `domain` under
/// `parent`, read-only, close-on-exec, and exclusively locked by this OFD.
pub(super) fn check_lease(
    file: &File,
    domain: Domain,
    encoded: &[u8; 16],
    parent: &File,
    uid: u32,
) -> Result<(), Error> {
    protected(file, uid, true)?;
    let named = restore_fs::open_beneath(
        parent,
        domain.directory(),
        OFlags::RDONLY | OFlags::DIRECTORY,
    )?;
    protected(&named, uid, true)?;
    let m = file.metadata()?;
    let n = named.metadata()?;
    let mut identity = [0; 16];
    identity[..8].copy_from_slice(&m.dev().to_be_bytes());
    identity[8..].copy_from_slice(&m.ino().to_be_bytes());
    if (m.dev(), m.ino()) != (n.dev(), n.ino())
        || m.dev() != parent.metadata()?.dev()
        || identity != *encoded
        || fcntl_getfl(file).map_err(io::Error::from)? & OFlags::ACCMODE != OFlags::RDONLY
        || !fcntl_getfd(file)
            .map_err(io::Error::from)?
            .contains(FdFlags::CLOEXEC)
    {
        return Err(Error::Admission);
    }
    // Same OFD as the sender's EX lease: flock is idempotent. A separately
    // opened or still-contended description cannot bypass existing EX.
    flock(file, FlockOperation::NonBlockingLockExclusive).map_err(|_| Error::Admission)
}

pub(super) fn protected(file: &File, uid: u32, private: bool) -> Result<(), Error> {
    let m = file.metadata()?;
    if !m.is_dir()
        || m.uid() != uid
        || m.mode() & 0o7022 != 0
        || (private && m.mode() & 0o7777 != 0o700)
    {
        return Err(Error::Admission);
    }
    Ok(())
}

pub(super) fn prepare(socket: &OwnedFd, pid: u32, uid: u32) -> Result<(), Error> {
    let peer = socket_peercred(socket).map_err(io::Error::from)?;
    if pid == 0
        || peer.pid.as_raw_nonzero().get() as u32 != pid
        || peer.uid.as_raw() != uid
        || socket_domain(socket).map_err(io::Error::from)? != AddressFamily::UNIX
        || socket_type(socket).map_err(io::Error::from)? != SocketType::SEQPACKET
    {
        return Err(Error::Channel);
    }
    let flags = fcntl_getfd(socket).map_err(io::Error::from)?;
    fcntl_setfd(socket, flags | FdFlags::CLOEXEC).map_err(io::Error::from)?;
    for kind in [Timeout::Recv, Timeout::Send] {
        set_socket_timeout(socket, kind, Some(TIMEOUT)).map_err(io::Error::from)?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn exchange_fixture(handoff: Handoff, parent: &File) -> Accepted {
    let id = handoff.transaction();
    let (sender, receiver) = pair().unwrap();
    sender.send(handoff).unwrap();
    receive(
        &receiver.socket,
        id,
        parent,
        nix::unistd::geteuid().as_raw(),
    )
    .unwrap()
}

#[cfg(test)]
#[path = "app_install_lease_tests.rs"]
mod tests;
