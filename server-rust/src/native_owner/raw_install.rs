//! The broker's raw system update: its endpoint, the ticket check before
//! anything stops, the drain of every scope and the exec into the raw writer.

use super::{Broker, JournalError, controller, journal};
use crate::update::{
    raw_install_lease::RawAccepted,
    raw_transport::{self, ImageReceiver},
    raw_writer::WriterArguments,
    restore_capsule::ticket::{Phase, RestoreTicket, Store, TicketError},
};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
};

/// Only the fixed protected broker endpoint, never a caller-selected address.
pub(crate) fn connect_peer() -> io::Result<OwnedFd> {
    journal::Store::connect_raw_install()
}

/// The prepared ticket on the current boot partition, read before anything
/// stops. The store closes again here, long before the writer opens it.
pub(crate) fn boot_ticket() -> Result<Option<RestoreTicket>, TicketError> {
    Store::open_boot()?.load()
}

/// The writer's arguments when `ticket` names exactly this offer: a prepared
/// ticket with its transaction and both image digests.
pub(crate) fn writer_arguments(
    ticket: &RestoreTicket,
    offer: &RawAccepted,
) -> Option<WriterArguments> {
    if ticket.phase() != Phase::Prepared
        || ticket.transaction_id() != offer.transaction()
        || ticket.image_digests() != offer.sha256()
    {
        return None;
    }
    WriterArguments::new(
        offer.transaction(),
        ticket.target_version(),
        offer.sizes(),
        offer.sha256(),
    )
}

pub enum Start {
    Draining(Session),
    /// Stopping could not be recorded; nothing was asked to stop.
    Retained(Broker),
}

/// The broker after its durable Stopping record, stopping every scope for a
/// raw write. It never resumes them: only the writer's exec or a reboot ends
/// it. The accepted offer's exclusions are held beside it by the engine.
pub struct Session {
    group: controller::Drain,
    journal: journal::Store,
    _enrollment: super::boot::Permit,
    #[cfg(test)]
    _update_parent: Option<std::fs::File>,
}

impl Broker {
    /// An accepted raw offer already owns UpdateEX and writer admission and
    /// activity EX. Stopping must be durable BEFORE any owned scope Stop.
    pub fn begin_raw_write(mut self) -> Start {
        if self.journal.stopping().is_err() {
            return Start::Retained(self);
        }
        Start::Draining(Session {
            group: self.group.begin_drain(),
            journal: self.journal,
            _enrollment: self.enrollment,
            #[cfg(test)]
            _update_parent: self.update_parent,
        })
    }
}

impl Session {
    pub fn poll(&mut self) -> Result<controller::DrainStatus, JournalError> {
        self.journal.ready()?;
        // Never Closed: the raw write goes on after every tree has joined.
        Ok(self.group.poll())
    }
}

/// After every scope has stopped: a sealed copy of `program` (the broker's own
/// `/proc/self/exe`), the images queued on a fresh transport pair, then the
/// exec. Returns only on failure. Another thread would die mid-work in the
/// exec, so a second thread refuses before anything is copied.
pub fn start_writer(program: &Path, arguments: &WriterArguments, images: [File; 2]) -> io::Error {
    match single_threaded() {
        Ok(true) => {}
        Ok(false) => {
            return io::Error::other("the raw writer exec needs a single-threaded broker");
        }
        Err(error) => return error,
    }
    let program = match sealed_copy(program) {
        Ok(program) => program,
        Err(error) => return error,
    };
    let (sender, receiver) = match raw_transport::channel() {
        Ok(pair) => pair,
        Err(error) => return io::Error::other(error),
    };
    if let Err(error) = sender.send(arguments.context(), images) {
        return io::Error::other(error);
    }
    exec_writer(&program, arguments, receiver)
}

/// The prepared ticket in the engine fixture's boot directory.
#[cfg(test)]
pub(crate) fn fixture_ticket(root: &Path) -> Result<Option<RestoreTicket>, TicketError> {
    Store::open_fixture(&root.join("boot"))?.load()
}

/// The engine fixture's exec: it records what the writer would receive, then
/// fails as a failed exec does. Tests never replace their own process.
#[cfg(test)]
pub(crate) fn record_writer_fixture(
    root: &Path,
    arguments: &WriterArguments,
    images: [File; 2],
) -> io::Error {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::FileExt;
    let mut record: Vec<String> = arguments
        .to_args()
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    for image in images {
        let mut bytes = vec![0; image.metadata().map_or(0, |m| m.len() as usize)];
        if let Err(error) = image.read_exact_at(&mut bytes, 0) {
            return error;
        }
        let digest = Sha256::digest(&bytes);
        record.push(digest.iter().map(|byte| format!("{byte:02x}")).collect());
    }
    match std::fs::write(root.join("raw-writer-exec"), record.join("\n")) {
        Ok(()) => io::Error::other("fixture: the writer exec is recorded, not run"),
        Err(error) => error,
    }
}

fn single_threaded() -> io::Result<bool> {
    let mut tasks = 0;
    for task in std::fs::read_dir("/proc/self/task")? {
        task?;
        tasks += 1;
    }
    Ok(tasks == 1)
}

/// A sealed anonymous copy of `program`, the only image the raw writer mode
/// runs from. The broker copies its own executable, which lives on the root
/// filesystem that the writer overwrites.
pub fn sealed_copy(program: &Path) -> io::Result<File> {
    let mut source = File::open(program)?;
    let expected = source.metadata()?.len();
    let mut copy = File::from(memfd_create(
        "nanokvm-raw-writer",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?);
    if io::copy(&mut source, &mut copy)? != expected || copy.metadata()?.len() != expected {
        return Err(io::Error::other(
            "the writer program changed while it was copied",
        ));
    }
    fcntl_add_seals(
        &copy,
        SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE | SealFlags::SEAL,
    )?;
    Ok(copy)
}

/// Replace this process with `program` in raw writer mode, with the images'
/// socket as stdin. Returns only if the exec failed; stdin is the socket from
/// then on, and the caller stays fail-closed.
pub fn exec_writer(
    program: &File,
    arguments: &WriterArguments,
    images: ImageReceiver,
) -> io::Error {
    let mut argv = vec![
        c"nanokvm-native-broker".to_owned(),
        c"--raw-writer".to_owned(),
    ];
    for argument in arguments.to_args() {
        match CString::new(argument.as_bytes()) {
            Ok(argument) => argv.push(argument),
            Err(error) => return io::Error::other(error),
        }
    }
    exec_with_stdin(program, &argv, images.into_socket())
}

fn exec_with_stdin(program: &File, argv: &[CString], stdin: OwnedFd) -> io::Error {
    if let Err(error) = close_on_exec_beyond_stdio().and_then(|()| into_stdin(stdin)) {
        return error;
    }
    let environment: [CString; 0] = [];
    match nix::unistd::fexecve(program.as_raw_fd(), argv, &environment) {
        Err(errno) => errno.into(),
        Ok(never) => match never {},
    }
}

// The leases, the journal and every other broker descriptor close at the exec
// boundary, whatever flags they were opened with.
fn close_on_exec_beyond_stdio() -> io::Result<()> {
    let mut open = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        if let Some(fd) = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
            && fd > 2
        {
            open.push(fd);
        }
    }
    for fd in open {
        match fcntl(fd, FcntlArg::F_GETFD) {
            Ok(flags) => {
                let flags = FdFlag::from_bits_truncate(flags) | FdFlag::FD_CLOEXEC;
                fcntl(fd, FcntlArg::F_SETFD(flags))?;
            }
            // The directory listing's own descriptor, closed by now.
            Err(nix::errno::Errno::EBADF) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn into_stdin(socket: OwnedFd) -> io::Result<()> {
    if socket.as_raw_fd() == 0 {
        let fd = socket.into_raw_fd();
        let flags = FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD)?);
        fcntl(fd, FcntlArg::F_SETFD(flags - FdFlag::FD_CLOEXEC))?;
        return Ok(());
    }
    // The duplicate on 0 has no close-on-exec flag; the original closes here.
    nix::unistd::dup2(socket.as_raw_fd(), 0)?;
    Ok(())
}

#[cfg(test)]
#[path = "raw_install_tests.rs"]
mod tests;
