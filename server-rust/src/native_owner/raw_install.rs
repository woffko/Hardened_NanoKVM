//! The broker's raw system-update endpoint and its exec into the raw writer.
//! Accepting an offer and stopping the scopes are not wired yet.

use super::journal;
use crate::update::{raw_transport::ImageReceiver, raw_writer::WriterArguments};
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
