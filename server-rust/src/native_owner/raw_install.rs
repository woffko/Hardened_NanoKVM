//! The broker's raw system-update endpoint. Accepting an offer, stopping the
//! scopes and re-executing into the writer are not wired yet.

use super::journal;

/// Only the fixed protected broker endpoint, never a caller-selected address.
pub(crate) fn connect_peer() -> std::io::Result<std::os::fd::OwnedFd> {
    journal::Store::connect_raw_install()
}
