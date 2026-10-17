//! Private SSH identity staging, never an applier or restore authorization.
//! Only IdentityCheckedRestore supplies bytes. The parent must keep the guard,
//! hold the common lock and quiesce writers until the native child is reaped.

use super::{
    restore_archive::RestoreAction, restore_fs, restore_identity::IdentityCheckedRestore,
    restore_ssh,
};
use rustix::fs::{
    AtFlags, Dir, Gid, Mode, OFlags, ResolveFlags, Uid, fchmod, fchown, mkdirat, openat2, unlinkat,
};
use std::{
    fs::File,
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const DIRECTORIES: [&str; 14] = [
    ".oldroot",
    "proc",
    "sys",
    "data",
    "dev",
    "etc",
    "etc/ssh",
    "etc/ssh/sshd_config.d",
    "root",
    "root/.ssh",
    "run",
    "run/sshd",
    "var",
    "var/empty",
];
const TABLES: [&str; 4] = ["etc/passwd", "etc/group", "etc/shadow", "etc/gshadow"];
const MAX_FILES: usize = 140;
const MAX_BYTES: u64 = 9 * 1024 * 1024;
const MAX_HOST_FILE: u64 = 64 * 1024;
const NSS: &[u8] = b"passwd: files\ngroup: files\nshadow: files\nhosts: files\n";

#[derive(Debug, thiserror::Error)]
pub enum PrepareRootError {
    #[error("SSH preflight staging requires an empty private root-owned rootfs directory")]
    Root,
    #[error("SSH preflight identity exceeds its fixed input policy")]
    Input,
    #[error("SSH preflight staging I/O failed")]
    Io,
}
type Result<T> = std::result::Result<T, PrepareRootError>;

struct Created {
    path: String,
    directory: bool,
    identity: [u64; 2],
}

/// Owns only the entries it created, not the caller's empty outer directory.
/// No Debug/Clone/serde/fd escape. Path access is not a signature or ticket.
/// Keep this alive until the child exits: cleanup unlinks its identity inputs.
pub struct PreparedSshRoot {
    root: File,
    path: PathBuf,
    created: Vec<Created>,
}

impl PreparedSshRoot {
    /// Recheck the root pathname immediately before passing it to the helper.
    /// Caller-protected ancestors and no concurrent local root remain required.
    pub fn checked_path(&self) -> Result<&Path> {
        let reopened =
            restore_fs::open_root(&self.path, true).map_err(|_| PrepareRootError::Root)?;
        let expected = self.root.metadata().map_err(|_| PrepareRootError::Io)?;
        let actual = reopened.metadata().map_err(|_| PrepareRootError::Io)?;
        if actual.dev() != expected.dev()
            || actual.ino() != expected.ino()
            || actual.uid() != 0
            || actual.mode() & 0o7777 != 0o700
        {
            return Err(PrepareRootError::Root);
        }
        Ok(&self.path)
    }

    /// Use after kill/reap; report cleanup failure instead of claiming removal.
    /// Drop is only best effort. Never recursively remove unexpected entries.
    pub fn cleanup(mut self) -> Result<()> {
        self.remove_created()
    }

    fn remove_created(&mut self) -> Result<()> {
        let mut failed = false;
        while let Some(entry) = self.created.pop() {
            // unlinkat has no openat2 resolve flags. Pin every intermediate
            // parent without links/mounts, then unlink just the final basename.
            // Never follow a replaced etc/root directory into another tree.
            let result = checked_parent(&self.root, &entry.path).and_then(|(parent, name)| {
                let current = restore_fs::open_beneath(&parent, name, OFlags::PATH)
                    .map_err(|_| PrepareRootError::Io)?;
                let metadata = current.metadata().map_err(|_| PrepareRootError::Io)?;
                if [metadata.dev(), metadata.ino()] != entry.identity {
                    return Err(PrepareRootError::Io);
                }
                unlinkat(
                    &parent,
                    name,
                    if entry.directory {
                        AtFlags::REMOVEDIR
                    } else {
                        AtFlags::empty()
                    },
                )
                .map_err(|_| PrepareRootError::Io)
            });
            failed |= result.is_err();
        }
        if failed {
            Err(PrepareRootError::Io)
        } else {
            Ok(())
        }
    }

    fn create_file(&mut self, path: &str, mode: u32) -> Result<File> {
        // All parents are fixed directories created above; the path is selected
        // only by the closed identity plan. EXCL prevents covering prior state.
        let file: File = openat2(
            &self.root,
            path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
        .map_err(|_| PrepareRootError::Io)?
        .into();
        let metadata = file.metadata().map_err(|_| PrepareRootError::Io)?;
        self.created.push(Created {
            path: path.to_owned(),
            directory: false,
            identity: [metadata.dev(), metadata.ino()],
        });
        fchown(&file, Some(Uid::ROOT), Some(Gid::ROOT)).map_err(|_| PrepareRootError::Io)?;
        fchmod(&file, Mode::from_raw_mode(mode)).map_err(|_| PrepareRootError::Io)?;
        Ok(file)
    }
}

impl Drop for PreparedSshRoot {
    fn drop(&mut self) {
        let _ = self.remove_created();
    }
}

/// Materialize only checked account/SSH data into an EMPTY private directory
/// on /. No factory identity, live /etc, mutable target tree or executable code.
/// This is ephemeral named native-input staging, not a plaintext archive spool
/// or a durable restore commit. It has no boot/app/enablement/settings side effect.
pub fn prepare_sshd_root(
    identity: &mut IdentityCheckedRestore,
    path: &Path,
) -> Result<PreparedSshRoot> {
    // Plan and reject budget failures before creating even a placeholder.
    let mut indexes = Vec::with_capacity(MAX_FILES);
    let mut total = 0_u64;
    for (index, member) in identity.members().iter().enumerate() {
        let host_file = matches!(member.path.as_str(), "etc/hosts" | "etc/hostname");
        if !(TABLES.contains(&member.path.as_str())
            || host_file
            || restore_ssh::runtime_file(&member.path))
        {
            continue;
        }
        if member.action != RestoreAction::Write {
            return Err(PrepareRootError::Input);
        }
        total = total
            .checked_add(member.size)
            .ok_or(PrepareRootError::Input)?;
        if indexes.len() == MAX_FILES
            || total > MAX_BYTES
            || (host_file && member.size > MAX_HOST_FILE)
        {
            return Err(PrepareRootError::Input);
        }
        indexes.push(index);
    }
    let root = restore_fs::open_root(path, true).map_err(|_| PrepareRootError::Root)?;
    let metadata = root.metadata().map_err(|_| PrepareRootError::Io)?;
    if !nix::unistd::geteuid().is_root() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700
    {
        return Err(PrepareRootError::Root);
    }
    for entry in Dir::read_from(&root).map_err(|_| PrepareRootError::Io)? {
        let entry = entry.map_err(|_| PrepareRootError::Io)?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Err(PrepareRootError::Root);
        }
    }
    let mut prepared = PreparedSshRoot {
        root,
        path: path.to_path_buf(),
        created: Vec::with_capacity(MAX_FILES + DIRECTORIES.len() + 2),
    };
    for directory in DIRECTORIES {
        let (parent, name) = checked_parent(&prepared.root, directory)?;
        mkdirat(&parent, name, Mode::RWXU).map_err(|_| PrepareRootError::Io)?;
        let fd = restore_fs::open_beneath(
            &prepared.root,
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY,
        )
        .map_err(|_| PrepareRootError::Io)?;
        let metadata = fd.metadata().map_err(|_| PrepareRootError::Io)?;
        prepared.created.push(Created {
            path: directory.to_owned(),
            directory: true,
            identity: [metadata.dev(), metadata.ino()],
        });
        fchown(&fd, Some(Uid::ROOT), Some(Gid::ROOT)).map_err(|_| PrepareRootError::Io)?;
        fchmod(&fd, Mode::RWXU).map_err(|_| PrepareRootError::Io)?;
    }
    drop(prepared.create_file("dev/null", 0o600)?);
    prepared
        .create_file("etc/nsswitch.conf", 0o644)?
        .write_all(NSS)
        .map_err(|_| PrepareRootError::Io)?;
    for index in indexes {
        let member = &identity.members()[index];
        let mode = match member.path.as_str() {
            "etc/passwd" | "etc/group" | "etc/hosts" | "etc/hostname" => 0o644,
            _ => 0o600,
        };
        let mut file = prepared.create_file(&member.path, mode)?;
        identity
            .copy_file(index, &mut file)
            .map_err(|_| PrepareRootError::Io)?;
    }
    prepared.checked_path()?;
    Ok(prepared)
}

fn checked_parent<'a>(root: &File, path: &'a str) -> Result<(File, &'a str)> {
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    let directory = if parent.is_empty() {
        root.try_clone().map_err(|_| PrepareRootError::Io)?
    } else {
        restore_fs::open_beneath(root, parent, OFlags::RDONLY | OFlags::DIRECTORY)
            .map_err(|_| PrepareRootError::Io)?
    };
    Ok((directory, name))
}
