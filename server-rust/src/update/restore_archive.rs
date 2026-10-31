//! Bounded closed-schema restore archives. This never unpacks into live rootfs.

use rustix::fs::{Dir, OFlags};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};
use tar::{Archive, Builder, EntryType, Header};
use zeroize::Zeroizing;

use super::{
    restore_capsule::{self, CapsuleError, VerifiedPayload},
    restore_fs, restore_policy as policy,
};

const FORMAT_PATH: &str = "restore-format";
const FORMAT: &[u8] = b"nanokvm-restore-v1\n";
const BLOCK: u64 = 512;
const MAX_FILES: usize = 4096;
const MAX_PATH: usize = 240;
const MAX_DEPTH: usize = 16;
/// sshd keeps the sockets of forwarded agents here and recreates the directory.
const AGENT_SOCKETS: &str = "root/.ssh/agent";
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RestoreArchiveError {
    #[error("invalid or unsupported restore archive")]
    InvalidArchive,
    #[error("restore archive exceeds its resource budget")]
    Limit,
    #[error("restore archive contains an unauthorized path or entry")]
    Unauthorized,
    #[error("restore archive is missing required identity or settings state")]
    Incomplete,
    #[error("restore source changed or is not a single regular file")]
    InvalidSource,
    #[error(transparent)]
    Capsule(#[from] CapsuleError),
    #[error("restore archive I/O failed: {0}")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, RestoreArchiveError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreAction {
    Write,
    Absent,
}

#[derive(Debug)]
pub struct RestoreMember {
    pub path: String,
    pub action: RestoreAction,
    pub size: u64,
    pub mode: u32,
    offset: u64,
}

pub struct CapturedArchive {
    file: File,
    size: u64,
}

impl CapturedArchive {
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl Read for CapturedArchive {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.file.read(out)
    }
}
impl Seek for CapturedArchive {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

// Constructor consumes authenticated private plaintext. Consumers cannot swap
// a p3 pathname after validation, nor construct this from an unchecked archive.
pub struct ValidatedRestore {
    payload: VerifiedPayload,
    members: Vec<RestoreMember>,
}

impl ValidatedRestore {
    pub fn members(&self) -> &[RestoreMember] {
        &self.members
    }

    /// Copy only one indexed file's bytes. This does not choose/open a target
    /// pathname or apply ownership/modes; the transaction applier owns that.
    pub fn copy_file<W: Write>(&mut self, index: usize, output: &mut W) -> Result<()> {
        let member = self
            .members
            .get(index)
            .ok_or(RestoreArchiveError::InvalidArchive)?;
        if member.action != RestoreAction::Write {
            return Err(RestoreArchiveError::InvalidArchive);
        }
        self.payload.seek(SeekFrom::Start(member.offset))?;
        let copied = io::copy(&mut (&mut self.payload).take(member.size), output)?;
        if copied != member.size {
            return Err(RestoreArchiveError::InvalidArchive);
        }
        Ok(())
    }
}

#[cfg(test)]
fn capture(source_root: &Path, private_staging: &Path) -> Result<CapturedArchive> {
    let source = SourceRoot::open(source_root)?;
    capture_canonical(&source, private_staging, &[], &[])
}

/// A captured archive of synthetic required state, for other modules' tests.
#[cfg(test)]
pub(crate) fn fixture_archive(source_root: &Path, private_staging: &Path) -> CapturedArchive {
    for path in policy::REQUIRED
        .iter()
        .copied()
        .chain(["etc/kvm/session_secret"])
    {
        let path = source_root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"synthetic fixture state\n").unwrap();
    }
    capture(source_root, private_staging).unwrap()
}

// Only the effective-state normalizer can supply canonical replacements. A
// missing optional replacement suppresses stale state at its old default path.
pub(super) struct CanonicalSetting<'a> {
    pub path: &'a str,
    pub bytes: Option<Zeroizing<Vec<u8>>>,
}

// An inventory already captured and validated as a whole must not be scanned
// again: later files would bypass that snapshot's semantic checks.
pub(super) enum SnapshottedTree {
    SshdConfig,
}

pub(super) fn capture_canonical(
    source: &SourceRoot,
    private_staging: &Path,
    overrides: &[CanonicalSetting<'_>],
    snapshotted_trees: &[SnapshottedTree],
) -> Result<CapturedArchive> {
    let mut override_paths = BTreeSet::new();
    for replacement in overrides {
        if !(policy::REQUIRED.contains(&replacement.path)
            || policy::FIXED.contains(&replacement.path)
            || policy::PRESENCE.contains(&replacement.path)
            || (replacement.path.starts_with("etc/ssh/sshd_config.d/")
                && policy::allowed(replacement.path)))
            || !override_paths.insert(replacement.path)
            || (policy::REQUIRED.contains(&replacement.path) && replacement.bytes.is_none())
        {
            return Err(RestoreArchiveError::Unauthorized);
        }
    }
    let mut paths = BTreeSet::new();
    for path in policy::REQUIRED
        .iter()
        .chain(policy::FIXED)
        .chain(policy::PRESENCE)
    {
        if !override_paths.contains(path) && source.metadata(path)?.is_some() {
            paths.insert((*path).to_string());
        }
    }
    let mut scanned = 0;
    for tree in policy::TREES {
        if snapshotted_trees.iter().any(|snapshot| match snapshot {
            SnapshottedTree::SshdConfig => *tree == "etc/ssh/sshd_config.d",
        }) {
            continue;
        }
        collect_tree(source, tree, &mut paths, 0, &mut scanned)?;
    }
    // Tree inventories may contain the dynamic SSH config paths already pinned
    // in canonical snapshots. Never append a second live/unchecked copy.
    paths.retain(|path| !override_paths.contains(path.as_str()));
    let mut present = BTreeSet::new();
    let mut planned = Vec::with_capacity(paths.len() + policy::PRESENCE.len() + overrides.len());
    let mut length = BLOCK + rounded(FORMAT.len() as u64)? + 2 * BLOCK;
    for path in &paths {
        let metadata = source
            .metadata(path)?
            .ok_or(RestoreArchiveError::InvalidSource)?;
        let size = if path == "boot/usb.disk0" {
            0
        } else {
            metadata.len()
        };
        check_size(size)?;
        if (policy::REQUIRED.contains(&path.as_str()) || path == "etc/kvm/session_secret")
            && size == 0
        {
            return Err(RestoreArchiveError::Incomplete);
        }
        length = length
            .checked_add(BLOCK + rounded(size)?)
            .ok_or(RestoreArchiveError::Limit)?;
        present.insert(path.clone());
        planned.push((path.clone(), Some(metadata), size, None));
    }
    for replacement in overrides {
        let Some(bytes) = &replacement.bytes else {
            continue;
        };
        let size = bytes.len() as u64;
        check_size(size)?;
        if size == 0
            && (policy::REQUIRED.contains(&replacement.path)
                || replacement.path == "etc/kvm/session_secret")
        {
            return Err(RestoreArchiveError::Incomplete);
        }
        length = length
            .checked_add(BLOCK + rounded(size)?)
            .ok_or(RestoreArchiveError::Limit)?;
        present.insert(replacement.path.to_string());
        planned.push((
            replacement.path.to_string(),
            None,
            size,
            Some(bytes.as_slice()),
        ));
    }
    for path in policy::PRESENCE {
        if !present.contains(*path) {
            length = length
                .checked_add(BLOCK)
                .ok_or(RestoreArchiveError::Limit)?;
            planned.push(((*path).to_string(), None, 0, None));
        }
    }
    check_required(&present)?;
    if planned.len() > MAX_FILES || length > restore_capsule::MAX_PLAINTEXT_BYTES {
        return Err(RestoreArchiveError::Limit);
    }
    planned.sort_by(|a, b| a.0.cmp(&b.0));
    let mut file = restore_capsule::create_private_spool(private_staging)?;
    {
        let mut builder = Builder::new(&mut file);
        append(
            &mut builder,
            FORMAT_PATH,
            FORMAT.len() as u64,
            0o600,
            &mut &FORMAT[..],
        )?;
        for (path, metadata, size, bytes) in planned {
            if let Some(bytes) = bytes {
                append(
                    &mut builder,
                    &format!("files/{path}"),
                    size,
                    policy::mode(&path),
                    &mut &bytes[..],
                )?;
                continue;
            }
            match metadata {
                Some(metadata) => {
                    let mut file = source.open_file(&path, &metadata)?;
                    if path == "boot/usb.disk0" {
                        // Preserve only enablement. Never archive old raw/custom
                        // contents as a future configfs backing pathname.
                        append(
                            &mut builder,
                            &format!("files/{path}"),
                            0,
                            policy::mode(&path),
                            &mut io::empty(),
                        )?;
                    } else {
                        append(
                            &mut builder,
                            &format!("files/{path}"),
                            size,
                            policy::mode(&path),
                            &mut file,
                        )?;
                        if file.read(&mut [0])? != 0 {
                            return Err(RestoreArchiveError::InvalidSource);
                        }
                    }
                    if !same_file(&metadata, &file.metadata()?) {
                        return Err(RestoreArchiveError::InvalidSource);
                    }
                }
                None => append(
                    &mut builder,
                    &format!("absent/{path}"),
                    0,
                    0o600,
                    &mut io::empty(),
                )?,
            }
        }
        builder.finish()?;
    }
    if file.metadata()?.len() != length {
        return Err(RestoreArchiveError::InvalidArchive);
    }
    file.sync_all()?;
    file.rewind()?;
    Ok(CapturedArchive { file, size: length })
}

pub fn validate(mut payload: VerifiedPayload) -> Result<ValidatedRestore> {
    payload.rewind()?;
    let length = payload.seek(SeekFrom::End(0))?;
    if !(BLOCK * 3..=restore_capsule::MAX_PLAINTEXT_BYTES).contains(&length) || length % BLOCK != 0
    {
        return Err(RestoreArchiveError::InvalidArchive);
    }
    payload.rewind()?;
    let mut archive = Archive::new(payload);
    let mut members = Vec::with_capacity(MAX_FILES);
    let mut seen = BTreeSet::new();
    let mut writes = BTreeSet::new();
    let mut end = 0;
    let mut format_seen = false;
    for entry in archive.entries_with_seek()?.raw(true) {
        let mut entry = entry?;
        let header = entry.header();
        // Reject extensions before reading path/extension bodies. The raw
        // iterator must never allocate GNU/PAX long-name content from a header.
        if header.entry_type() != EntryType::Regular
            || header.as_ustar().is_none()
            || header.uid()? != 0
            || header.gid()? != 0
            || header.link_name_bytes().is_some()
            || entry.raw_header_position() != end
        {
            return Err(RestoreArchiveError::Unauthorized);
        }
        let name = header.path_bytes();
        let name = std::str::from_utf8(&name).map_err(|_| RestoreArchiveError::Unauthorized)?;
        let size = header.size()?;
        let mode = header.mode()?;
        check_size(size)?;
        let offset = entry.raw_file_position();
        end = offset
            .checked_add(rounded(size)?)
            .ok_or(RestoreArchiveError::Limit)?;
        if end.checked_add(BLOCK * 2).is_none_or(|end| end > length) {
            return Err(RestoreArchiveError::InvalidArchive);
        }
        if !format_seen {
            if name != FORMAT_PATH || size != FORMAT.len() as u64 || mode != 0o600 {
                return Err(RestoreArchiveError::InvalidArchive);
            }
            let mut data = [0; FORMAT.len()];
            entry.read_exact(&mut data)?;
            if data != FORMAT {
                return Err(RestoreArchiveError::InvalidArchive);
            }
            format_seen = true;
            continue;
        }
        let (action, path) = if let Some(path) = name.strip_prefix("files/") {
            (RestoreAction::Write, path)
        } else if let Some(path) = name.strip_prefix("absent/") {
            (RestoreAction::Absent, path)
        } else {
            return Err(RestoreArchiveError::Unauthorized);
        };
        check_path(path)?;
        if !policy::allowed(path) || !seen.insert(path.to_string()) {
            return Err(RestoreArchiveError::Unauthorized);
        }
        match action {
            RestoreAction::Write => {
                if mode != policy::mode(path) || (path == "boot/usb.disk0" && size != 0) {
                    return Err(RestoreArchiveError::Unauthorized);
                }
                if (policy::REQUIRED.contains(&path) || path == "etc/kvm/session_secret")
                    && size == 0
                {
                    return Err(RestoreArchiveError::Incomplete);
                }
                writes.insert(path.to_string());
            }
            RestoreAction::Absent => {
                if !policy::PRESENCE.contains(&path) || size != 0 || mode != 0o600 {
                    return Err(RestoreArchiveError::Unauthorized);
                }
            }
        }
        if members.len() == MAX_FILES {
            return Err(RestoreArchiveError::Limit);
        }
        members.push(RestoreMember {
            path: path.to_string(),
            action,
            size,
            mode,
            offset,
        });
    }
    if !format_seen {
        return Err(RestoreArchiveError::Incomplete);
    }
    check_required(&writes)?;
    if !policy::PRESENCE.iter().all(|path| seen.contains(*path)) {
        return Err(RestoreArchiveError::Incomplete);
    }
    for path in &seen {
        let mut parent = Path::new(path).parent();
        while let Some(candidate) = parent {
            if candidate.to_str().is_some_and(|path| writes.contains(path)) {
                return Err(RestoreArchiveError::Unauthorized);
            }
            parent = candidate.parent();
        }
    }
    let mut payload = archive.into_inner();
    // Require canonical zero padding and a real two-block trailer. No hidden
    // concatenated archive, extension or data after the first zero header.
    for member in &members {
        check_zeroes(
            &mut payload,
            member.offset + member.size,
            rounded(member.size)? - member.size,
        )?;
    }
    check_zeroes(
        &mut payload,
        BLOCK + FORMAT.len() as u64,
        rounded(FORMAT.len() as u64)? - FORMAT.len() as u64,
    )?;
    check_zeroes(&mut payload, end, length - end)?;
    members.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(ValidatedRestore { payload, members })
}

fn append<R: Read>(
    builder: &mut Builder<&mut File>,
    name: &str,
    size: u64,
    mode: u32,
    source: &mut R,
) -> Result<()> {
    let mut header = Header::new_ustar();
    header.set_path(name)?;
    header.set_entry_type(EntryType::Regular);
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    let mut bounded = source.take(size);
    builder.append(&header, &mut bounded)?;
    if bounded.limit() != 0 {
        return Err(RestoreArchiveError::InvalidSource);
    }
    Ok(())
}

fn check_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAX_PATH
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path.split('/').count() > MAX_DEPTH
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(RestoreArchiveError::Unauthorized);
    }
    Ok(())
}

fn rounded(size: u64) -> Result<u64> {
    size.checked_add(BLOCK - 1)
        .map(|n| n / BLOCK * BLOCK)
        .ok_or(RestoreArchiveError::Limit)
}
fn check_size(size: u64) -> Result<()> {
    if size > MAX_FILE_BYTES {
        Err(RestoreArchiveError::Limit)
    } else {
        Ok(())
    }
}

fn check_required(paths: &BTreeSet<String>) -> Result<()> {
    if !policy::REQUIRED.iter().all(|path| paths.contains(*path))
        || !(paths.contains("etc/kvm/session_secret") || paths.contains("etc/kvm/server.yaml"))
    {
        return Err(RestoreArchiveError::Incomplete);
    }
    Ok(())
}

pub(super) struct SourceRoot {
    root: File,
    boot: Option<File>,
}

impl SourceRoot {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let root = restore_fs::open_root(path, false).map_err(source_error)?;
        let boot = match restore_fs::open_boot(&root) {
            Ok(file) => Some(file),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(source_error(err)),
        };
        Ok(Self { root, boot })
    }

    fn open_path(&self, relative: &str, flags: OFlags) -> Result<Option<File>> {
        check_path(relative)?;
        let (root, path) = if let Some(path) = relative.strip_prefix("boot/") {
            let Some(boot) = &self.boot else {
                return Ok(None);
            };
            (boot, path)
        } else {
            (&self.root, relative)
        };
        match restore_fs::open_beneath(root, path, flags) {
            Ok(file) => Ok(Some(file)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(source_error(err)),
        }
    }

    pub(super) fn exists(&self, relative: &str) -> Result<bool> {
        Ok(self.open_path(relative, OFlags::PATH)?.is_some())
    }

    pub(super) fn metadata(&self, relative: &str) -> Result<Option<fs::Metadata>> {
        let Some(file) = self.open_path(relative, OFlags::PATH)? else {
            return Ok(None);
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(RestoreArchiveError::InvalidSource);
        }
        Ok(Some(metadata))
    }

    fn open_file(&self, relative: &str, expected: &fs::Metadata) -> Result<File> {
        let file = self
            .open_path(relative, OFlags::RDONLY | OFlags::NONBLOCK)?
            .ok_or(RestoreArchiveError::InvalidSource)?;
        if !same_file(expected, &file.metadata()?) {
            return Err(RestoreArchiveError::InvalidSource);
        }
        Ok(file)
    }

    pub(super) fn read_setting(
        &self,
        relative: &str,
        limit: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Some(metadata) = self.metadata(relative)? else {
            return Ok(None);
        };
        if metadata.len() > limit as u64 {
            return Err(RestoreArchiveError::Limit);
        }
        let mut file = self.open_file(relative, &metadata)?;
        let mut bytes = Zeroizing::new(vec![0; metadata.len() as usize]);
        file.read_exact(&mut bytes)?;
        if file.read(&mut [0])? != 0 || !same_file(&metadata, &file.metadata()?) {
            return Err(RestoreArchiveError::InvalidSource);
        }
        Ok(Some(bytes))
    }
}

fn source_error(err: io::Error) -> RestoreArchiveError {
    match err.raw_os_error() {
        Some(nix::libc::ELOOP | nix::libc::EXDEV | nix::libc::ENOTDIR | nix::libc::EAGAIN) => {
            RestoreArchiveError::InvalidSource
        }
        _ if err.kind() == io::ErrorKind::InvalidInput => RestoreArchiveError::InvalidSource,
        _ => err.into(),
    }
}

fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    b.is_file()
        && b.nlink() == 1
        && a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

/// The first entry of a directory that the schema does not cover.
pub(super) fn unlisted(root: &SourceRoot, relative: &str) -> Result<Option<String>> {
    let Some(directory) = root.open_path(relative, OFlags::RDONLY | OFlags::DIRECTORY)? else {
        return Ok(None);
    };
    for entry in Dir::new(directory).map_err(io::Error::from)? {
        let entry = entry.map_err(io::Error::from)?;
        let name = String::from_utf8_lossy(entry.file_name().to_bytes());
        if name == "." || name == ".." {
            continue;
        }
        let path = format!("{relative}/{name}");
        let listed = if entry.file_type() == rustix::fs::FileType::Directory {
            policy::TREES.contains(&path.as_str()) || path == AGENT_SOCKETS
        } else {
            policy::allowed(&path)
        };
        if !listed {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

pub(super) fn collect_tree(
    root: &SourceRoot,
    relative: &str,
    out: &mut BTreeSet<String>,
    depth: usize,
    scanned: &mut usize,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(RestoreArchiveError::Limit);
    }
    let Some(directory) = root.open_path(relative, OFlags::RDONLY | OFlags::DIRECTORY)? else {
        return Ok(());
    };
    for entry in Dir::new(directory).map_err(io::Error::from)? {
        let entry = entry.map_err(io::Error::from)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| RestoreArchiveError::InvalidSource)?;
        if name == "." || name == ".." {
            continue;
        }
        *scanned += 1;
        if *scanned > MAX_FILES * 2 {
            return Err(RestoreArchiveError::Limit);
        }
        let relative = format!("{relative}/{name}");
        check_path(&relative)?;
        let metadata = root
            .open_path(&relative, OFlags::PATH)?
            .ok_or(RestoreArchiveError::InvalidSource)?
            .metadata()?;
        if metadata.is_dir() {
            // Do not descend into signed skill/profile state excluded by policy,
            // or into the sockets sshd keeps for forwarded agents.
            if !matches!(
                relative.as_str(),
                "root/.picoclaw/workspace/skills/kvm-control" | AGENT_SOCKETS
            ) {
                collect_tree(root, &relative, out, depth + 1, scanned)?;
            }
        } else if metadata.is_file() && policy::allowed(&relative) {
            if out.len() >= MAX_FILES {
                return Err(RestoreArchiveError::Limit);
            }
            out.insert(relative);
        } else if relative != "root/.picoclaw/workspace/AGENT.md" {
            // Never silently drop unsupported state from a selected tree. The
            // only ignored file is the profile regenerated by the signed app.
            return Err(RestoreArchiveError::InvalidSource);
        }
    }
    Ok(())
}

fn check_zeroes<R: Read + Seek>(reader: &mut R, start: u64, mut length: u64) -> Result<()> {
    reader.seek(SeekFrom::Start(start))?;
    let mut buffer = [0; 512];
    while length > 0 {
        let count = length.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..count])?;
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err(RestoreArchiveError::InvalidArchive);
        }
        length -= count as u64;
    }
    Ok(())
}

#[cfg(test)]
#[path = "restore_archive_tests.rs"]
mod tests;
