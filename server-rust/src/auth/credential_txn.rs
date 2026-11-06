//! Root and web credentials change together through one journal.
//!
//! `/etc/shadow` and the web account file are separate stores. Before either is
//! replaced, a journal holding both previous files is durable. A failed change
//! restores them at once; an interrupted one is restored at the next start,
//! before any request is served. Success is reported only once both stores are
//! replaced and the journal is durably gone.
//!
//! Root's hash comes from BusyBox `mkpasswd`, which writes no file. Native
//! `passwd` is not used: its own rename of `/etc/shadow` could not be bound to
//! this journal.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{AppError, Result};

pub(crate) const SHADOW_FILE: &str = "/etc/shadow";
pub(crate) const PASSWD_FILE: &str = "/etc/passwd";
/// A stored password field shorter than this is no crypt(3) hash; OpenSSH
/// 10.6p2 refuses such fields for the same reason.
const MIN_HASH_CHARS: usize = 4;
const MAGIC: &[u8; 8] = b"NKCRED01";
/// Bound for each stored file; the frozen trial reads the account under it too.
const MAX_STORE_BYTES: usize = 64 * 1024;
const MAX_JOURNAL_BYTES: usize = MAGIC.len() + 2 * (16 + MAX_STORE_BYTES) + 1 + 32;
const DIGEST_BYTES: usize = 32;
const SCRATCH: &str = "nanokvm-new";
const CRYPT_ALPHABET: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const SALT_CHARS: usize = 16;
const SHA512_CRYPT_CHARS: usize = 86;
/// 2020-01-01 in days. An earlier clock is unset: no RTC and no NTP yet.
const FIRST_PLAUSIBLE_DAY: u64 = 18_262;
const PENDING: &str = "an interrupted credential change is restored at the next start";
const RESTORE_AT_START: &str =
    "the credential change failed; the previous credentials are restored at the next start";

/// What a change expects of the web account it replaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    /// First setup: no web account exists yet.
    Setup,
    /// Password change: the web account exists.
    Replace,
}

/// The two credential stores. The journal lives beside the web account.
#[derive(Debug, Clone)]
pub(crate) struct CredentialFiles {
    pub(crate) shadow: PathBuf,
    pub(crate) account: PathBuf,
}

/// One stored file, with the mode and owner it is restored with.
struct Store {
    bytes: Zeroizing<Vec<u8>>,
    mode: u32,
    uid: u32,
    gid: u32,
}

/// Mode and owner of a file this module writes. No owner keeps the writer's.
struct Owner {
    mode: u32,
    ids: Option<(u32, u32)>,
}

const PRIVATE: Owner = Owner {
    mode: 0o600,
    ids: None,
};

/// The stores as they were before the change. No account means first setup.
struct Journal {
    shadow: Store,
    account: Option<Store>,
}

/// Points of a change where host tests inject a fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    Journaled,
    ShadowReplaced,
    AccountReplaced,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// The step fails with an I/O error; the change is undone at once.
    Fail,
    /// The process stops right after the step, leaving the files as they are.
    Crash,
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Option<(Step, Fault)>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn inject(fault: Option<(Step, Fault)>) {
    FAULT.with(|cell| cell.set(fault));
}

/// `Ok(true)` stops the change as a crashed process would; only tests inject.
fn reached(_step: Step) -> io::Result<bool> {
    #[cfg(test)]
    match FAULT.with(|cell| cell.get()) {
        Some((at, Fault::Fail)) if at == _step => {
            return Err(io::Error::other("injected credential fault"));
        }
        Some((at, Fault::Crash)) if at == _step => return Ok(true),
        _ => {}
    }
    Ok(false)
}

impl CredentialFiles {
    fn journal(&self) -> PathBuf {
        beside(&self.account, "journal")
    }

    fn scratch(&self) -> [PathBuf; 3] {
        [
            scratch(&self.shadow),
            scratch(&self.account),
            scratch(&self.journal()),
        ]
    }

    /// A journal or a scratch file of an interrupted change exists. Errors
    /// other than absence count as pending, so recovery reports them.
    pub(crate) fn recovery_pending(&self) -> bool {
        std::iter::once(self.journal())
            .chain(self.scratch())
            .any(|path| !matches!(present(&path), Ok(false)))
    }
}

/// Replace root's password hash and the web account as one change. `account`
/// is the complete new web account file; `root_hash` is a SHA-512 crypt(3)
/// string for the same password.
pub(crate) fn replace(
    files: &CredentialFiles,
    change: Change,
    account: &[u8],
    root_hash: &str,
) -> Result<()> {
    let journal_path = files.journal();
    if present(&journal_path)? {
        return Err(AppError::Conflict(PENDING.into()));
    }
    let shadow = read_store(&files.shadow)?
        .ok_or_else(|| AppError::Internal("the root account store is missing".into()))?;
    let previous = read_store(&files.account)?;
    match (change, &previous) {
        (Change::Setup, Some(_)) => {
            return Err(AppError::Conflict("account already initialized".into()));
        }
        (Change::Replace, None) => {
            return Err(AppError::NotFound("account not initialized".into()));
        }
        _ => {}
    }
    let next_shadow = with_root_hash(&shadow.bytes, root_hash, today())?;
    let journal = Journal {
        shadow,
        account: previous,
    };

    if let Err(error) = write_atomic(&journal_path, &journal.encode(), &PRIVATE) {
        // Nothing is replaced yet; a journal left behind restores the same files.
        let _ = remove_durably(&journal_path);
        return Err(error.into());
    }
    let applied = (|| -> io::Result<bool> {
        if reached(Step::Journaled)? {
            return Ok(true);
        }
        write_atomic(&files.shadow, &next_shadow, &journal.shadow.owner())?;
        if reached(Step::ShadowReplaced)? {
            return Ok(true);
        }
        write_atomic(&files.account, account, &PRIVATE)?;
        reached(Step::AccountReplaced)
    })();
    match applied {
        Ok(false) => {}
        // An injected crash leaves every file for the next start.
        Ok(true) => return Err(AppError::Internal("stopped at an injected crash".into())),
        Err(error) => {
            roll_back(files, &journal)?;
            return Err(error.into());
        }
    }

    // Removing the journal commits the change.
    if fs::remove_file(&journal_path).is_err() {
        roll_back(files, &journal)?;
        return Err(AppError::Internal(
            "the credential change could not be committed and was undone".into(),
        ));
    }
    sync_parent(&journal_path).map_err(|_| {
        AppError::Internal(
            "the credential change is applied, but its commit is not confirmed durable".into(),
        )
    })
}

/// Restore the stores of an interrupted change and close it. Runs at start,
/// under the account permit, before any request is served. `Ok(true)` means a
/// change was undone.
pub(crate) fn recover(files: &CredentialFiles) -> Result<bool> {
    let journal_path = files.journal();
    let restored = match read_bounded(&journal_path, MAX_JOURNAL_BYTES)? {
        Some(stored) => {
            let journal = Journal::decode(&stored.bytes)?;
            restore(files, &journal)?;
            remove_durably(&journal_path)?;
            true
        }
        None => false,
    };
    // Scratch names belong to this module; without a journal they bind nothing.
    for path in files.scratch() {
        remove_durably(&path)?;
    }
    Ok(restored)
}

/// Lock every account that no person logs in to and whose shadow field holds no
/// hash. Without PAM, OpenSSH before 10.6p2 checks a password for a field of
/// `*` with the salt of another account's hash, and musl's crypt(3) returns `*`
/// for any password longer than 256 bytes, so the two match: CVE-2026-123158.
/// A leading `!` makes sshd refuse the account before any method runs. Root and
/// the accounts of people stay as they are, because `*` there may stand for a
/// login by key alone. Returns the accounts it locked. A pending credential
/// change is left to its recovery at the next start.
pub(crate) fn lock_service_accounts(files: &CredentialFiles, passwd: &Path) -> Result<Vec<String>> {
    if present(&files.journal())? {
        return Err(AppError::Conflict(PENDING.into()));
    }
    let Some(accounts) = read_store(passwd)? else {
        return Ok(Vec::new());
    };
    let services = service_accounts(&accounts.bytes);
    let shadow = read_store(&files.shadow)?
        .ok_or_else(|| AppError::Internal("the root account store is missing".into()))?;
    let (next, locked) = with_services_locked(&shadow.bytes, &services);
    if !locked.is_empty() {
        write_atomic(&files.shadow, &next, &shadow.owner())?;
    }
    Ok(locked)
}

/// Accounts of `/etc/passwd` that are neither root nor a person's, by the rule
/// a raw update uses to tell the image's accounts from a device's own.
fn service_accounts(passwd: &[u8]) -> BTreeSet<String> {
    passwd
        .split(|byte| *byte == b'\n')
        .filter_map(|line| std::str::from_utf8(line).ok())
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let service = fields.len() == 7
                && !fields[0].is_empty()
                && fields[2].parse::<u32>().is_ok_and(|uid| uid != 0)
                && !crate::update::restore_native::person(fields[2], fields[6]);
            service.then(|| fields[0].to_string())
        })
        .collect()
}

/// `shadow` with `!` put in front of each listed account's field that is shorter
/// than a hash and not locked yet; every other byte stays.
fn with_services_locked(
    shadow: &[u8],
    services: &BTreeSet<String>,
) -> (Zeroizing<Vec<u8>>, Vec<String>) {
    let mut out = Zeroizing::new(Vec::with_capacity(shadow.len() + services.len()));
    let mut locked = Vec::new();
    for (index, line) in shadow.split(|byte| *byte == b'\n').enumerate() {
        if index > 0 {
            out.push(b'\n');
        }
        let mut parts = line.splitn(3, |byte| *byte == b':');
        let (Some(name), Some(field), Some(_)) = (parts.next(), parts.next(), parts.next()) else {
            out.extend_from_slice(line);
            continue;
        };
        let name = std::str::from_utf8(name)
            .ok()
            .filter(|name| services.contains(*name));
        match name {
            Some(name) if field.len() < MIN_HASH_CHARS && !field.starts_with(b"!") => {
                out.extend_from_slice(&line[..name.len() + 1]);
                out.push(b'!');
                out.extend_from_slice(&line[name.len() + 1..]);
                locked.push(name.to_string());
            }
            _ => out.extend_from_slice(line),
        }
    }
    (out, locked)
}

/// Write an account file atomically: the old or the new file, never a torn one.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    Ok(write_atomic(path, bytes, &PRIVATE)?)
}

/// A random SHA-512 crypt(3) salt. A failing OS random source is an error,
/// never a weaker fallback.
pub(crate) fn root_salt() -> Result<String> {
    let mut bytes = [0_u8; SALT_CHARS];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AppError::Internal("the random source is unavailable".into()))?;
    Ok(bytes
        .iter()
        .map(|byte| char::from(CRYPT_ALPHABET[usize::from(byte & 63)]))
        .collect())
}

/// Accept exactly one SHA-512 crypt(3) line for `salt`, as `mkpasswd -m sha512
/// -S salt` prints it, so nothing else can reach `/etc/shadow`.
pub(crate) fn parse_root_hash(output: &[u8], salt: &str) -> Result<String> {
    let invalid = || AppError::Internal("the root password hash is malformed".into());
    let line = std::str::from_utf8(output)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
        .ok_or_else(invalid)?;
    let digest = line
        .strip_prefix("$6$")
        .and_then(|rest| rest.strip_prefix(salt))
        .and_then(|rest| rest.strip_prefix('$'))
        .ok_or_else(invalid)?;
    if salt.len() != SALT_CHARS
        || !salt.bytes().all(is_crypt_char)
        || digest.len() != SHA512_CRYPT_CHARS
        || !digest.bytes().all(is_crypt_char)
    {
        return Err(invalid());
    }
    Ok(line.to_owned())
}

fn is_crypt_char(byte: u8) -> bool {
    CRYPT_ALPHABET.contains(&byte)
}

/// Put `hash` into root's entry and stamp the change day, as `passwd` does. An
/// unset clock keeps the previous day: a 0 would force a password change.
fn with_root_hash(shadow: &[u8], hash: &str, day: Option<u64>) -> Result<Zeroizing<Vec<u8>>> {
    if hash.is_empty() || !hash.bytes().all(|byte| byte == b'$' || is_crypt_char(byte)) {
        return Err(AppError::Internal(
            "the root password hash is malformed".into(),
        ));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(shadow.len() + hash.len()));
    let mut roots = 0;
    for line in shadow.split_inclusive(|byte| *byte == b'\n') {
        let (entry, end) = match line.strip_suffix(b"\n") {
            Some(entry) => (entry, &b"\n"[..]),
            None => (line, &b""[..]),
        };
        if !entry.starts_with(b"root:") {
            out.extend_from_slice(line);
            continue;
        }
        roots += 1;
        let fields: Vec<&[u8]> = entry.split(|byte| *byte == b':').collect();
        if fields.len() < 3 {
            return Err(AppError::Internal(
                "the root shadow entry is malformed".into(),
            ));
        }
        out.extend_from_slice(b"root:");
        out.extend_from_slice(hash.as_bytes());
        out.push(b':');
        match day {
            Some(day) => out.extend_from_slice(day.to_string().as_bytes()),
            None => out.extend_from_slice(fields[2]),
        }
        for field in &fields[3..] {
            out.push(b':');
            out.extend_from_slice(field);
        }
        out.extend_from_slice(end);
    }
    if roots != 1 {
        return Err(AppError::Internal(
            "expected exactly one root shadow entry".into(),
        ));
    }
    Ok(out)
}

fn today() -> Option<u64> {
    let day = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() / 86_400;
    (day >= FIRST_PLAUSIBLE_DAY).then_some(day)
}

/// Undo a change whose journal still exists, then close the journal. If that
/// fails, the journal stays and the next start restores the same files.
fn roll_back(files: &CredentialFiles, journal: &Journal) -> Result<()> {
    restore(files, journal)
        .and_then(|()| remove_durably(&files.journal()))
        .map_err(|_| AppError::Internal(RESTORE_AT_START.into()))
}

fn restore(files: &CredentialFiles, journal: &Journal) -> io::Result<()> {
    write_atomic(
        &files.shadow,
        &journal.shadow.bytes,
        &journal.shadow.owner(),
    )?;
    match &journal.account {
        Some(account) => write_atomic(&files.account, &account.bytes, &account.owner()),
        None => remove_durably(&files.account),
    }
}

impl Store {
    fn owner(&self) -> Owner {
        Owner {
            mode: self.mode,
            ids: Some((self.uid, self.gid)),
        }
    }
}

impl Journal {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let stored = self.shadow.bytes.len() + self.account.as_ref().map_or(0, |a| a.bytes.len());
        let mut out = Zeroizing::new(Vec::with_capacity(
            MAGIC.len() + 2 * 16 + 1 + stored + DIGEST_BYTES,
        ));
        out.extend_from_slice(MAGIC);
        put_store(&mut out, &self.shadow);
        match &self.account {
            Some(account) => {
                out.push(1);
                put_store(&mut out, account);
            }
            None => out.push(0),
        }
        let digest = Sha256::digest(&out[..]);
        out.extend_from_slice(&digest);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let invalid = || {
            AppError::Internal(
                "the credential journal is unreadable; the change stays pending".into(),
            )
        };
        let body_len = bytes.len().checked_sub(DIGEST_BYTES).ok_or_else(invalid)?;
        let (body, digest) = bytes.split_at(body_len);
        if Sha256::digest(body)[..] != digest[..] {
            return Err(invalid());
        }
        let mut reader = Reader(body);
        if reader.take(MAGIC.len()) != Some(&MAGIC[..]) {
            return Err(invalid());
        }
        let shadow = reader.store().ok_or_else(invalid)?;
        let account = match reader.take(1) {
            Some([0]) => None,
            Some([1]) => Some(reader.store().ok_or_else(invalid)?),
            _ => return Err(invalid()),
        };
        if !reader.0.is_empty() {
            return Err(invalid());
        }
        Ok(Self { shadow, account })
    }
}

fn put_store(out: &mut Vec<u8>, store: &Store) {
    let len = u32::try_from(store.bytes.len()).unwrap_or(u32::MAX);
    for value in [store.mode, store.uid, store.gid, len] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&store.bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.0.len() < count {
            return None;
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    fn store(&mut self) -> Option<Store> {
        let (mode, uid, gid) = (self.u32()?, self.u32()?, self.u32()?);
        let len = usize::try_from(self.u32()?).ok()?;
        if len > MAX_STORE_BYTES || mode > 0o7777 {
            return None;
        }
        let bytes = Zeroizing::new(self.take(len)?.to_vec());
        Some(Store {
            bytes,
            mode,
            uid,
            gid,
        })
    }
}

fn read_store(path: &Path) -> Result<Option<Store>> {
    read_bounded(path, MAX_STORE_BYTES)
}

/// Read a regular file without following a final symlink, within `limit`.
fn read_bounded(path: &Path, limit: usize) -> Result<Option<Store>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    let limit_bytes = u64::try_from(limit).unwrap_or(u64::MAX);
    if !metadata.is_file() || metadata.len() > limit_bytes {
        return Err(AppError::Internal(
            "a credential store is not a bounded regular file".into(),
        ));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).unwrap_or(limit),
    ));
    file.take(limit_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(AppError::Internal(
            "a credential store is not a bounded regular file".into(),
        ));
    }
    Ok(Some(Store {
        bytes,
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
    }))
}

fn present(path: &Path) -> io::Result<bool> {
    match path.symlink_metadata() {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Replace `target` with `bytes` through a fixed scratch name: fsync the data,
/// rename, then fsync the directory.
fn write_atomic(target: &Path, bytes: &[u8], owner: &Owner) -> io::Result<()> {
    let temp = scratch(target);
    remove_present(&temp)?;
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temp)?;
        if let Some((uid, gid)) = owner.ids {
            std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
        }
        file.set_permissions(Permissions::from_mode(owner.mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, target)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written?;
    sync_parent(target)
}

fn remove_present(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn remove_durably(path: &Path) -> io::Result<()> {
    if remove_present(path)? {
        sync_parent(path)?;
    }
    Ok(())
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()
}

fn beside(path: &Path, extension: &str) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!("{name}.{extension}"))
}

fn scratch(path: &Path) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(".{name}.{SCRATCH}"))
}

#[cfg(test)]
#[path = "credential_txn_tests.rs"]
mod tests;
