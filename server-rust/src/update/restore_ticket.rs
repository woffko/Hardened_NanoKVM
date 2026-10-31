//! Protected one-shot boot state. No p3 marker/record is an authorization input.

use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, ResolveFlags, flock, mkdirat, openat2, renameat,
    unlinkat,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
};
use zeroize::Zeroizing;

use super::super::restore_fs;
use super::{CapsuleError, RestoreSecret, VerifiedPayload, open_capsule, validate_context};

const MAGIC: &[u8; 8] = b"NKTKT001";
const RECORD_BYTES: usize = 512;
const HASH_OFFSET: usize = 480;
const DIRECTORY: &str = ".nanokvm-restore";
const STATE: &str = "state";
const NEXT: &str = ".state.next";
const MAX_MOUNT_BYTES: u64 = 256 * 1024;
const DEVICE_UID: &str = "/sys/class/cvi-base/base_uid";
const DEVICE_DOMAIN: &[u8] = b"nanokvm-restore-device-v1\0";
const MAX_DEVICE_UID_BYTES: u64 = 256;

#[derive(Debug, thiserror::Error)]
pub enum TicketError {
    #[error("boot restore state is invalid or corrupt")]
    Invalid,
    #[error("boot restore state is not on the protected expected partition")]
    UnsafeStore,
    #[error("another boot restore operation owns the store")]
    Busy,
    #[error("restore ticket does not match this boot, device or image")]
    WrongBoot,
    #[error("restore transaction was already committed")]
    Replay,
    #[error("this device has no readable unique ID to bind a restore to")]
    Device,
    #[error("boot restore publication was interrupted; reopen and inspect durable state")]
    Ambiguous,
    #[error("boot restore I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Capsule(#[from] CapsuleError),
}
type Result<T> = std::result::Result<T, TicketError>;

/// The device binding of a ticket: SHA-256 over a fixed domain and the exact
/// SoC unique-ID attribute that S95 also derives `/device_key` from. Capture
/// and the early restore both read it. A kernel that prints the attribute
/// differently makes the restore refuse; it never guesses.
pub fn device_id() -> Result<[u8; 32]> {
    device_id_from(Path::new(DEVICE_UID))
}

fn device_id_from(path: &Path) -> Result<[u8; 32]> {
    let mut uid = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_DEVICE_UID_BYTES + 1).read_to_end(&mut uid))
        .map_err(|_| TicketError::Device)?;
    if uid.len() as u64 > MAX_DEVICE_UID_BYTES
        || uid.contains(&0)
        || uid.iter().all(u8::is_ascii_whitespace)
    {
        return Err(TicketError::Device);
    }
    let mut hash = Sha256::new();
    hash.update(DEVICE_DOMAIN);
    hash.update(&uid);
    Ok(hash.finalize().into())
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BootId([u8; 16]);
impl BootId {
    pub fn parse(value: &str) -> Result<Self> {
        let bytes = value.as_bytes();
        if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|i| bytes[*i] != b'-') {
            return Err(TicketError::Invalid);
        }
        let mut result = [0; 16];
        let mut digits = 0;
        for (index, byte) in bytes.iter().enumerate() {
            if [8, 13, 18, 23].contains(&index) {
                continue;
            }
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(TicketError::Invalid),
            };
            result[digits / 2] = result[digits / 2] * 16 + digit;
            digits += 1;
        }
        if result == [0; 16] {
            return Err(TicketError::Invalid);
        }
        Ok(Self(result))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Prepared = 1,
    Applying = 2,
    Restored = 3,
    Committed = 4,
    /// Key-free terminal record for an attempt that never started the writer.
    Abandoned = 5,
}

/// Values must come from trusted live identity and exact verified signed image
/// metadata. This carrier does not perform signature/payload verification.
pub struct Binding {
    pub source_boot: BootId,
    pub device_id: [u8; 32],
    pub capsule_sha256: [u8; 32],
    pub boot_image_sha256: [u8; 32],
    pub rootfs_image_sha256: [u8; 32],
    pub target_app_version: String,
    pub target: String,
}
pub struct BootObservation<'a> {
    pub boot_id: BootId,
    pub device_id: [u8; 32],
    pub system_version: &'a str,
    pub app_version: &'a str,
    pub target: &'a str,
}

// No Debug/Clone/serde. Committed state retains only a non-secret receipt.
pub struct RestoreTicket {
    transaction_id: [u8; 16],
    target_version: String,
    plaintext_len: u64,
    secret: Option<RestoreSecret>,
    binding: Binding,
    phase: Phase,
    last_boot: Option<BootId>,
}
impl RestoreTicket {
    pub fn prepared(secret: RestoreSecret, binding: Binding) -> Result<Self> {
        secret.validate()?;
        let ticket = Self {
            transaction_id: secret.transaction_id,
            target_version: secret.target_version.clone(),
            plaintext_len: secret.plaintext_len,
            secret: Some(secret),
            binding,
            phase: Phase::Prepared,
            last_boot: None,
        };
        ticket.validate()?;
        Ok(ticket)
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn transaction_id(&self) -> [u8; 16] {
        self.transaction_id
    }
    /// The signed system version the restore belongs to.
    pub fn target_version(&self) -> &str {
        &self.target_version
    }
    /// BOOT and ROOTFS image digests bound at capture.
    pub fn image_digests(&self) -> [[u8; 32]; 2] {
        [
            self.binding.boot_image_sha256,
            self.binding.rootfs_image_sha256,
        ]
    }

    /// No plaintext escapes until full AEAD *and* exact encrypted-file hash
    /// validation. Ticket publication/replay state is checked by Store methods.
    fn decrypt<R: Read>(
        &self,
        observed: &BootObservation<'_>,
        input: &mut R,
        staging: &Path,
    ) -> Result<VerifiedPayload> {
        if self.phase == Phase::Committed {
            return Err(TicketError::Replay);
        }
        self.matches_boot(observed)?;
        let secret = self.secret.as_ref().ok_or(TicketError::Invalid)?;
        let mut source = HashingReader {
            input,
            hash: Sha256::new(),
        };
        let payload = open_capsule(secret, &mut source, staging)?;
        if source.hash.finalize().as_slice() != self.binding.capsule_sha256 {
            return Err(TicketError::Invalid);
        }
        Ok(payload)
    }

    /// Whether this ticket was bound to the observed system and device. Unlike
    /// `matches_boot` this holds on every later boot and after an app update.
    pub fn belongs_to(&self, observed: &BootObservation<'_>) -> Result<()> {
        if observed.device_id != self.binding.device_id
            || observed.system_version != self.target_version
            || observed.target != self.binding.target
        {
            return Err(TicketError::WrongBoot);
        }
        Ok(())
    }

    fn matches_boot(&self, observed: &BootObservation<'_>) -> Result<()> {
        if observed.boot_id == self.binding.source_boot
            || observed.device_id != self.binding.device_id
            || observed.system_version != self.target_version
            || observed.app_version != self.binding.target_app_version
            || observed.target != self.binding.target
        {
            return Err(TicketError::WrongBoot);
        }
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        validate_context(&self.target_version, self.plaintext_len)?;
        if self.transaction_id == [0; 16]
            || self.binding.source_boot.0 == [0; 16]
            || [
                self.binding.device_id,
                self.binding.capsule_sha256,
                self.binding.boot_image_sha256,
                self.binding.rootfs_image_sha256,
            ]
            .contains(&[0; 32])
            || !identifier(&self.binding.target_app_version)
            || !identifier(&self.binding.target)
            || (matches!(self.phase, Phase::Prepared | Phase::Abandoned))
                != self.last_boot.is_none()
            || self.last_boot == Some(self.binding.source_boot)
            || matches!(self.phase, Phase::Committed | Phase::Abandoned) != self.secret.is_none()
        {
            return Err(TicketError::Invalid);
        }
        if let Some(secret) = &self.secret {
            secret.validate()?;
            if secret.transaction_id != self.transaction_id
                || secret.target_version != self.target_version
                || secret.plaintext_len != self.plaintext_len
            {
                return Err(TicketError::Invalid);
            }
        }
        Ok(())
    }
}

struct HashingReader<'a, R> {
    input: &'a mut R,
    hash: Sha256,
}
impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.input.read(out)?;
        self.hash.update(&out[..count]);
        Ok(count)
    }
}

/// Holds a kernel exclusive lock on the pinned private directory. Dropping the
/// store releases it; no HTTP future may own this instead of the restore job.
pub struct Store {
    directory: File,
    uid: u32,
    device: u64,
    poisoned: bool,
    #[cfg(test)]
    fail_at: Option<PublishStep>,
    #[cfg(test)]
    pause_at: Option<PublishStep>,
}
impl Drop for Store {
    fn drop(&mut self) {
        // flock belongs to the open file description, not this fd. A sibling
        // pre-exec child can momentarily inherit it despite CLOEXEC. End the
        // ownership lease explicitly; closing an incidental alias must neither
        // extend this lease nor affect a successor's separate description.
        // Store is deliberately non-Clone and never lends its lock descriptor.
        let _ = flock(&self.directory, FlockOperation::Unlock);
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum PublishStep {
    BeforeCreate,
    AfterCreate,
    AfterWrite,
    AfterFileSync,
    AfterRename,
    AfterDirectorySync,
}
impl Store {
    pub fn open_boot() -> Result<Self> {
        Self::open_mounted("/boot", "/dev/mmcblk0p1")
    }

    /// The raw writer publishes the ticket on the newly written boot partition
    /// mounted at its own path: `/boot` lives on the root filesystem it has
    /// just overwritten. The same root, device and mount checks apply.
    pub fn open_mounted(mountpoint: &str, source: &str) -> Result<Self> {
        if nix::unistd::geteuid().as_raw() != 0 {
            return Err(TicketError::UnsafeStore);
        }
        let device = fs::symlink_metadata(source)?;
        if !device.file_type().is_block_device() {
            return Err(TicketError::UnsafeStore);
        }
        let boot = restore_fs::open_root(Path::new(mountpoint), false)?;
        let mounts = bounded_text("/proc/mounts")?;
        let mountinfo = bounded_text("/proc/self/mountinfo")?;
        if !crate::system::media::has_expected_mount(&mounts, mountpoint, source, "vfat", true)
            || !mount_is_whole_device(&mountinfo, mountpoint, source, device.rdev())
        {
            return Err(TicketError::UnsafeStore);
        }
        Self::from_boot(boot, 0, device.rdev())
    }

    /// A store in a private test directory, owned by the test user.
    #[cfg(test)]
    pub(crate) fn open_fixture(root: &Path) -> Result<Self> {
        let boot = restore_fs::open_root(root, false)?;
        let device = boot.metadata()?.dev();
        Self::from_boot(boot, nix::unistd::geteuid().as_raw(), device)
    }

    fn from_boot(boot: File, uid: u32, device: u64) -> Result<Self> {
        private_directory(&boot, uid, device)?;
        match mkdirat(&boot, DIRECTORY, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => boot.sync_all()?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(err) => return Err(io::Error::from(err).into()),
        }
        let directory =
            restore_fs::open_beneath(&boot, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
        private_directory(&directory, uid, device)?;
        flock(&directory, FlockOperation::NonBlockingLockExclusive).map_err(|err| {
            if err == rustix::io::Errno::WOULDBLOCK {
                TicketError::Busy
            } else {
                TicketError::Io(err.into())
            }
        })?;
        let mut store = Self {
            directory,
            uid,
            device,
            poisoned: false,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            pause_at: None,
        };
        // A canonical valid record remains authoritative after an interrupted
        // replacement. An initial temp with no canonical record is ambiguous.
        store.load()?;
        Ok(store)
    }

    pub fn load(&mut self) -> Result<Option<RestoreTicket>> {
        self.ready()?;
        let current = self.read_state()?;
        if self.open_regular(NEXT)?.is_some() {
            if current.is_none() {
                return Err(TicketError::Ambiguous);
            }
            if unlinkat(&self.directory, NEXT, AtFlags::empty())
                .map_err(io::Error::from)
                .and_then(|_| self.directory.sync_all())
                .is_err()
            {
                self.poisoned = true;
                return Err(TicketError::Ambiguous);
            }
        }
        Ok(current)
    }

    pub fn publish_prepared(&mut self, ticket: &RestoreTicket) -> Result<()> {
        self.ready()?;
        ticket.validate()?;
        if ticket.phase != Phase::Prepared {
            return Err(TicketError::Invalid);
        }
        if let Some(current) = self.load()? {
            if current.transaction_id == ticket.transaction_id {
                return Err(TicketError::Replay);
            }
            if !matches!(current.phase, Phase::Committed | Phase::Abandoned) {
                return Err(TicketError::Busy);
            }
        }
        self.publish(&*encode(ticket, ticket.phase, ticket.last_boot)?)
    }

    /// Retire a prepared attempt that never reached the writer. The record
    /// keeps the exact transaction and binding as a key-free terminal receipt;
    /// a new prepared ticket may replace it.
    pub fn abandon_prepared(&mut self, ticket: &RestoreTicket) -> Result<()> {
        self.ready()?;
        ticket.validate()?;
        if ticket.phase != Phase::Prepared {
            return Err(TicketError::Invalid);
        }
        self.publish(&*encode(ticket, Phase::Abandoned, None)?)
    }

    pub fn decrypt<R: Read>(
        &mut self,
        ticket: &RestoreTicket,
        observed: &BootObservation<'_>,
        input: &mut R,
        staging: &Path,
    ) -> Result<VerifiedPayload> {
        self.check_current(ticket)?;
        ticket.decrypt(observed, input, staging)
    }

    pub fn begin_apply(
        &mut self,
        ticket: &mut RestoreTicket,
        observed: &BootObservation<'_>,
    ) -> Result<()> {
        self.check_current(ticket)?;
        ticket.matches_boot(observed)?;
        if !matches!(ticket.phase, Phase::Prepared | Phase::Applying) {
            return Err(TicketError::Invalid);
        }
        self.transition(ticket, Phase::Applying, observed.boot_id)
    }
    pub fn mark_restored(
        &mut self,
        ticket: &mut RestoreTicket,
        observed: &BootObservation<'_>,
    ) -> Result<()> {
        self.check_current(ticket)?;
        ticket.matches_boot(observed)?;
        if ticket.phase != Phase::Applying || ticket.last_boot != Some(observed.boot_id) {
            return Err(TicketError::Invalid);
        }
        // Caller must already have durably applied and verified all state.
        self.transition(ticket, Phase::Restored, observed.boot_id)
    }
    pub fn commit(
        &mut self,
        ticket: &mut RestoreTicket,
        observed: &BootObservation<'_>,
    ) -> Result<()> {
        self.check_current(ticket)?;
        ticket.matches_boot(observed)?;
        if ticket.phase != Phase::Restored {
            return Err(TicketError::Invalid);
        }
        // Caller must supply real post-restore runtime/boot health, not a marker.
        self.transition(ticket, Phase::Committed, observed.boot_id)
    }

    fn transition(&mut self, ticket: &mut RestoreTicket, phase: Phase, boot: BootId) -> Result<()> {
        self.publish(&*encode(ticket, phase, Some(boot))?)?;
        ticket.phase = phase;
        ticket.last_boot = Some(boot);
        if matches!(phase, Phase::Committed | Phase::Abandoned) {
            ticket.secret = None;
        }
        Ok(())
    }
    fn check_current(&mut self, ticket: &RestoreTicket) -> Result<()> {
        self.ready()?;
        ticket.validate()?;
        let current = self.load()?.ok_or(TicketError::Invalid)?;
        let disk = encode(&current, current.phase, current.last_boot)?;
        let expected = encode(ticket, ticket.phase, ticket.last_boot)?;
        if disk.as_slice() != expected.as_slice() {
            return Err(TicketError::Invalid);
        }
        Ok(())
    }
    fn ready(&self) -> Result<()> {
        if self.poisoned {
            Err(TicketError::Ambiguous)
        } else {
            Ok(())
        }
    }
    fn open_regular(&self, name: &str) -> Result<Option<File>> {
        let file = match restore_fs::open_beneath(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK,
        ) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != self.uid
            || metadata.dev() != self.device
            || metadata.mode() & 0o7177 != 0
        {
            return Err(TicketError::UnsafeStore);
        }
        Ok(Some(file))
    }
    fn read_state(&self) -> Result<Option<RestoreTicket>> {
        let Some(mut file) = self.open_regular(STATE)? else {
            return Ok(None);
        };
        if file.metadata()?.len() != RECORD_BYTES as u64 {
            return Err(TicketError::Invalid);
        }
        let mut bytes = Zeroizing::new([0; RECORD_BYTES]);
        file.read_exact(&mut *bytes)?;
        if file.read(&mut [0])? != 0 {
            return Err(TicketError::Invalid);
        }
        Ok(Some(decode(&bytes)?))
    }
    fn publish(&mut self, bytes: &[u8; RECORD_BYTES]) -> Result<()> {
        let result = (|| -> io::Result<()> {
            #[cfg(test)]
            self.inject(PublishStep::BeforeCreate)?;
            let mut file: File = openat2(
                &self.directory,
                NEXT,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
                ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS,
            )?
            .into();
            #[cfg(test)]
            self.inject(PublishStep::AfterCreate)?;
            let metadata = file.metadata()?;
            if metadata.uid() != self.uid
                || metadata.dev() != self.device
                || metadata.mode() & 0o7177 != 0
                || metadata.nlink() != 1
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            file.write_all(bytes)?;
            #[cfg(test)]
            self.inject(PublishStep::AfterWrite)?;
            file.sync_all()?;
            #[cfg(test)]
            self.inject(PublishStep::AfterFileSync)?;
            renameat(&self.directory, NEXT, &self.directory, STATE)?;
            #[cfg(test)]
            self.inject(PublishStep::AfterRename)?;
            self.directory.sync_all()?;
            #[cfg(test)]
            self.inject(PublishStep::AfterDirectorySync)?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
            return Err(TicketError::Ambiguous);
        }
        Ok(())
    }
    #[cfg(test)]
    fn inject(&self, step: PublishStep) -> io::Result<()> {
        if self.pause_at == Some(step) {
            // libtest may print its test-name prefix without a final newline.
            // Keep the fixture protocol marker on its own line in every mode.
            println!("\nTICKET_FIXTURE_READY");
            io::stdout().flush()?;
            // Finite safety timeout if the parent fails before killing us.
            std::thread::sleep(std::time::Duration::from_secs(20));
        }
        if self.fail_at == Some(step) {
            Err(io::Error::from_raw_os_error(nix::libc::EIO))
        } else {
            Ok(())
        }
    }
}

fn private_directory(file: &File, uid: u32, device: u64) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.dev() != device
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(TicketError::UnsafeStore);
    }
    Ok(())
}
fn bounded_text(path: &str) -> Result<String> {
    let mut value = String::new();
    File::open(path)?
        .take(MAX_MOUNT_BYTES + 1)
        .read_to_string(&mut value)?;
    if value.len() as u64 > MAX_MOUNT_BYTES {
        return Err(TicketError::UnsafeStore);
    }
    Ok(value)
}
fn mount_is_whole_device(mountinfo: &str, mountpoint: &str, source: &str, device: u64) -> bool {
    let mut matching = mountinfo
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|fields| fields.get(4) == Some(&mountpoint));
    let Some(fields) = matching.next() else {
        return false;
    };
    let Some(separator) = fields.iter().position(|part| *part == "-") else {
        return false;
    };
    fields.len() > separator + 2
        && fields[3] == "/"
        && fields[2]
            == format!(
                "{}:{}",
                rustix::fs::major(device),
                rustix::fs::minor(device)
            )
        && fields[separator + 1] == "vfat"
        && fields[separator + 2] == source
        && matching.next().is_none()
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
fn put_string(out: &mut [u8], value: &str) {
    out[0] = value.len() as u8;
    out[1..1 + value.len()].copy_from_slice(value.as_bytes());
}
fn get_string(bytes: &[u8]) -> Result<String> {
    let length = usize::from(bytes[0]);
    if length == 0 || length > 64 || bytes[1 + length..].iter().any(|b| *b != 0) {
        return Err(TicketError::Invalid);
    }
    let value = std::str::from_utf8(&bytes[1..1 + length]).map_err(|_| TicketError::Invalid)?;
    if !identifier(value) {
        return Err(TicketError::Invalid);
    }
    Ok(value.to_string())
}

fn encode(
    ticket: &RestoreTicket,
    phase: Phase,
    last_boot: Option<BootId>,
) -> Result<Zeroizing<[u8; RECORD_BYTES]>> {
    ticket.validate()?;
    let mut bytes = Zeroizing::new([0; RECORD_BYTES]);
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8] = phase as u8;
    bytes[16..32].copy_from_slice(&ticket.transaction_id);
    bytes[32..40].copy_from_slice(&ticket.plaintext_len.to_be_bytes());
    put_string(&mut bytes[40..105], &ticket.target_version);
    if !matches!(phase, Phase::Committed | Phase::Abandoned) {
        bytes[105..137].copy_from_slice(&*ticket.secret.as_ref().ok_or(TicketError::Invalid)?.key);
    }
    bytes[137..153].copy_from_slice(&ticket.binding.source_boot.0);
    if let Some(boot) = last_boot {
        bytes[153..169].copy_from_slice(&boot.0);
    }
    bytes[169..201].copy_from_slice(&ticket.binding.device_id);
    bytes[201..233].copy_from_slice(&ticket.binding.capsule_sha256);
    bytes[233..265].copy_from_slice(&ticket.binding.boot_image_sha256);
    bytes[265..297].copy_from_slice(&ticket.binding.rootfs_image_sha256);
    put_string(&mut bytes[297..362], &ticket.binding.target_app_version);
    put_string(&mut bytes[362..427], &ticket.binding.target);
    let hash = Sha256::digest(&bytes[..HASH_OFFSET]);
    bytes[HASH_OFFSET..].copy_from_slice(&hash);
    Ok(bytes)
}
fn decode(bytes: &[u8; RECORD_BYTES]) -> Result<RestoreTicket> {
    if &bytes[..8] != MAGIC
        || bytes[9..16].iter().chain(&bytes[427..480]).any(|b| *b != 0)
        || Sha256::digest(&bytes[..HASH_OFFSET]).as_slice() != &bytes[HASH_OFFSET..]
    {
        return Err(TicketError::Invalid);
    }
    let phase = match bytes[8] {
        1 => Phase::Prepared,
        2 => Phase::Applying,
        3 => Phase::Restored,
        4 => Phase::Committed,
        5 => Phase::Abandoned,
        _ => return Err(TicketError::Invalid),
    };
    let mut id = [0; 16];
    id.copy_from_slice(&bytes[16..32]);
    let mut length = [0; 8];
    length.copy_from_slice(&bytes[32..40]);
    let version = get_string(&bytes[40..105])?;
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes[105..137]);
    if matches!(phase, Phase::Committed | Phase::Abandoned) && *key != [0; 32] {
        return Err(TicketError::Invalid);
    }
    let secret = if matches!(phase, Phase::Committed | Phase::Abandoned) {
        None
    } else {
        Some(RestoreSecret {
            transaction_id: id,
            target_version: version.clone(),
            plaintext_len: u64::from_be_bytes(length),
            key,
        })
    };
    let mut source_boot = [0; 16];
    source_boot.copy_from_slice(&bytes[137..153]);
    let mut last_boot = [0; 16];
    last_boot.copy_from_slice(&bytes[153..169]);
    let mut device = [0; 32];
    device.copy_from_slice(&bytes[169..201]);
    let mut capsule = [0; 32];
    capsule.copy_from_slice(&bytes[201..233]);
    let mut boot = [0; 32];
    boot.copy_from_slice(&bytes[233..265]);
    let mut rootfs = [0; 32];
    rootfs.copy_from_slice(&bytes[265..297]);
    let ticket = RestoreTicket {
        transaction_id: id,
        target_version: version,
        plaintext_len: u64::from_be_bytes(length),
        secret,
        binding: Binding {
            source_boot: BootId(source_boot),
            device_id: device,
            capsule_sha256: capsule,
            boot_image_sha256: boot,
            rootfs_image_sha256: rootfs,
            target_app_version: get_string(&bytes[297..362])?,
            target: get_string(&bytes[362..427])?,
        },
        phase,
        last_boot: if last_boot == [0; 16] {
            None
        } else {
            Some(BootId(last_boot))
        },
    };
    ticket.validate()?;
    Ok(ticket)
}

#[cfg(test)]
#[path = "restore_ticket_tests.rs"]
mod tests;
