//! Fixed private acceptance publication, never a target mutation/recovery API.
use super::*;
use rustix::fs::{
    AtFlags, Mode, RenameFlags, ResolveFlags, fchmod, openat2, renameat_with, unlinkat,
};
use std::io::{Seek, SeekFrom, Write};

enum Member {
    Active,
    Payload,
    Source,
    Plan,
    Next,
}
impl Member {
    fn name(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Payload => "payload",
            Self::Source => "source",
            Self::Plan => "plan",
            Self::Next => ".state.next",
        }
    }
}

enum Publication {
    Accepted,
    Stop,
    Closed,
    Applying,
    Committed,
    Activating,
    Completed,
}

impl Publication {
    #[cfg(test)]
    fn label(&self) -> &'static str {
        match self {
            Self::Accepted => "state",
            Self::Stop => "stop",
            Self::Closed => "closed",
            Self::Applying => "applying",
            Self::Committed => "committed",
            Self::Activating => "activating",
            Self::Completed => "completed",
        }
    }
}

struct OwnedMember {
    file: File,
    revision: Revision,
    hash: [u8; 32],
}

impl OwnedMember {
    fn check(&mut self, directory: &File, name: &str) -> Result<()> {
        if Revision::from(&self.file.metadata()?) != self.revision
            || Revision::from(&restore_fs::open_beneath(directory, name, OFlags::PATH)?.metadata()?)
                != self.revision
        {
            return Err(invalid());
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let length = std::io::copy(
            &mut (&mut self.file).take(self.revision.bytes + 1),
            &mut hash,
        )?;
        if length != self.revision.bytes
            || hash.finalize().as_slice() != self.hash
            || Revision::from(&self.file.metadata()?) != self.revision
            || Revision::from(&restore_fs::open_beneath(directory, name, OFlags::PATH)?.metadata()?)
                != self.revision
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn private_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

pub(super) struct Source {
    directory: Directory,
    bytes: Zeroizing<Vec<u8>>,
}

impl Drop for Source {
    fn drop(&mut self) {
        // End this lease explicitly: an inherited or duplicated description
        // must not keep the Home lock after its owning job is gone.
        let _ = flock(&self.directory.file, FlockOperation::Unlock);
    }
}

impl Source {
    /// Convert this job's Home lease to exclusive on the SAME description. A
    /// refused non-blocking conversion can drop the shared lease, so callers
    /// revalidate only after this returns. Bounded for transient readers.
    fn lock_exclusive(&self) -> Result<()> {
        for _ in 0..150 {
            match flock(
                &self.directory.file,
                FlockOperation::NonBlockingLockExclusive,
            ) {
                Ok(()) => return Ok(()),
                Err(rustix::io::Errno::WOULDBLOCK) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
        Err(AppError::Conflict("picoclaw configuration is busy".into()))
    }

    fn capture(facts: &Facts) -> Result<Self> {
        let mut directory = Directory::open(Path::new("/"), false)?;
        let mut present = true;
        let mut depth = 0u32;
        for component in facts.home.components() {
            let std::path::Component::Normal(name) = component else {
                continue;
            };
            let name = name.to_str().ok_or_else(invalid)?;
            match restore_fs::open_beneath(
                &directory.file,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY,
            ) {
                Ok(file) => {
                    directory.file = file;
                    directory.check()?;
                    depth += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    present = false;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        directory.lock(true)?;
        let before = directory.file.metadata()?;
        let pair = if present {
            super::super::super::pair::read_source(&directory)?
        } else {
            [None, None]
        };
        if Revision::from(&directory.file.metadata()?) != Revision::from(&before) {
            return Err(invalid());
        }
        let home = facts.home.as_os_str().as_encoded_bytes();
        let config_len = pair[0].as_ref().map_or(0, |bytes| bytes.len());
        let security_len = pair[1].as_ref().map_or(0, |bytes| bytes.len());
        let size = 128usize
            .checked_add(home.len())
            .and_then(|n| n.checked_add(config_len))
            .and_then(|n| n.checked_add(security_len))
            .ok_or_else(invalid)?;
        if home.len() > 4095
            || config_len > super::super::super::MAX_FILE_BYTES
            || security_len > super::super::super::MAX_FILE_BYTES
        {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(size));
        bytes.extend_from_slice(&[0; 128]);
        // Private source v2 additionally binds the SAME owned Pico launch.
        // A v1 source is not silently reinterpreted as carrying this proof.
        bytes[..8].copy_from_slice(b"NKPSRC02");
        bytes[8] = u8::from(present);
        bytes[9] = u8::from(pair[0].is_some());
        bytes[10] = u8::from(pair[1].is_some());
        bytes[11] = u8::from(facts.running_generation.is_some());
        if let Some(generation) = facts.running_generation {
            bytes[96..128].copy_from_slice(generation.private_bytes());
        }
        bytes[12..16].copy_from_slice(&depth.to_le_bytes());
        bytes[16..24].copy_from_slice(&before.dev().to_le_bytes());
        bytes[24..32].copy_from_slice(&before.ino().to_le_bytes());
        bytes[32..36].copy_from_slice(&before.uid().to_le_bytes());
        bytes[36..40].copy_from_slice(&before.mode().to_le_bytes());
        for (offset, length) in [(40, home.len()), (44, config_len), (48, security_len)] {
            bytes[offset..offset + 4].copy_from_slice(&(length as u32).to_le_bytes());
        }
        bytes[64..72].copy_from_slice(&before.mtime().to_le_bytes());
        bytes[72..80].copy_from_slice(&before.mtime_nsec().to_le_bytes());
        bytes[80..88].copy_from_slice(&before.ctime().to_le_bytes());
        bytes[88..96].copy_from_slice(&before.ctime_nsec().to_le_bytes());
        bytes.extend_from_slice(home);
        for member in pair.into_iter().flatten() {
            bytes.extend_from_slice(member.as_slice());
        }
        Ok(Self { directory, bytes })
    }
}

#[cfg(test)]
pub(super) fn source_fixture(directory: Directory) -> Source {
    Source {
        directory,
        bytes: Zeroizing::new(Vec::new()),
    }
}

#[cfg(test)]
impl Source {
    pub(super) fn alias_for_test(&self) -> File {
        self.directory.file.try_clone().unwrap()
    }
}

/// Typed view of the private source captured at acceptance. It borrows the
/// credential-bearing bytes; never Debug/log it.
pub(super) struct SourceView<'a> {
    pub(super) home: &'a [u8],
    pub(super) home_present: bool,
    pub(super) config: Option<&'a [u8]>,
    pub(super) security: Option<&'a [u8]>,
}

pub(super) fn decode_source(bytes: &[u8]) -> Result<SourceView<'_>> {
    if bytes.len() < 128 || &bytes[..8] != b"NKPSRC02" {
        return Err(invalid());
    }
    let flag = |index: usize| match bytes[index] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid()),
    };
    let length = |offset: usize| -> Result<usize> {
        Ok(u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize)
    };
    let (present, config_present, security_present, generation) =
        (flag(8)?, flag(9)?, flag(10)?, flag(11)?);
    let (home, config, security) = (length(40)?, length(44)?, length(48)?);
    if bytes[52..64].iter().any(|byte| *byte != 0)
        || (!generation && bytes[96..128].iter().any(|byte| *byte != 0))
        || (!present && (config_present || security_present))
        || (!config_present && config != 0)
        || (!security_present && security != 0)
        || !(1..=4095).contains(&home)
    {
        return Err(invalid());
    }
    let total = 128usize
        .checked_add(home)
        .and_then(|n| n.checked_add(config))
        .and_then(|n| n.checked_add(security))
        .ok_or_else(invalid)?;
    if total != bytes.len() || bytes[128] != b'/' || bytes[128..128 + home].contains(&0) {
        return Err(invalid());
    }
    let config_start = 128 + home;
    let security_start = config_start + config;
    Ok(SourceView {
        home: &bytes[128..128 + home],
        home_present: present,
        config: config_present.then(|| &bytes[config_start..security_start]),
        security: security_present.then(|| &bytes[security_start..]),
    })
}

const PLAN_MAGIC: &[u8; 8] = b"NKPPLN01";
const PLAN_HEADER: usize = 96;

/// Credential-bearing desired pair and internal value, chosen once before any
/// stop or publication so a retry or crash replays the same change. Never
/// Debug/log it; the durable copy is a protected 0600 member.
pub(super) struct Plan {
    pub(super) config: Zeroizing<Vec<u8>>,
    pub(super) security: Zeroizing<Vec<u8>>,
    pub(super) internal: Zeroizing<String>,
    pub(super) internal_new: bool,
}

pub(super) fn encode_plan(record: &Record, plan: &Plan) -> Result<Zeroizing<Vec<u8>>> {
    let internal = plan.internal.as_bytes();
    if plan.config.len() > super::super::super::MAX_FILE_BYTES
        || plan.security.len() > super::super::super::MAX_FILE_BYTES
        || !crate::update::picoclaw_token::valid_token(plan.internal.as_str())
    {
        return Err(invalid());
    }
    let size = PLAN_HEADER + plan.config.len() + plan.security.len() + internal.len() + 32;
    let mut bytes = Zeroizing::new(vec![0; PLAN_HEADER]);
    bytes.reserve(size - PLAN_HEADER);
    bytes[..8].copy_from_slice(PLAN_MAGIC);
    bytes[8..16].copy_from_slice(&record.sequence.to_le_bytes());
    bytes[16..32].copy_from_slice(&record.nonce);
    bytes[32..64].copy_from_slice(&record.source);
    bytes[64] = u8::from(plan.internal_new);
    for (offset, length) in [
        (68, plan.config.len()),
        (72, plan.security.len()),
        (76, internal.len()),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&(length as u32).to_le_bytes());
    }
    bytes.extend_from_slice(&plan.config);
    bytes.extend_from_slice(&plan.security);
    bytes.extend_from_slice(internal);
    let hash = private_digest(b"NanoKVM Pico startup plan v1\0", &bytes);
    bytes.extend_from_slice(&hash);
    Ok(bytes)
}

pub(super) fn decode_plan(record: &Record, bytes: &[u8]) -> Result<Plan> {
    if bytes.len() < PLAN_HEADER + 32 || &bytes[..8] != PLAN_MAGIC {
        return Err(invalid());
    }
    let (body, hash) = bytes.split_at(bytes.len() - 32);
    if private_digest(b"NanoKVM Pico startup plan v1\0", body) != hash
        || bytes[8..16] != record.sequence.to_le_bytes()
        || bytes[16..32] != record.nonce
        || bytes[32..64] != record.source
        || bytes[64] > 1
        || bytes[65..68].iter().any(|byte| *byte != 0)
        || bytes[80..PLAN_HEADER].iter().any(|byte| *byte != 0)
    {
        return Err(invalid());
    }
    let length = |offset: usize| -> Result<usize> {
        Ok(u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize)
    };
    let (config, security, internal) = (length(68)?, length(72)?, length(76)?);
    if PLAN_HEADER
        .checked_add(config)
        .and_then(|n| n.checked_add(security))
        .and_then(|n| n.checked_add(internal))
        != Some(body.len())
    {
        return Err(invalid());
    }
    let config_end = PLAN_HEADER + config;
    let security_end = config_end + security;
    let internal = std::str::from_utf8(&body[security_end..]).map_err(|_| invalid())?;
    if !crate::update::picoclaw_token::valid_token(internal) {
        return Err(invalid());
    }
    Ok(Plan {
        config: Zeroizing::new(body[PLAN_HEADER..config_end].to_vec()),
        security: Zeroizing::new(body[config_end..security_end].to_vec()),
        internal: Zeroizing::new(internal.to_string()),
        internal_new: bytes[64] == 1,
    })
}

const REMOVAL_MAGIC: &[u8; 8] = b"NKPRMV01";
const REMOVAL_BYTES: usize = 224;

/// The managed files a Remove job deletes besides the accepted pair, bound to
/// their exact identities when the job was settled. Absent means nothing to do.
pub(super) struct Removal {
    pub(super) binary: Option<crate::update::picoclaw_runtime::Asset>,
    pub(super) token: Option<crate::update::picoclaw_runtime::Asset>,
}

fn encode_removal(record: &Record, removal: &Removal) -> [u8; REMOVAL_BYTES] {
    use crate::update::picoclaw_runtime::Asset;
    let mut bytes = [0; REMOVAL_BYTES];
    bytes[..8].copy_from_slice(REMOVAL_MAGIC);
    bytes[8..16].copy_from_slice(&record.sequence.to_le_bytes());
    bytes[16..32].copy_from_slice(&record.nonce);
    bytes[32..64].copy_from_slice(&record.source);
    for (offset, asset) in [(64, removal.binary), (128, removal.token)] {
        if let Some(asset) = asset {
            bytes[offset] = 1;
            bytes[offset + 8..offset + 8 + Asset::BYTES].copy_from_slice(&asset.encode());
        }
    }
    let hash = private_digest(b"NanoKVM Pico removal plan v1\0", &bytes[..192]);
    bytes[192..].copy_from_slice(&hash);
    bytes
}

pub(super) fn decode_removal(record: &Record, bytes: &[u8]) -> Result<Removal> {
    use crate::update::picoclaw_runtime::Asset;
    if bytes.len() != REMOVAL_BYTES
        || &bytes[..8] != REMOVAL_MAGIC
        || private_digest(b"NanoKVM Pico removal plan v1\0", &bytes[..192]) != bytes[192..]
        || bytes[8..16] != record.sequence.to_le_bytes()
        || bytes[16..32] != record.nonce
        || bytes[32..64] != record.source
    {
        return Err(invalid());
    }
    let asset = |offset: usize| -> Result<Option<Asset>> {
        if bytes[offset + 1..offset + 8].iter().any(|byte| *byte != 0) {
            return Err(invalid());
        }
        let identity: &[u8; Asset::BYTES] = bytes[offset + 8..offset + 8 + Asset::BYTES]
            .try_into()
            .map_err(|_| invalid())?;
        match bytes[offset] {
            0 if identity.iter().all(|byte| *byte == 0) => Ok(None),
            1 => Ok(Some(Asset::decode(identity))),
            _ => Err(invalid()),
        }
    };
    Ok(Removal {
        binary: asset(64)?,
        token: asset(128)?,
    })
}

const PROFILE_MAGIC: &[u8; 8] = b"NKPPRF01";
const PROFILE_HEADER: usize = 112;

/// The workspace AGENT.md a Profile job replaces: the digest of the document
/// it found (or its absence) and the exact shipped bytes it installs.
pub(super) struct ProfilePlan {
    pub(super) before: Option<[u8; 32]>,
    pub(super) desired: Vec<u8>,
}

fn profile_digest(bytes: &[u8]) -> [u8; 32] {
    private_digest(b"NanoKVM Pico profile document v1\0", bytes)
}

fn encode_profile(record: &Record, plan: &ProfilePlan) -> Result<Vec<u8>> {
    if plan.desired.len() > crate::update::picoclaw_profile::MAX_PROFILE_BYTES {
        return Err(invalid());
    }
    let mut bytes = vec![0; PROFILE_HEADER];
    bytes[..8].copy_from_slice(PROFILE_MAGIC);
    bytes[8..16].copy_from_slice(&record.sequence.to_le_bytes());
    bytes[16..32].copy_from_slice(&record.nonce);
    bytes[32..64].copy_from_slice(&record.source);
    if let Some(before) = plan.before {
        bytes[64] = 1;
        bytes[72..104].copy_from_slice(&before);
    }
    bytes[104..108].copy_from_slice(&(plan.desired.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&plan.desired);
    let hash = private_digest(b"NanoKVM Pico profile plan v1\0", &bytes);
    bytes.extend_from_slice(&hash);
    Ok(bytes)
}

pub(super) fn decode_profile(record: &Record, bytes: &[u8]) -> Result<ProfilePlan> {
    if bytes.len() < PROFILE_HEADER + 32 || &bytes[..8] != PROFILE_MAGIC {
        return Err(invalid());
    }
    let (body, hash) = bytes.split_at(bytes.len() - 32);
    let length = u32::from_le_bytes(bytes[104..108].try_into().map_err(|_| invalid())?) as usize;
    if private_digest(b"NanoKVM Pico profile plan v1\0", body) != hash
        || bytes[8..16] != record.sequence.to_le_bytes()
        || bytes[16..32] != record.nonce
        || bytes[32..64] != record.source
        || bytes[64] > 1
        || bytes[65..72].iter().any(|byte| *byte != 0)
        || (bytes[64] == 0 && bytes[72..104].iter().any(|byte| *byte != 0))
        || bytes[108..PROFILE_HEADER].iter().any(|byte| *byte != 0)
        || length > crate::update::picoclaw_profile::MAX_PROFILE_BYTES
        || PROFILE_HEADER + length != body.len()
    {
        return Err(invalid());
    }
    Ok(ProfilePlan {
        before: (bytes[64] == 1)
            .then(|| bytes[72..104].try_into().map_err(|_| invalid()))
            .transpose()?,
        desired: body[PROFILE_HEADER..].to_vec(),
    })
}

const INSTALL_MAGIC: &[u8; 8] = b"NKPINS01";
const INSTALL_BYTES: usize = 280;

/// The executable an Install job puts in place: the staged file's exact
/// identity and SHA-512, and the prior installed file (or its absence).
pub(super) struct InstallPlan {
    pub(super) staged: crate::update::picoclaw_runtime::Asset,
    pub(super) digest: [u8; 64],
    pub(super) prior: Option<crate::update::picoclaw_runtime::Asset>,
}

fn encode_install(record: &Record, plan: &InstallPlan) -> [u8; INSTALL_BYTES] {
    use crate::update::picoclaw_runtime::Asset;
    let mut bytes = [0; INSTALL_BYTES];
    bytes[..8].copy_from_slice(INSTALL_MAGIC);
    bytes[8..16].copy_from_slice(&record.sequence.to_le_bytes());
    bytes[16..32].copy_from_slice(&record.nonce);
    bytes[32..64].copy_from_slice(&record.source);
    bytes[64..64 + Asset::BYTES].copy_from_slice(&plan.staged.encode());
    bytes[120..184].copy_from_slice(&plan.digest);
    if let Some(prior) = plan.prior {
        bytes[184] = 1;
        bytes[192..192 + Asset::BYTES].copy_from_slice(&prior.encode());
    }
    let hash = private_digest(b"NanoKVM Pico install plan v1\0", &bytes[..248]);
    bytes[248..].copy_from_slice(&hash);
    bytes
}

pub(super) fn decode_install(record: &Record, bytes: &[u8]) -> Result<InstallPlan> {
    use crate::update::picoclaw_runtime::Asset;
    if bytes.len() != INSTALL_BYTES
        || &bytes[..8] != INSTALL_MAGIC
        || private_digest(b"NanoKVM Pico install plan v1\0", &bytes[..248]) != bytes[248..]
        || bytes[8..16] != record.sequence.to_le_bytes()
        || bytes[16..32] != record.nonce
        || bytes[32..64] != record.source
        || bytes[185..192].iter().any(|byte| *byte != 0)
    {
        return Err(invalid());
    }
    let asset = |offset: usize| -> Result<Asset> {
        Ok(Asset::decode(
            bytes[offset..offset + Asset::BYTES]
                .try_into()
                .map_err(|_| invalid())?,
        ))
    };
    let prior = match bytes[184] {
        0 if bytes[192..248].iter().all(|byte| *byte == 0) => None,
        1 => Some(asset(192)?),
        _ => return Err(invalid()),
    };
    Ok(InstallPlan {
        staged: asset(64)?,
        digest: bytes[120..184].try_into().map_err(|_| invalid())?,
        prior,
    })
}

// The plan member of a job, by the job's kind.
fn check_plan(record: &Record, bytes: &[u8]) -> Result<()> {
    match record.kind {
        Kind::Remove => decode_removal(record, bytes).map(|_| ()),
        Kind::Profile => decode_profile(record, bytes).map(|_| ()),
        Kind::Install => decode_install(record, bytes).map(|_| ()),
        _ => decode_plan(record, bytes).map(|_| ()),
    }
}

// Install exactly the planned executable once: installed already (done), the
// planned prior still in place (installed now from the staged file, which
// must still verify), or anything else (false: nothing written).
fn complete_install(plan: &InstallPlan) -> Result<bool> {
    let current = crate::update::picoclaw_runtime::installed()?;
    if current.is_some_and(|(_, digest)| digest == plan.digest) {
        return Ok(true);
    }
    if current.map(|(asset, _)| asset) != plan.prior
        || crate::update::picoclaw_runtime::staged()? != Some((plan.staged, plan.digest))
    {
        return Ok(false);
    }
    crate::update::picoclaw_runtime::install(plan.staged, plan.digest, plan.prior)?;
    Ok(true)
}

// The workspace an accepted source's config selects.
fn source_workspace(view: &SourceView<'_>) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;
    let config = view.config.ok_or_else(invalid)?;
    let documents = crate::update::picoclaw_startup::decode(config, view.security)?;
    crate::update::picoclaw_profile::workspace(
        &documents.config,
        Path::new(std::ffi::OsStr::from_bytes(view.home)),
    )
    .ok_or_else(invalid)
}

// Both shipped profile documents, from the fixed application directory.
fn read_shipped() -> Result<[Vec<u8>; 2]> {
    use crate::update::picoclaw_profile::{MAX_PROFILE_BYTES, SHIPPED, shipped_name};
    let directory = Directory::open(Path::new(SHIPPED), false)?;
    let read = |kvm: bool| -> Result<Vec<u8>> {
        Ok(directory
            .read_document(shipped_name(kvm), MAX_PROFILE_BYTES)?
            .ok_or_else(invalid)?
            .to_vec())
    };
    Ok([read(false)?, read(true)?])
}

// The workspace's current AGENT.md; a missing workspace holds none.
fn read_workspace_agent(workspace: &Path) -> Result<Option<Vec<u8>>> {
    use crate::update::picoclaw_profile::{AGENT, MAX_PROFILE_BYTES};
    let directory = match Directory::open(workspace, false) {
        Ok(directory) => directory,
        Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    Ok(directory
        .read_document(AGENT, MAX_PROFILE_BYTES)?
        .map(|bytes| bytes.to_vec()))
}

// Install the planned document exactly once: the workspace AGENT.md is the
// planned prior one (replaced atomically), already the desired one (done), or
// anything else (false: nothing written).
fn install_profile(workspace: &Path, plan: &ProfilePlan) -> Result<bool> {
    use crate::update::picoclaw_profile::{AGENT, MAX_PROFILE_BYTES};
    use std::io::Write as _;
    let directory = Directory::open(workspace, true)?;
    let before = directory.inspect_document(AGENT, MAX_PROFILE_BYTES)?;
    let current = directory.read_document(AGENT, MAX_PROFILE_BYTES)?;
    if current.as_deref().map(Vec::as_slice) == Some(plan.desired.as_slice()) {
        directory.file.sync_all()?;
        return Ok(true);
    }
    if current.as_deref().map(|bytes| profile_digest(bytes)) != plan.before {
        return Ok(false);
    }
    let mut staged = directory.temporary(MAX_PROFILE_BYTES)?;
    staged.file.write_all(&plan.desired)?;
    staged.file.sync_all()?;
    staged.publish_document(AGENT, before)?;
    directory.file.sync_all()?;
    if directory
        .read_document(AGENT, MAX_PROFILE_BYTES)?
        .as_deref()
        .map(Vec::as_slice)
        != Some(plan.desired.as_slice())
    {
        return Err(invalid());
    }
    Ok(true)
}

pub(super) struct Store {
    parent: File,
    directory: File,
    identity: (u64, u64),
    anchor: (bootstrap::Anchor, Revision),
    revision: Revision,
    snapshot: Snapshot,
    members: [Option<OwnedMember>; 4],
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = flock(&self.directory, FlockOperation::Unlock);
    }
}

impl Store {
    fn open() -> Result<Self> {
        let parent = Directory::open(Path::new("/etc/kvm"), false)?.file;
        bootstrap::check_next_absent(&parent)?;
        let anchor = bootstrap::read_anchor(&parent, 0)?.ok_or_else(invalid)?;
        let bootstrap::Anchor::Ready(epoch) = anchor.0 else {
            return Err(fenced());
        };
        let directory =
            restore_fs::open_beneath(&parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let m = directory.metadata()?;
        if m.uid() != 0 || m.dev() != parent.metadata()?.dev() || m.mode() & 0o7777 != 0o700 {
            return Err(invalid());
        }
        flock(&directory, FlockOperation::NonBlockingLockExclusive)
            .map_err(std::io::Error::from)?;
        let (bytes, revision) =
            bootstrap::read_member::<BYTES>(&directory, STATE, 0)?.ok_or_else(invalid)?;
        let snapshot = Snapshot::decode(bytes.as_slice())?;
        if snapshot.epoch != epoch || snapshot.active.is_some() {
            return Err(fenced());
        }
        let store = Self {
            parent,
            directory,
            identity: (m.dev(), m.ino()),
            anchor,
            revision,
            snapshot,
            members: [None, None, None, None],
        };
        store.inventory(false)?;
        store.check_bound()?;
        // Seal any prior empty bootstrap publication before accepting work.
        restore_fs::open_beneath(&store.parent, "picoclaw-enrollment", OFlags::RDONLY)?
            .sync_all()?;
        restore_fs::open_beneath(&store.directory, STATE, OFlags::RDONLY)?.sync_all()?;
        store.directory.sync_all()?;
        store.parent.sync_all()?;
        Ok(store)
    }

    fn inventory(&self, accepted: bool) -> Result<()> {
        self.inventory_exact([true, accepted, accepted, accepted, false])
    }

    /// State plus exactly the private members this store currently owns.
    fn inventory_owned(&self) -> Result<()> {
        let owned = self.members.each_ref().map(Option::is_some);
        self.inventory_exact([true, owned[0], owned[1], owned[2], owned[3]])
    }

    /// Exactly these of state/active/payload/source/plan; anything else fences.
    fn inventory_exact(&self, expected: [bool; 5]) -> Result<()> {
        let mut found = [false; 5];
        for entry in rustix::fs::Dir::read_from(&self.directory).map_err(std::io::Error::from)? {
            let entry = entry.map_err(std::io::Error::from)?;
            let slot = match entry.file_name().to_bytes() {
                b"." | b".." => continue,
                b"state" => 0,
                b"active" => 1,
                b"payload" => 2,
                b"source" => 3,
                b"plan" => 4,
                _ => return Err(fenced()),
            };
            if !expected[slot] {
                return Err(fenced());
            }
            if found[slot] {
                return Err(invalid());
            }
            found[slot] = true;
        }
        if found != expected {
            return Err(invalid());
        }
        Ok(())
    }

    fn check_bound(&self) -> Result<()> {
        bootstrap::check_next_absent(&self.parent)?;
        let anchor = bootstrap::read_anchor(&self.parent, 0)?.ok_or_else(invalid)?;
        if anchor != self.anchor {
            return Err(invalid());
        }
        for file in [
            &self.directory,
            &restore_fs::open_beneath(&self.parent, DIRECTORY, OFlags::PATH)?,
        ] {
            let m = file.metadata()?;
            if (m.dev(), m.ino()) != self.identity || m.uid() != 0 || m.mode() & 0o7777 != 0o700 {
                return Err(invalid());
            }
        }
        if Revision::from(
            &restore_fs::open_beneath(&self.directory, STATE, OFlags::PATH)?.metadata()?,
        ) != self.revision
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn write(&self, member: Member, bytes: &[u8], touched: &mut bool) -> Result<OwnedMember> {
        self.check_bound()?;
        let mut file: File = openat2(
            &self.directory,
            member.name(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
        .map_err(std::io::Error::from)?
        .into();
        *touched = true;
        fchmod(&file, Mode::from_raw_mode(0o600)).map_err(std::io::Error::from)?;
        file.write_all(bytes)?;
        #[cfg(test)]
        checkpoint(member.name(), "written")?;
        file.sync_all()?;
        let before = Revision::from(&file.metadata()?);
        file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let length = std::io::copy(&mut (&mut file).take(bytes.len() as u64 + 1), &mut hash)?;
        let m = file.metadata()?;
        if length != bytes.len() as u64
            || hash.finalize()[..] != Sha256::digest(bytes)[..]
            || m.uid() != 0
            || m.dev() != self.identity.0
            || m.nlink() != 1
            || m.mode() & 0o7777 != 0o600
            || Revision::from(&m) != before
            || Revision::from(
                &restore_fs::open_beneath(&self.directory, member.name(), OFlags::PATH)?
                    .metadata()?,
            ) != before
        {
            return Err(invalid());
        }
        self.directory.sync_all()?;
        #[cfg(test)]
        checkpoint(member.name(), "durable")?;
        Ok(OwnedMember {
            file,
            revision: before,
            hash: Sha256::digest(bytes).into(),
        })
    }

    fn check_members(&mut self) -> Result<()> {
        if self.members[..3].iter().any(Option::is_none) {
            return Err(invalid());
        }
        for (name, owned) in ["active", "payload", "source", "plan"]
            .into_iter()
            .zip(&mut self.members)
        {
            if let Some(owned) = owned {
                owned.check(&self.directory, name)?;
            }
        }
        Ok(())
    }

    fn check_current(&mut self) -> Result<()> {
        self.check_bound()?;
        self.inventory_owned()?;
        let (bytes, revision) =
            bootstrap::read_member::<BYTES>(&self.directory, STATE, 0)?.ok_or_else(invalid)?;
        if revision != self.revision || bytes.as_slice() != self.snapshot.encode()?.as_slice() {
            return Err(invalid());
        }
        self.check_members()
    }

    fn publish(
        &mut self,
        record: Record,
        touched: &mut bool,
        publication: Publication,
    ) -> Result<()> {
        self.snapshot.sequence = record.sequence;
        self.snapshot.active = Some(record);
        self.commit(touched, publication)
    }

    /// Publish the job's terminal receipt into its ring slot and clear the
    /// active record. The private members stay until `retire` checks them.
    fn publish_terminal(&mut self, record: Record, touched: &mut bool) -> Result<()> {
        if record.phase != Phase::Completed
            || record.sequence != self.snapshot.sequence
            || self
                .snapshot
                .active
                .map(|active| (active.sequence, active.nonce))
                != Some((record.sequence, record.nonce))
        {
            return Err(invalid());
        }
        let slot = ((record.sequence - 1) % RETAINED as u64) as usize;
        self.snapshot.active = None;
        self.snapshot.receipts[slot] = Some(record);
        self.commit(touched, Publication::Completed)
    }

    // The in-memory snapshot already holds the intended value: a failure at
    // any point leaves memory and disk unequal, which later checks fence.
    fn commit(&mut self, touched: &mut bool, publication: Publication) -> Result<()> {
        #[cfg(test)]
        checkpoint(publication.label(), "begin")?;
        #[cfg(not(test))]
        let _ = publication;
        let bytes = self.snapshot.encode()?;
        let file = self.write(Member::Next, bytes.as_slice(), touched)?;
        self.check_bound()?;
        renameat_with(
            &self.directory,
            Member::Next.name(),
            &self.directory,
            STATE,
            RenameFlags::empty(),
        )
        .map_err(std::io::Error::from)?;
        #[cfg(test)]
        checkpoint(publication.label(), "renamed")?;
        self.directory.sync_all()?;
        self.revision = Revision::from(&file.file.metadata()?);
        self.check_bound()?;
        let (published, revision) =
            bootstrap::read_member::<BYTES>(&self.directory, STATE, 0)?.ok_or_else(invalid)?;
        if revision != self.revision || published.as_slice() != bytes.as_slice() {
            return Err(invalid());
        }
        self.inventory_owned()?;
        self.check_members()?;
        #[cfg(test)]
        checkpoint(publication.label(), "durable")?;
        Ok(())
    }
}

impl Store {
    pub(super) fn active_record(&self) -> Option<Record> {
        self.snapshot.active
    }

    /// Exact retirement after a durable terminal receipt. Each member is
    /// re-checked against its owned identity and content just before unlink;
    /// the active fence goes last, after payload and source are durably gone.
    fn retire(&mut self) -> Result<()> {
        if self.snapshot.active.is_some() {
            return Err(invalid());
        }
        self.check_bound()?;
        self.inventory_owned()?;
        for (owned, name) in self
            .members
            .iter_mut()
            .zip(["active", "payload", "source", "plan"])
        {
            if let Some(owned) = owned {
                owned.check(&self.directory, name)?;
            }
        }
        for (slot, member) in [
            (1, Member::Payload),
            (2, Member::Source),
            (3, Member::Plan),
            (0, Member::Active),
        ] {
            let Some(owned) = self.members[slot].as_mut() else {
                continue;
            };
            owned.check(&self.directory, member.name())?;
            unlinkat(&self.directory, member.name(), AtFlags::empty())
                .map_err(std::io::Error::from)?;
            #[cfg(test)]
            checkpoint(member.name(), "retired")?;
            self.members[slot] = None;
            if slot == 3 || (slot == 2 && self.members[3].is_none()) {
                // Private payload/source/plan removal is durable before the fence goes.
                self.directory.sync_all()?;
                self.inventory_owned()?;
            }
        }
        self.directory.sync_all()?;
        self.check_bound()?;
        self.inventory(false)
    }

    /// Persist the once-chosen change before any stop or publication.
    fn write_plan(&mut self, bytes: &[u8], touched: &mut bool) -> Result<()> {
        if self.members[3].is_some() {
            return Err(fenced());
        }
        self.members[3] = Some(self.write(Member::Plan, bytes, touched)?);
        self.inventory_owned()?;
        self.check_members()
    }
}

fn support(facts: &mut Facts) -> Result<[u8; 32]> {
    let before = facts.image.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7022 != 0
        || !(1..=crate::update::helper_family::MAX_BACKEND_BYTES).contains(&before.len())
    {
        return Err(invalid());
    }
    let mut hash = Sha256::new();
    hash.update(b"NanoKVM Pico executing producer image v1\0");
    let length = std::io::copy(&mut (&mut facts.image).take(before.len() + 1), &mut hash)?;
    if length != before.len() || Revision::from(&facts.image.metadata()?) != Revision::from(&before)
    {
        return Err(invalid());
    }
    Ok(hash.finalize().into())
}

pub(super) fn perform(
    payload: &mut Payload,
    cursor: Cursor,
    nonce: [u8; 16],
) -> Result<Acceptance> {
    if nonce == [0; 16] || cursor.epoch == [0; 16] {
        return Err(invalid());
    }
    let request = payload.request.as_ref().ok_or_else(invalid)?;
    let kind = request.kind();
    let encoded = request.encode()?;
    let request_hash = private_digest(b"NanoKVM Pico request v1\0", encoded.as_slice());
    payload.store = Some(Store::open()?);
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    if cursor.epoch != store.snapshot.epoch {
        return Ok(Acceptance::Expired);
    }
    for receipt in store.snapshot.receipts.iter().flatten() {
        if receipt.nonce == nonce {
            if cursor.sequence.checked_add(1) != Some(receipt.sequence)
                || receipt.kind != kind
                || receipt.request != request_hash
                || receipt.home != payload.facts.home_fingerprint
            {
                return Err(invalid());
            }
            return Ok(Acceptance::Existing(JobId {
                epoch: cursor.epoch,
                sequence: receipt.sequence,
                nonce,
            }));
        }
    }
    if cursor.sequence < store.snapshot.sequence {
        return Ok(Acceptance::Expired);
    }
    if cursor.sequence != store.snapshot.sequence {
        return Err(invalid());
    }
    let sequence = cursor.sequence.checked_add(1).ok_or_else(invalid)?;
    let support = support(&mut payload.facts)?;
    payload.source = Some(Source::capture(&payload.facts)?);
    let source = payload.source.as_ref().ok_or_else(invalid)?;
    let record = Record {
        sequence,
        nonce,
        boot: payload.facts.boot,
        home: payload.facts.home_fingerprint,
        support,
        request: request_hash,
        source: private_digest(b"NanoKVM Pico source v2\0", source.bytes.as_slice()),
        kind,
        phase: Phase::Accepted,
        was_running: payload.facts.running_generation.is_some(),
        resume_allowed: payload.facts.running_generation.is_some() && kind != Kind::Remove,
        uncertain: false,
        outcome: Outcome::Pending,
        runtime: Runtime::Pending,
    };
    let mut active = Zeroizing::new([0; 352]);
    active[..8].copy_from_slice(b"NKPINT01");
    active[8..24].copy_from_slice(&cursor.epoch);
    active[24..32].copy_from_slice(&cursor.sequence.to_le_bytes());
    active[64..320].copy_from_slice(&record.encode()?);
    let hash = private_digest(b"NanoKVM Pico active intent v1\0", &active[..320]);
    active[320..].copy_from_slice(&hash);
    store.members[0] =
        Some(store.write(Member::Active, active.as_slice(), &mut payload.touched)?);
    store.members[1] =
        Some(store.write(Member::Payload, encoded.as_slice(), &mut payload.touched)?);
    store.members[2] = Some(store.write(
        Member::Source,
        source.bytes.as_slice(),
        &mut payload.touched,
    )?);
    store.publish(record, &mut payload.touched, Publication::Accepted)?;
    Ok(Acceptance::Accepted(JobId {
        epoch: cursor.epoch,
        sequence,
        nonce,
    }))
}

pub(super) fn advance(payload: &mut Payload, advance: Advance) -> Result<TransitionStatus> {
    match advance {
        Advance::Settle => return settle(payload),
        Advance::Apply => return apply(payload),
        Advance::Activate => return activate(payload),
        Advance::Finish(resume) => return finish(payload, resume),
        Advance::Stop { .. } | Advance::Closed { .. } => {}
    }
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    store.check_current()?;
    let mut record = store.snapshot.active.ok_or_else(invalid)?;
    let id = JobId {
        epoch: store.snapshot.epoch,
        sequence: record.sequence,
        nonce: record.nonce,
    };
    if record.uncertain
        || record.boot != payload.facts.boot
        || record.home != payload.facts.home_fingerprint
    {
        return Err(fenced());
    }
    // An explicit Stop lowers resume permission durably; it can only fall and
    // stays distinct from initial was_running. Automatic quiescence keeps it,
    // and is only allowed for a change whose plan is already durable. A
    // repeated explicit request may lower it in place but never re-publish.
    let (explicit, publication, status) = match advance {
        Advance::Stop {
            id: expected,
            explicit,
        } if expected == id
            && record.was_running
            && (record.phase == Phase::Accepted
                || (explicit && record.phase == Phase::Stopping && record.resume_allowed)) =>
        {
            record.phase = Phase::Stopping;
            (explicit, Publication::Stop, TransitionStatus::Stopping)
        }
        Advance::Closed { proof, explicit }
            if proof.matches(id, record.boot, record.home)
                && (matches!(record.phase, Phase::Accepted | Phase::Stopping)
                    || (explicit && record.phase == Phase::Closed && record.resume_allowed)) =>
        {
            record.phase = Phase::Closed;
            (explicit, Publication::Closed, TransitionStatus::Closed)
        }
        _ => return Err(fenced()),
    };
    if explicit {
        record.resume_allowed = false;
    } else if store.members[3].is_none() {
        return Err(fenced());
    }
    store.publish(record, &mut payload.touched, publication)?;
    Ok(status)
}

// The documents a request asks for before the fixed startup defaults: the
// source itself for Startup, the selected model for Model.
fn target_documents(
    request: Option<&Request>,
    source: &crate::update::picoclaw_startup::Documents,
) -> Result<crate::update::picoclaw_startup::Documents> {
    let mut target = crate::update::picoclaw_startup::Documents {
        config: source.config.clone(),
        security: source.security.clone(),
    };
    match request {
        Some(Request::Startup) => {}
        Some(Request::Model {
            model,
            api_base,
            api_key,
        }) => {
            crate::update::picoclaw_model::apply(
                &mut target.config,
                &mut target.security,
                model,
                api_base,
                api_key,
            )?;
        }
        _ => return Err(invalid()),
    }
    Ok(target)
}

// Nothing was planned, stopped or changed: like a canonical no-op, the refusal
// is terminal at once and a live runtime keeps running untouched.
fn refuse(store: &mut Store, mut record: Record, touched: &mut bool) -> Result<TransitionStatus> {
    record.phase = Phase::Completed;
    record.outcome = Outcome::Failed;
    record.runtime = if record.was_running && !record.resume_allowed {
        Runtime::Suppressed
    } else {
        Runtime::Unchanged
    };
    store.publish_terminal(record, touched)?;
    store.retire()?;
    Ok(TransitionStatus::Refused)
}

/// Install: put the installer's staged executable in place when its SHA-512
/// is the requested one. An installed equal executable is a no-op; a staged
/// file that is missing, unsafe or different refuses.
fn settle_install(payload: &mut Payload, mut record: Record) -> Result<TransitionStatus> {
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    let Some(Request::Install { digest }) = payload.request.as_ref() else {
        return Err(invalid());
    };
    let digest = *digest;
    let (Ok(staged), Ok(installed)) = (
        crate::update::picoclaw_runtime::staged(),
        crate::update::picoclaw_runtime::installed(),
    ) else {
        return refuse(store, record, &mut payload.touched);
    };
    if installed.is_some_and(|(_, current)| current == digest) {
        record.phase = Phase::Completed;
        record.outcome = Outcome::Noop;
        record.runtime = if record.was_running && !record.resume_allowed {
            Runtime::Suppressed
        } else {
            Runtime::Unchanged
        };
        store.publish_terminal(record, &mut payload.touched)?;
        store.retire()?;
        return Ok(TransitionStatus::Completed);
    }
    let Some((staged, staged_digest)) = staged else {
        return refuse(store, record, &mut payload.touched);
    };
    if staged_digest != digest {
        return refuse(store, record, &mut payload.touched);
    }
    let plan = InstallPlan {
        staged,
        digest,
        prior: installed.map(|(asset, _)| asset),
    };
    store.write_plan(&encode_install(&record, &plan), &mut payload.touched)?;
    payload.install = Some(plan);
    Ok(TransitionStatus::Planned)
}

/// Profile: replace the workspace AGENT.md with the requested shipped profile,
/// but only an absent document or an exact shipped one; a customized document
/// is kept and the request refused. An equal document is a no-op.
fn settle_profile(payload: &mut Payload, mut record: Record) -> Result<TransitionStatus> {
    use crate::update::picoclaw_profile::{Decision, classify};
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    let source = payload.source.as_ref().ok_or_else(invalid)?;
    let kvm = match payload.request.as_ref() {
        Some(Request::Profile(Profile::Kvm)) => true,
        Some(Request::Profile(Profile::Default)) => false,
        _ => return Err(invalid()),
    };
    let view = decode_source(source.bytes.as_slice())?;
    if !view.home_present || view.config.is_none() {
        // The workspace is chosen by the config; Profile never creates it.
        return refuse(store, record, &mut payload.touched);
    }
    let (Ok(workspace), Ok(shipped)) = (source_workspace(&view), read_shipped()) else {
        return refuse(store, record, &mut payload.touched);
    };
    let Ok(current) = read_workspace_agent(&workspace) else {
        return refuse(store, record, &mut payload.touched);
    };
    let desired = shipped[usize::from(kvm)].clone();
    match classify(
        current.as_deref(),
        &desired,
        [shipped[0].as_slice(), shipped[1].as_slice()],
    ) {
        Decision::Custom => refuse(store, record, &mut payload.touched),
        Decision::Noop => {
            record.phase = Phase::Completed;
            record.outcome = Outcome::Noop;
            record.runtime = if record.was_running && !record.resume_allowed {
                Runtime::Suppressed
            } else {
                Runtime::Unchanged
            };
            store.publish_terminal(record, &mut payload.touched)?;
            store.retire()?;
            Ok(TransitionStatus::Completed)
        }
        Decision::Replace => {
            let plan = ProfilePlan {
                before: current.as_deref().map(profile_digest),
                desired,
            };
            store.write_plan(&encode_profile(&record, &plan)?, &mut payload.touched)?;
            payload.profile = Some(plan);
            Ok(TransitionStatus::Planned)
        }
    }
}

/// Remove: delete exactly the managed executable, NanoKVM's internal
/// credential and the accepted pair; the workspace and the rest of Home stay.
/// Nothing managed left is a no-op that never stops a live runtime.
fn settle_removal(payload: &mut Payload, mut record: Record) -> Result<TransitionStatus> {
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    let source = payload.source.as_ref().ok_or_else(invalid)?;
    let view = decode_source(source.bytes.as_slice())?;
    let (Ok(binary), Ok(token)) = (
        crate::update::picoclaw_runtime::observe(),
        crate::update::picoclaw_token::observe_identity(),
    ) else {
        return refuse(store, record, &mut payload.touched);
    };
    if binary.is_none() && token.is_none() && view.config.is_none() && view.security.is_none() {
        record.phase = Phase::Completed;
        record.outcome = Outcome::Noop;
        record.runtime = if record.was_running && !record.resume_allowed {
            Runtime::Suppressed
        } else {
            Runtime::Unchanged
        };
        store.publish_terminal(record, &mut payload.touched)?;
        store.retire()?;
        return Ok(TransitionStatus::Completed);
    }
    let removal = Removal { binary, token };
    store.write_plan(&encode_removal(&record, &removal), &mut payload.touched)?;
    payload.removal = Some(removal);
    Ok(TransitionStatus::Planned)
}

/// Ordinary Startup settlement, entered only from Accepted without an explicit
/// Stop. A canonical no-op records its terminal receipt and retires the job
/// without stopping a live runtime or touching the pair. A refusal does the
/// same with a Failed receipt; a change makes its plan durable.
pub(super) fn settle(payload: &mut Payload) -> Result<TransitionStatus> {
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    store.check_current()?;
    let mut record = store.snapshot.active.ok_or_else(invalid)?;
    if record.uncertain
        || record.boot != payload.facts.boot
        || record.home != payload.facts.home_fingerprint
        || record.phase != Phase::Accepted
    {
        return Err(fenced());
    }
    if record.kind == Kind::Remove {
        return settle_removal(payload, record);
    }
    if record.kind == Kind::Profile {
        return settle_profile(payload, record);
    }
    if record.kind == Kind::Install {
        return settle_install(payload, record);
    }
    if !matches!(record.kind, Kind::Startup | Kind::Model) {
        // The other fixed operations have no settlement executor yet.
        return refuse(store, record, &mut payload.touched);
    }
    let source = payload.source.as_ref().ok_or_else(invalid)?;
    let view = decode_source(source.bytes.as_slice())?;
    let (true, Some(config)) = (view.home_present, view.config) else {
        // Startup never creates a missing Home or config.
        return refuse(store, record, &mut payload.touched);
    };
    let Ok(documents) = crate::update::picoclaw_startup::decode(config, view.security) else {
        return refuse(store, record, &mut payload.touched);
    };
    // The request's own change first, then the fixed startup defaults on top.
    let Ok(target) = target_documents(payload.request.as_ref(), &documents) else {
        return refuse(store, record, &mut payload.touched);
    };
    let internal = crate::update::picoclaw_token::observe()?;
    let decision = match crate::update::picoclaw_startup::classify_change(
        &documents,
        &target,
        internal.as_deref().map(String::as_str),
    ) {
        Ok(decision) => decision,
        Err(_) => return refuse(store, record, &mut payload.touched),
    };
    if decision != crate::update::picoclaw_startup::Decision::Noop {
        // Select missing tokens exactly once and make the whole change durable
        // before any stop: a retry or crash replays this plan, never new entropy.
        let gateway = crate::update::picoclaw_startup::existing_gateway_token(
            &target.config,
            &target.security,
        )
        .map(Zeroizing::new)
        .unwrap_or_else(|| Zeroizing::new(crate::auth::token::random_token(36)));
        let internal_new = internal.is_none();
        let internal = match internal {
            Some(value) => value,
            None => crate::update::picoclaw_token::new_value()?,
        };
        let desired = crate::update::picoclaw_startup::desired(&target, &gateway, &internal)?;
        let plan = Plan {
            config: desired.config,
            security: Zeroizing::new(desired.security.as_bytes().to_vec()),
            internal,
            internal_new,
        };
        store.write_plan(
            encode_plan(&record, &plan)?.as_slice(),
            &mut payload.touched,
        )?;
        payload.plan = Some(plan);
        return Ok(TransitionStatus::Planned);
    }
    record.phase = Phase::Completed;
    record.outcome = Outcome::Noop;
    record.runtime = if record.was_running && !record.resume_allowed {
        Runtime::Suppressed
    } else {
        Runtime::Unchanged
    };
    store.publish_terminal(record, &mut payload.touched)?;
    store.retire()?;
    Ok(TransitionStatus::Completed)
}

/// Apply a quiesced Startup plan. Under the job's exclusive Home lease the
/// accepted pair and internal value are revalidated; a concurrent change ends
/// the job as a terminal failure with nothing changed. Otherwise Applying is
/// durable before the planned internal value and then the pair (through its
/// own journal) are installed, and Committed binds the installed generation.
pub(super) fn apply(payload: &mut Payload) -> Result<TransitionStatus> {
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    store.check_current()?;
    let mut record = store.snapshot.active.ok_or_else(invalid)?;
    if record.uncertain
        || record.boot != payload.facts.boot
        || record.home != payload.facts.home_fingerprint
        || record.phase != Phase::Closed
        || !matches!(
            record.kind,
            Kind::Startup | Kind::Model | Kind::Remove | Kind::Profile | Kind::Install
        )
        || store.members[3].is_none()
    {
        return Err(fenced());
    }
    if record.kind == Kind::Remove {
        return apply_removal(payload, record);
    }
    if record.kind == Kind::Profile {
        return apply_profile(payload, record);
    }
    if record.kind == Kind::Install {
        return apply_install(payload, record);
    }
    let plan = payload.plan.as_ref().ok_or_else(invalid)?;
    let source = payload.source.as_ref().ok_or_else(invalid)?;
    source.lock_exclusive()?;
    let view = decode_source(source.bytes.as_slice())?;
    let current = super::super::super::pair::read_source(&source.directory)?;
    let internal = crate::update::picoclaw_token::observe()?;
    let unchanged = current[0].as_deref().map(Vec::as_slice) == view.config
        && current[1].as_deref().map(Vec::as_slice) == view.security
        && match (&internal, plan.internal_new) {
            (None, true) => true,
            (Some(value), false) => value.as_str() == plan.internal.as_str(),
            _ => false,
        };
    if !unchanged {
        // The scope is proven closed and nothing was changed: terminal failure.
        record.phase = Phase::Completed;
        record.outcome = Outcome::Failed;
        record.runtime = Runtime::NotRequested;
        store.publish_terminal(record, &mut payload.touched)?;
        store.retire()?;
        return Ok(TransitionStatus::Superseded);
    }
    record.phase = Phase::Applying;
    store.publish(record, &mut payload.touched, Publication::Applying)?;
    if plan.internal_new {
        crate::update::picoclaw_token::install(&payload._configuration, plan.internal.as_str())?;
    }
    #[cfg(test)]
    checkpoint("internal", "installed")?;
    super::super::super::pair::publish(&source.directory, &plan.config, Some(&plan.security))?;
    #[cfg(test)]
    checkpoint("pair", "published")?;
    let installed = super::super::super::pair::read_installed(&source.directory)?;
    if installed.config.as_slice() != plan.config.as_slice()
        || installed.security.as_deref().map(Vec::as_slice) != Some(plan.security.as_slice())
    {
        return Err(invalid());
    }
    record.phase = Phase::Committed;
    store.publish(record, &mut payload.touched, Publication::Committed)?;
    Ok(TransitionStatus::Committed(
        super::super::super::Generation::from_documents(&installed),
    ))
}

/// Install the planned executable of a quiesced Install job. The staged file
/// and the prior executable are revalidated; any difference ends the job as a
/// terminal failure with nothing changed. Applying is durable before the
/// atomic replacement. Without a configuration nothing is launched.
fn apply_install(payload: &mut Payload, mut record: Record) -> Result<TransitionStatus> {
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    let plan = payload.install.as_ref().ok_or_else(invalid)?;
    let source = payload.source.as_ref().ok_or_else(invalid)?;
    source.lock_exclusive()?;
    let view = decode_source(source.bytes.as_slice())?;
    let unchanged = crate::update::picoclaw_runtime::staged()? == Some((plan.staged, plan.digest))
        && crate::update::picoclaw_runtime::installed()?.map(|(asset, _)| asset) == plan.prior;
    if !unchanged {
        record.phase = Phase::Completed;
        record.outcome = Outcome::Failed;
        record.runtime = Runtime::NotRequested;
        store.publish_terminal(record, &mut payload.touched)?;
        store.retire()?;
        return Ok(TransitionStatus::Superseded);
    }
    record.phase = Phase::Applying;
    store.publish(record, &mut payload.touched, Publication::Applying)?;
    crate::update::picoclaw_runtime::install(plan.staged, plan.digest, plan.prior)?;
    #[cfg(test)]
    checkpoint("binary", "installed")?;
    // A running runtime had a configuration; a fresh install may have none.
    let generation = if view.home_present && view.config.is_some() {
        Some(super::super::super::Generation::from_documents(
            &super::super::super::pair::read_installed(&source.directory)?,
        ))
    } else {
        None
    };
    record.phase = Phase::Committed;
    store.publish(record, &mut payload.touched, Publication::Committed)?;
    Ok(match generation {
        Some(generation) => TransitionStatus::Committed(generation),
        None => TransitionStatus::CommittedWithoutLaunch,
    })
}

/// Install the planned profile of a quiesced Profile job. Under the job's
/// exclusive Home lease the pair (which selects the workspace) and the prior
/// document are revalidated; any difference ends the job as a terminal
/// failure with nothing changed. Applying is durable before the document is
/// replaced, and Committed binds the unchanged pair's generation.
fn apply_profile(payload: &mut Payload, mut record: Record) -> Result<TransitionStatus> {
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    let plan = payload.profile.as_ref().ok_or_else(invalid)?;
    let source = payload.source.as_ref().ok_or_else(invalid)?;
    source.lock_exclusive()?;
    let view = decode_source(source.bytes.as_slice())?;
    let current = super::super::super::pair::read_source(&source.directory)?;
    let workspace = source_workspace(&view)?;
    let unchanged = current[0].as_deref().map(Vec::as_slice) == view.config
        && current[1].as_deref().map(Vec::as_slice) == view.security
        && read_workspace_agent(&workspace)?
            .as_deref()
            .map(profile_digest)
            == plan.before;
    if !unchanged {
        record.phase = Phase::Completed;
        record.outcome = Outcome::Failed;
        record.runtime = Runtime::NotRequested;
        store.publish_terminal(record, &mut payload.touched)?;
        store.retire()?;
        return Ok(TransitionStatus::Superseded);
    }
    record.phase = Phase::Applying;
    store.publish(record, &mut payload.touched, Publication::Applying)?;
    if !install_profile(&workspace, plan)? {
        return Err(invalid());
    }
    #[cfg(test)]
    checkpoint("profile", "published")?;
    let installed = super::super::super::pair::read_installed(&source.directory)?;
    record.phase = Phase::Committed;
    store.publish(record, &mut payload.touched, Publication::Committed)?;
    Ok(TransitionStatus::Committed(
        super::super::super::Generation::from_documents(&installed),
    ))
}

/// Delete exactly the planned files of a quiesced Remove job. Under the job's
/// exclusive Home lease the pair, executable and credential are revalidated;
/// any difference ends the job as a terminal failure with nothing deleted.
/// Applying is durable before the first deletion; each is idempotent.
fn apply_removal(payload: &mut Payload, mut record: Record) -> Result<TransitionStatus> {
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    let removal = payload.removal.as_ref().ok_or_else(invalid)?;
    let source = payload.source.as_ref().ok_or_else(invalid)?;
    source.lock_exclusive()?;
    let view = decode_source(source.bytes.as_slice())?;
    // Without its Home the pair was absent; the lease is on an ancestor then.
    let current = if view.home_present {
        super::super::super::pair::read_source(&source.directory)?
    } else {
        [None, None]
    };
    let unchanged = current[0].as_deref().map(Vec::as_slice) == view.config
        && current[1].as_deref().map(Vec::as_slice) == view.security
        && crate::update::picoclaw_runtime::observe()? == removal.binary
        && crate::update::picoclaw_token::observe_identity()? == removal.token;
    if !unchanged {
        record.phase = Phase::Completed;
        record.outcome = Outcome::Failed;
        record.runtime = Runtime::NotRequested;
        store.publish_terminal(record, &mut payload.touched)?;
        store.retire()?;
        return Ok(TransitionStatus::Superseded);
    }
    record.phase = Phase::Applying;
    store.publish(record, &mut payload.touched, Publication::Applying)?;
    if view.home_present {
        super::super::super::pair::remove(&source.directory, [view.config, view.security])?;
    }
    #[cfg(test)]
    checkpoint("pair", "removed")?;
    if let Some(token) = removal.token {
        crate::update::picoclaw_token::remove(&payload._configuration, token)?;
    }
    #[cfg(test)]
    checkpoint("internal", "removed")?;
    if let Some(binary) = removal.binary {
        crate::update::picoclaw_runtime::remove(binary)?;
    }
    #[cfg(test)]
    checkpoint("binary", "removed")?;
    record.phase = Phase::Committed;
    store.publish(record, &mut payload.touched, Publication::Committed)?;
    Ok(TransitionStatus::CommittedWithoutLaunch)
}

/// Record the intent to resume before the native launch.
pub(super) fn activate(payload: &mut Payload) -> Result<TransitionStatus> {
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    store.check_current()?;
    let mut record = store.snapshot.active.ok_or_else(invalid)?;
    if record.uncertain
        || record.boot != payload.facts.boot
        || record.phase != Phase::Committed
        || !record.was_running
        || !record.resume_allowed
    {
        return Err(fenced());
    }
    record.phase = Phase::Activating;
    store.publish(record, &mut payload.touched, Publication::Activating)?;
    Ok(TransitionStatus::Activating)
}

/// Terminal Changed receipt with the exact runtime result, then retirement.
pub(super) fn finish(payload: &mut Payload, resume: RuntimeResult) -> Result<TransitionStatus> {
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    store.check_current()?;
    let mut record = store.snapshot.active.ok_or_else(invalid)?;
    if record.uncertain
        || record.boot != payload.facts.boot
        || !matches!(
            record.kind,
            Kind::Startup | Kind::Model | Kind::Remove | Kind::Profile | Kind::Install
        )
    {
        return Err(fenced());
    }
    record.runtime = match (record.phase, resume) {
        (Phase::Committed, RuntimeResult::NotRequested) if record.kind == Kind::Remove => {
            Runtime::Removed
        }
        _ if record.kind == Kind::Remove => return Err(fenced()),
        (Phase::Activating, RuntimeResult::Resumed) => Runtime::Resumed,
        (Phase::Activating, RuntimeResult::ResumeFailed) => Runtime::ResumeFailed,
        (Phase::Committed | Phase::Activating, RuntimeResult::Suppressed) if record.was_running => {
            record.resume_allowed = false;
            Runtime::Suppressed
        }
        (Phase::Committed, RuntimeResult::NotRequested) if !record.was_running => {
            Runtime::NotRequested
        }
        (Phase::Committed, RuntimeResult::NotRequested) if !record.resume_allowed => {
            Runtime::Suppressed
        }
        _ => return Err(fenced()),
    };
    record.phase = Phase::Completed;
    record.outcome = Outcome::Changed;
    store.publish_terminal(record, &mut payload.touched)?;
    store.retire()?;
    Ok(TransitionStatus::Completed)
}

// ---- Prior-boot recovery ------------------------------------------------

const PAYLOAD_LIMIT: usize = super::super::super::MAX_FILE_BYTES;
const SOURCE_LIMIT: usize = 128 + 4095 + 2 * super::super::super::MAX_FILE_BYTES;
const PLAN_LIMIT: usize = PLAN_HEADER + 2 * super::super::super::MAX_FILE_BYTES + 256 + 32;

type Contents = [Option<Zeroizing<Vec<u8>>>; 4];

// One existing private member read exactly once, kept as the owned identity
// that retirement re-checks immediately before its unlink.
fn adopt_member(
    directory: &File,
    name: &str,
    limit: usize,
    device: u64,
) -> Result<Option<(OwnedMember, Zeroizing<Vec<u8>>)>> {
    let pinned = match restore_fs::open_beneath(directory, name, OFlags::PATH) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let m = pinned.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.dev() != device
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o600
        || m.len() > limit as u64
    {
        return Err(invalid());
    }
    let revision = Revision::from(&m);
    let mut file = restore_fs::open_beneath(directory, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
    if Revision::from(&file.metadata()?) != revision {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(m.len() as usize));
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != m.len() || Revision::from(&file.metadata()?) != revision {
        return Err(invalid());
    }
    let hash = Sha256::digest(bytes.as_slice()).into();
    Ok(Some((
        OwnedMember {
            file,
            revision,
            hash,
        },
        bytes,
    )))
}

impl Store {
    /// Recovery-only opener: unlike `open`, an active record and its private
    /// members are expected. Only the fixed names are accepted.
    fn open_for_recovery() -> Result<Option<(Self, Contents)>> {
        let parent = Directory::open(Path::new("/etc/kvm"), false)?.file;
        bootstrap::check_next_absent(&parent)?;
        let Some(anchor) = bootstrap::read_anchor(&parent, 0)? else {
            return Ok(None);
        };
        let bootstrap::Anchor::Ready(epoch) = anchor.0 else {
            return Ok(None);
        };
        let directory =
            restore_fs::open_beneath(&parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let m = directory.metadata()?;
        if m.uid() != 0 || m.dev() != parent.metadata()?.dev() || m.mode() & 0o7777 != 0o700 {
            return Err(invalid());
        }
        flock(&directory, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                fenced()
            } else {
                std::io::Error::from(error).into()
            }
        })?;
        let (bytes, revision) =
            bootstrap::read_member::<BYTES>(&directory, STATE, 0)?.ok_or_else(invalid)?;
        let snapshot = Snapshot::decode(bytes.as_slice())?;
        if snapshot.epoch != epoch {
            return Err(invalid());
        }
        let mut members = [None, None, None, None];
        let mut contents: Contents = [None, None, None, None];
        for (slot, (name, limit)) in [
            ("active", 352),
            ("payload", PAYLOAD_LIMIT),
            ("source", SOURCE_LIMIT),
            ("plan", PLAN_LIMIT),
        ]
        .into_iter()
        .enumerate()
        {
            if let Some((owned, bytes)) = adopt_member(&directory, name, limit, m.dev())? {
                members[slot] = Some(owned);
                contents[slot] = Some(bytes);
            }
        }
        let store = Self {
            parent,
            directory,
            identity: (m.dev(), m.ino()),
            anchor,
            revision,
            snapshot,
            members,
        };
        store.inventory_owned()?;
        store.check_bound()?;
        Ok(Some((store, contents)))
    }
}

// Every present member must belong to exactly this job: the active intent
// embeds its accepted record, payload and source match the bound digests and
// the plan its own binding. Foreign or damaged data is never adopted.
fn check_binding(record: &Record, epoch: [u8; 16], contents: &Contents) -> Result<()> {
    if let Some(active) = &contents[0] {
        if active.len() != 352
            || &active[..8] != b"NKPINT01"
            || active[8..24] != epoch
            || active[24..32] != record.sequence.wrapping_sub(1).to_le_bytes()
            || active[32..64].iter().any(|byte| *byte != 0)
            || private_digest(b"NanoKVM Pico active intent v1\0", &active[..320]) != active[320..]
        {
            return Err(invalid());
        }
        let accepted = Record::decode(&active[64..320])?;
        if accepted.phase != Phase::Accepted
            || (
                accepted.sequence,
                accepted.nonce,
                accepted.boot,
                accepted.home,
                accepted.support,
                accepted.request,
                accepted.source,
                accepted.was_running,
            ) != (
                record.sequence,
                record.nonce,
                record.boot,
                record.home,
                record.support,
                record.request,
                record.source,
                record.was_running,
            )
            || accepted.kind != record.kind
            // Resume permission only ever falls after acceptance.
            || (record.resume_allowed && !accepted.resume_allowed)
        {
            return Err(invalid());
        }
    }
    if let Some(payload) = &contents[1]
        && private_digest(b"NanoKVM Pico request v1\0", payload) != record.request
    {
        return Err(invalid());
    }
    if let Some(source) = &contents[2]
        && private_digest(b"NanoKVM Pico source v2\0", source) != record.source
    {
        return Err(invalid());
    }
    if let Some(plan) = &contents[3] {
        check_plan(record, plan)?;
    }
    Ok(())
}

// The job's own Home again, by the source's path and only with its exact
// recorded identity (device, inode, owner and mode); `None` otherwise.
fn reopen_source(bytes: Zeroizing<Vec<u8>>) -> Result<Option<Source>> {
    use std::os::unix::ffi::OsStrExt as _;
    let directory = Directory::open(
        Path::new(std::ffi::OsStr::from_bytes(decode_source(&bytes)?.home)),
        false,
    )?;
    let m = directory.file.metadata()?;
    if bytes[16..24] != m.dev().to_le_bytes()
        || bytes[24..32] != m.ino().to_le_bytes()
        || bytes[32..36] != m.uid().to_le_bytes()
        || bytes[36..40] != m.mode().to_le_bytes()
    {
        return Ok(None);
    }
    Ok(Some(Source { directory, bytes }))
}

// Finish the SAME planned removal of an interrupted Applying job: each file
// is gone already or still exactly its planned or accepted self. A changed
// file refuses and keeps the fence.
fn complete_removal(
    configuration: &ConfigPermit,
    removal: &Removal,
    bytes: Zeroizing<Vec<u8>>,
) -> Result<bool> {
    if decode_source(&bytes)?.home_present {
        let Some(source) = reopen_source(bytes)? else {
            return Ok(false);
        };
        source.lock_exclusive()?;
        let view = decode_source(source.bytes.as_slice())?;
        super::super::super::pair::remove(&source.directory, [view.config, view.security])?;
    }
    if let Some(token) = removal.token {
        crate::update::picoclaw_token::remove(configuration, token)?;
    }
    if let Some(binary) = removal.binary {
        crate::update::picoclaw_runtime::remove(binary)?;
    }
    Ok(true)
}

// Finish the SAME durable plan of an interrupted Applying job under the job's
// own Home identity: the pair is still the accepted source or already the plan
// (an interrupted pair journal is completed first), the credential the planned
// value or absent for a new one. Anything else keeps the fence.
fn complete_startup_apply(
    configuration: &ConfigPermit,
    plan: &Plan,
    bytes: Zeroizing<Vec<u8>>,
) -> Result<bool> {
    let Some(source) = reopen_source(bytes)? else {
        return Ok(false);
    };
    source.lock_exclusive()?;
    super::super::super::pair::recover(&source.directory)?;
    let view = decode_source(source.bytes.as_slice())?;
    let current = super::super::super::pair::read_source(&source.directory)?;
    let equals = |config: Option<&[u8]>, security: Option<&[u8]>| {
        current[0].as_deref().map(Vec::as_slice) == config
            && current[1].as_deref().map(Vec::as_slice) == security
    };
    let applied = equals(Some(&plan.config), Some(&plan.security));
    if !applied && !equals(view.config, view.security) {
        return Ok(false);
    }
    if plan.internal_new {
        crate::update::picoclaw_token::install(configuration, plan.internal.as_str())?;
    } else if crate::update::picoclaw_token::observe()?
        .as_deref()
        .map(String::as_str)
        != Some(plan.internal.as_str())
    {
        return Ok(false);
    }
    if !applied {
        super::super::super::pair::publish(&source.directory, &plan.config, Some(&plan.security))?;
    }
    let installed = super::super::super::pair::read_installed(&source.directory)?;
    if installed.config.as_slice() != plan.config.as_slice()
        || installed.security.as_deref().map(Vec::as_slice) != Some(plan.security.as_slice())
    {
        return Err(invalid());
    }
    Ok(true)
}

/// Settle a job left by a PREVIOUS kernel boot, at early boot under Update
/// and Config: its native scope cannot have survived. Only fixed steps run;
/// never new entropy, a fresh classification or adoption of foreign data.
/// `false` means nothing was settled and the normal fence decides.
pub(super) fn recover_prior_boot(configuration: &ConfigPermit) -> Result<bool> {
    let Some((mut store, mut contents)) = Store::open_for_recovery()? else {
        return Ok(false);
    };
    let epoch = store.snapshot.epoch;
    let mut touched = false;
    let Some(mut record) = store.snapshot.active else {
        // Completion pending: members left behind a durable terminal receipt.
        // Members of an unpublished acceptance belong to no receipt and keep
        // the fence, as does anything else that does not bind to the head.
        let sequence = store.snapshot.sequence;
        let Some(receipt) = sequence
            .checked_sub(1)
            .and_then(|index| store.snapshot.receipts[(index % RETAINED as u64) as usize])
            .filter(|receipt| receipt.sequence == sequence)
        else {
            return Ok(false);
        };
        if store.members.iter().all(Option::is_none)
            || contents[0]
                .as_ref()
                .is_some_and(|active| active.get(64..72) != Some(&sequence.to_le_bytes()[..]))
        {
            return Ok(false);
        }
        check_binding(&receipt, epoch, &contents)?;
        store.retire()?;
        return Ok(true);
    };
    // Same boot: the owned native scope may still exist, so only its broker
    // may settle the job. Uncertain or incomplete jobs are never adopted.
    if record.uncertain
        || contents[..3].iter().any(Option::is_none)
        || record.boot == super::super::current_boot()?
    {
        return Ok(false);
    }
    check_binding(&record, epoch, &contents)?;
    let startup_runtime = |record: &mut Record| {
        record.runtime = if record.was_running {
            record.resume_allowed = false;
            Runtime::Suppressed
        } else {
            Runtime::NotRequested
        };
    };
    match (record.phase, record.kind) {
        // No target change began: the job is cancelled.
        (Phase::Accepted | Phase::Stopping | Phase::Closed, _) => {
            record.outcome = Outcome::Cancelled;
            record.runtime = Runtime::NotRequested;
            record.resume_allowed = false;
        }
        (Phase::Applying, Kind::Startup | Kind::Model) => {
            let source = contents[2].take();
            let (Some(plan), Some(source)) = (&contents[3], source) else {
                return Ok(false);
            };
            let plan = decode_plan(&record, plan)?;
            if !complete_startup_apply(configuration, &plan, source)? {
                return Ok(false);
            }
            record.outcome = Outcome::Changed;
            startup_runtime(&mut record);
        }
        (Phase::Applying, Kind::Profile) => {
            let source = contents[2].take();
            let (Some(plan), Some(source)) = (&contents[3], source) else {
                return Ok(false);
            };
            let plan = decode_profile(&record, plan)?;
            let Some(source) = reopen_source(source)? else {
                return Ok(false);
            };
            source.lock_exclusive()?;
            let workspace = source_workspace(&decode_source(source.bytes.as_slice())?)?;
            if !install_profile(&workspace, &plan)? {
                return Ok(false);
            }
            record.outcome = Outcome::Changed;
            startup_runtime(&mut record);
        }
        (Phase::Applying, Kind::Install) => {
            let Some(plan) = &contents[3] else {
                return Ok(false);
            };
            if !complete_install(&decode_install(&record, plan)?)? {
                return Ok(false);
            }
            record.outcome = Outcome::Changed;
            startup_runtime(&mut record);
        }
        (Phase::Applying, Kind::Remove) => {
            let source = contents[2].take();
            let (Some(plan), Some(source)) = (&contents[3], source) else {
                return Ok(false);
            };
            let removal = decode_removal(&record, plan)?;
            if !complete_removal(configuration, &removal, source)? {
                return Ok(false);
            }
            record.outcome = Outcome::Changed;
            record.runtime = Runtime::Removed;
        }
        (Phase::Committed, Kind::Remove) => {
            record.outcome = Outcome::Changed;
            record.runtime = Runtime::Removed;
        }
        (Phase::Committed, Kind::Startup | Kind::Model | Kind::Profile | Kind::Install) => {
            record.outcome = Outcome::Changed;
            startup_runtime(&mut record);
        }
        // The relaunched scope did not survive this boot.
        (Phase::Activating, Kind::Startup | Kind::Model | Kind::Profile | Kind::Install) => {
            record.outcome = Outcome::Changed;
            record.runtime = Runtime::ResumeFailed;
        }
        _ => return Ok(false),
    }
    record.phase = Phase::Completed;
    store.publish_terminal(record, &mut touched)?;
    store.retire()?;
    Ok(true)
}

#[cfg(test)]
fn checkpoint(member: &str, phase: &str) -> Result<()> {
    // An emulated later boot does not inherit this process's fault injection.
    if super::super::TEST_BOOT.with(std::cell::Cell::get).is_some() {
        return Ok(());
    }
    let point = format!("{member}-{phase}");
    if std::env::var("NANOKVM_PICO_ACCEPT_FAIL").as_deref() == Ok(point.as_str()) {
        return Err(invalid());
    }
    if std::env::var("NANOKVM_PICO_ACCEPT_POINT").as_deref() == Ok(point.as_str()) {
        println!("pico-accept-checkpoint-ready");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
    Ok(())
}
