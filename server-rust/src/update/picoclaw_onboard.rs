//! Import a completed one-shot's fresh workspace, never run upstream onboarding
//! against the installed credential pair or a user's existing workspace.
use super::*;
use std::path::PathBuf;

use crate::native_owner::picoclaw_home::ONBOARD_DIRECTORY as STAGE;
/// Binds the fixed stage name to exactly one durable broker Onboard job.
const MARKER: &str = ".nanokvm-onboard-job";
const MAX_MARKER: usize = 256;
const MAX_ENTRIES: usize = 256;
const MAX_TOTAL: usize = 8 * 1024 * 1024;
const MAX_DEPTH: usize = 12;
const GENERATED: [(&str, &[u8], bool); 3] = [
    (
        "AGENT.md",
        include_bytes!("../../../kvmapp/picoclaw/AGENT_KVM.md"),
        false,
    ),
    (
        "skills/kvm-control/SKILL.md",
        include_bytes!("../../../kvmapp/picoclaw/skills/kvm-control/SKILL.md"),
        false,
    ),
    (
        "skills/kvm-control/scripts/nanokvm-bridge.sh",
        include_bytes!("../../../kvmapp/picoclaw/skills/kvm-control/scripts/nanokvm-bridge.sh"),
        true,
    ),
];

pub(crate) struct Onboarding {
    home: Directory,
    stage: Directory,
    path: PathBuf,
    #[cfg(test)]
    fail_after_member: Option<usize>,
}

struct Artifact {
    name: String,
    bytes: Zeroizing<Vec<u8>>,
    generated: bool,
    executable: bool,
}

fn child(parent: &Directory, name: &str, create: bool) -> Result<Directory> {
    parent.check()?;
    let file =
        match restore_fs::open_beneath(&parent.file, name, OFlags::RDONLY | OFlags::DIRECTORY) {
            Ok(file) => file,
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                match mkdirat(&parent.file, name, Mode::from_raw_mode(0o700)) {
                    Ok(()) => parent.file.sync_all()?,
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(std::io::Error::from(error).into()),
                }
                restore_fs::open_beneath(&parent.file, name, OFlags::RDONLY | OFlags::DIRECTORY)?
            }
            Err(error) => return Err(error.into()),
        };
    let directory = Directory {
        file,
        device: parent.device,
    };
    directory.check()?;
    Ok(directory)
}

// The name a job's stage has while it is created or retired, unique to the
// job: the fixed stage name only ever exists carrying exactly its marker.
fn side_name(marker: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    let mut name = String::with_capacity(STAGE.len() + 33);
    name.push_str(STAGE);
    name.push('-');
    for byte in &Sha256::digest(marker)[..16] {
        let _ = write!(name, "{byte:02x}");
    }
    name
}

// Remove a tree under a job's side name: every entry by a bounded walk, then
// the directory. The name binds it to the job; its marker is absent before it
// is written and once the walk has removed it.
fn remove_side(home: &Directory, side: &str, stage: &Directory) -> Result<()> {
    let named = child(home, side, false)?;
    if Revision::from(&named.file.metadata()?) != Revision::from(&stage.file.metadata()?) {
        return Err(invalid());
    }
    let mut visited = 0;
    for name in names(stage)? {
        remove_entry(stage, &name, 0, &mut visited)?;
    }
    stage.file.sync_all()?;
    #[cfg(test)]
    fail_at("side-emptied")?;
    unlinkat(&home.file, side, AtFlags::REMOVEDIR).map_err(std::io::Error::from)?;
    home.file.sync_all()?;
    Ok(())
}

// Fault injection at one point of a job's stage lifecycle; an emulated later
// boot does not inherit it.
#[cfg(test)]
fn fail_at(point: &str) -> Result<()> {
    if super::jobs::TEST_BOOT.with(std::cell::Cell::get).is_none()
        && std::env::var("NANOKVM_PICO_ACCEPT_FAIL").as_deref() == Ok(point)
    {
        return Err(invalid());
    }
    Ok(())
}

// One entry of a job's own stage, removed without following any link.
fn remove_entry(
    directory: &Directory,
    name: &str,
    depth: usize,
    visited: &mut usize,
) -> Result<()> {
    *visited += 1;
    if depth > MAX_DEPTH || *visited > 4 * MAX_ENTRIES {
        return Err(invalid());
    }
    let stat = rustix::fs::statat(&directory.file, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(std::io::Error::from)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory {
        let nested = child(directory, name, false)?;
        for entry in names(&nested)? {
            remove_entry(&nested, &entry, depth + 1, visited)?;
        }
        nested.file.sync_all()?;
        unlinkat(&directory.file, name, AtFlags::REMOVEDIR).map_err(std::io::Error::from)?;
    } else {
        unlinkat(&directory.file, name, AtFlags::empty()).map_err(std::io::Error::from)?;
    }
    Ok(())
}

fn names(directory: &Directory) -> Result<Vec<String>> {
    directory.check()?;
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(&directory.file).map_err(std::io::Error::from)? {
        let entry = entry.map_err(std::io::Error::from)?;
        let name = entry.file_name().to_str().map_err(|_| invalid())?;
        if matches!(name, "." | "..") {
            continue;
        }
        if names.len() == MAX_ENTRIES {
            return Err(invalid());
        }
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

// Workspace files may be executable/readable (upstream emits 0644), but never
// writable by another UID, hardlinked, special, symlinked or on a nested mount.
fn read_artifact(directory: &Directory, name: &str) -> Result<Option<(File, Zeroizing<Vec<u8>>)>> {
    directory.check()?;
    let file =
        match restore_fs::open_beneath(&directory.file, name, OFlags::RDONLY | OFlags::NONBLOCK) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.dev() != directory.device
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
        || metadata.len() > MAX_FILE_BYTES as u64
    {
        return Err(invalid());
    }
    let before = Revision::from(&metadata);
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize + 1));
    (&file)
        .take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.bytes || Revision::from(&file.metadata()?) != before {
        return Err(invalid());
    }
    Ok(Some((file, bytes)))
}

fn collect(
    directory: &Directory,
    prefix: &str,
    depth: usize,
    out: &mut Vec<Artifact>,
    total: &mut usize,
    visited: &mut usize,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(invalid());
    }
    for name in names(directory)? {
        *visited += 1;
        if *visited > MAX_ENTRIES {
            return Err(invalid());
        }
        let relative = format!("{prefix}{name}");
        if relative.len() > 1024 || out.len() == MAX_ENTRIES {
            return Err(invalid());
        }
        let pinned = restore_fs::open_beneath(&directory.file, &name, OFlags::PATH)?;
        let metadata = pinned.metadata()?;
        if metadata.is_dir() {
            collect(
                &child(directory, &name, false)?,
                &format!("{relative}/"),
                depth + 1,
                out,
                total,
                visited,
            )?;
        } else {
            let (_, bytes) = read_artifact(directory, &name)?.ok_or_else(invalid)?;
            *total = total.checked_add(bytes.len()).ok_or_else(invalid)?;
            if *total > MAX_TOTAL {
                return Err(invalid());
            }
            out.push(Artifact {
                name: relative,
                bytes,
                generated: false,
                executable: metadata.mode() & 0o100 != 0,
            });
        }
    }
    Ok(())
}

fn destination_directory(
    workspace: &Directory,
    path: &str,
    create: bool,
) -> Result<Option<(Directory, String)>> {
    let mut parts = path.split('/').peekable();
    let mut directory = Directory {
        file: workspace.file.try_clone()?,
        device: workspace.device,
    };
    while let Some(part) = parts.next() {
        if part.is_empty() || matches!(part, "." | "..") {
            return Err(invalid());
        }
        if parts.peek().is_none() {
            return Ok(Some((directory, part.to_owned())));
        }
        directory = match child(&directory, part, create) {
            Ok(directory) => directory,
            Err(AppError::Io(error)) if !create && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
    }
    Err(invalid())
}

impl Onboarding {
    /// Fixed derived scratch path; no client-supplied staging location.
    pub(crate) fn path(home: &Path) -> PathBuf {
        home.join(STAGE)
    }

    /// An unmarked stage for the import tests; production stages come only
    /// from a broker Onboard job. An orphan scratch directory is preserved
    /// and refused, never adopted.
    #[cfg(all(test, feature = "sandbox-test-fixture"))]
    pub(crate) fn prepare(_permit: &ConfigPermit, path: &Path) -> Result<Option<Self>> {
        if path.file_name().and_then(|name| name.to_str()) != Some(CONFIG) {
            return Err(invalid());
        }
        let home_path = path.parent().ok_or_else(invalid)?;
        let home = Directory::open(home_path, true)?;
        home.lock(false)?;
        pair::recover(&home)?;
        if home.inspect(CONFIG)?.is_some() {
            // Existing credentials are a strict no-op, not a reset/re-onboard.
            let documents = pair::read_installed(&home)?;
            let config: serde_json::Value =
                serde_json::from_slice(&documents.config).map_err(|_| invalid())?;
            if !config.is_object() {
                return Err(invalid());
            }
            if let Some(security) = documents.security {
                let _: serde_yaml::Value =
                    serde_yaml::from_slice(&security).map_err(|_| invalid())?;
            }
            return Ok(None);
        }
        if home.inspect(SECURITY)?.is_some() {
            return Err(invalid());
        }
        mkdirat(&home.file, STAGE, Mode::from_raw_mode(0o700)).map_err(std::io::Error::from)?;
        home.file.sync_all()?;
        let stage = child(&home, STAGE, false)?;
        stage.file.sync_all()?;
        Ok(Some(Self {
            home,
            stage,
            path: Self::path(home_path),
            #[cfg(test)]
            fail_after_member: None,
        }))
    }

    /// Create the stage of a broker Onboard job. The caller holds Update,
    /// Config and the exclusive lease of `home`, proved the pair and any stage
    /// absent and made Applying durable. The stage is built under this job's
    /// side name and takes the fixed name only once its marker is durable,
    /// before the one-shot can write anything into it.
    pub(super) fn stage_for_job(home: &Directory, home_path: &Path, marker: &[u8]) -> Result<Self> {
        if marker.is_empty() || marker.len() > MAX_MARKER {
            return Err(invalid());
        }
        let home = Directory {
            file: home.file.try_clone()?,
            device: home.device,
        };
        home.check()?;
        if home.inspect(CONFIG)?.is_some() || home.inspect(SECURITY)?.is_some() {
            return Err(invalid());
        }
        let side = side_name(marker);
        mkdirat(&home.file, side.as_str(), Mode::from_raw_mode(0o700))
            .map_err(std::io::Error::from)?;
        home.file.sync_all()?;
        #[cfg(test)]
        fail_at("side-created")?;
        let stage = child(&home, &side, false)?;
        let mut temporary = stage.temporary(MAX_MARKER)?;
        temporary.file.write_all(marker)?;
        temporary.file.sync_all()?;
        temporary.publish(MARKER, None)?;
        drop(temporary);
        stage.file.sync_all()?;
        #[cfg(test)]
        fail_at("side-marked")?;
        renameat_with(
            &home.file,
            side.as_str(),
            &home.file,
            STAGE,
            RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        home.file.sync_all()?;
        Ok(Self {
            home,
            stage,
            path: Self::path(home_path),
            #[cfg(test)]
            fail_after_member: None,
        })
    }

    /// Settle exactly this job's stage at a later boot: a stage carrying this
    /// job's marker, or a tree under this job's side name, is retired. A stage
    /// without exactly this marker, or both names at once, refuses and is kept.
    pub(super) fn recover_for_job(home: &Directory, home_path: &Path, marker: &[u8]) -> Result<()> {
        let side = side_name(marker);
        let leftover = match child(home, &side, false) {
            Ok(directory) => Some(directory),
            Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        match (Self::reopen_for_job(home, home_path, marker)?, leftover) {
            (Some(stage), None) => stage.retire(marker),
            (None, Some(stage)) => remove_side(home, &side, &stage),
            (None, None) => Ok(()),
            (Some(_), Some(_)) => Err(invalid()),
        }
    }

    /// Exactly this job's stage after an interruption: `None` when absent. A
    /// stage without exactly this marker is never adopted and refuses.
    fn reopen_for_job(home: &Directory, home_path: &Path, marker: &[u8]) -> Result<Option<Self>> {
        let home = Directory {
            file: home.file.try_clone()?,
            device: home.device,
        };
        let stage = match child(&home, STAGE, false) {
            Ok(stage) => stage,
            Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if stage
            .read_bounded(MARKER, MAX_MARKER)?
            .as_deref()
            .map(Vec::as_slice)
            != Some(marker)
        {
            return Err(AppError::Conflict(
                "picoclaw onboarding stage belongs to no job".into(),
            ));
        }
        Ok(Some(Self {
            home,
            stage,
            path: Self::path(home_path),
            #[cfg(test)]
            fail_after_member: None,
        }))
    }

    /// Remove exactly this job's stage after its import or abort. The fixed
    /// name goes first and atomically, renamed to this job's side name; the
    /// side tree then goes by a bounded walk. Each step is synced.
    pub(super) fn retire(self, marker: &[u8]) -> Result<()> {
        let named = child(&self.home, STAGE, false)?;
        if Revision::from(&named.file.metadata()?) != Revision::from(&self.stage.file.metadata()?)
            || self
                .stage
                .read_bounded(MARKER, MAX_MARKER)?
                .as_deref()
                .map(Vec::as_slice)
                != Some(marker)
        {
            return Err(invalid());
        }
        let side = side_name(marker);
        renameat_with(
            &self.home.file,
            STAGE,
            &self.home.file,
            side.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        self.home.file.sync_all()?;
        #[cfg(test)]
        fail_at("stage-renamed")?;
        remove_side(&self.home, &side, &self.stage)
    }

    #[cfg(all(test, feature = "sandbox-test-fixture"))]
    pub(crate) fn fail_after_member(&mut self, count: usize) {
        assert!(count != 0);
        self.fail_after_member = Some(count);
    }

    /// Only call after receipt + owner reap + EOF, never on a child exit alone.
    /// The pair is published LAST. Default templates never overwrite user data;
    /// generated assets either match exactly or require explicit migration.
    /// Borrow the retained stage: neither success nor Err consumes its leases.
    pub(crate) fn finish(&mut self, permit: &ConfigPermit) -> Result<()> {
        let named = child(&self.home, STAGE, false)?;
        if Revision::from(&named.file.metadata()?) != Revision::from(&self.stage.file.metadata()?) {
            return Err(invalid());
        }
        for name in names(&self.stage)? {
            if !matches!(name.as_str(), CONFIG | SECURITY | "workspace" | MARKER) {
                return Err(invalid());
            }
        }
        let documents = pair::read_installed(&self.stage)?;
        let mut config: serde_json::Value =
            serde_json::from_slice(&documents.config).map_err(|_| invalid())?;
        let defaults = config
            .pointer_mut("/agents/defaults")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(invalid)?;
        if defaults
            .get("workspace")
            .and_then(serde_json::Value::as_str)
            != self.path.join("workspace").to_str()
        {
            return Err(invalid());
        }
        let home_path = self.path.parent().ok_or_else(invalid)?;
        defaults.insert(
            "workspace".into(),
            serde_json::Value::String(
                home_path
                    .join("workspace")
                    .to_str()
                    .ok_or_else(invalid)?
                    .to_owned(),
            ),
        );
        defaults.insert(
            "restrict_to_workspace".into(),
            serde_json::Value::Bool(true),
        );
        defaults.insert(
            "allow_read_outside_workspace".into(),
            serde_json::Value::Bool(false),
        );
        if let Some(security) = &documents.security {
            let value: serde_yaml::Value =
                serde_yaml::from_slice(security).map_err(|_| invalid())?;
            if !value.is_mapping() {
                return Err(invalid());
            }
        }
        let encoded = Zeroizing::new(serde_json::to_vec_pretty(&config).map_err(|_| invalid())?);
        if encoded.len() > MAX_FILE_BYTES {
            return Err(invalid());
        }
        let source = child(&self.stage, "workspace", false)?;
        let mut artifacts = Vec::new();
        collect(&source, "", 0, &mut artifacts, &mut 0, &mut 0)?;
        artifacts.retain(|item| !GENERATED.iter().any(|(name, _, _)| item.name == *name));
        for (name, bytes, executable) in GENERATED {
            artifacts.push(Artifact {
                name: name.into(),
                bytes: Zeroizing::new(bytes.to_vec()),
                generated: true,
                executable,
            });
        }
        let existing_workspace = match child(&self.home, "workspace", false) {
            Ok(directory) => Some(directory),
            Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        // Read-only preflight: even empty directories must not be created
        // before a later custom generated-file collision is discovered.
        if let Some(workspace) = &existing_workspace {
            for item in &artifacts {
                let Some((directory, name)) = destination_directory(workspace, &item.name, false)?
                else {
                    continue;
                };
                if let Some((_, bytes)) = read_artifact(&directory, &name)?
                    && item.generated
                    && bytes.as_slice() != item.bytes.as_slice()
                {
                    return Err(AppError::Conflict(
                        "custom Pico workspace asset requires explicit migration".into(),
                    ));
                }
            }
        }
        if self.home.inspect(CONFIG)?.is_some() || self.home.inspect(SECURITY)?.is_some() {
            return Err(invalid());
        }
        let workspace = match existing_workspace {
            Some(directory) => directory,
            None => child(&self.home, "workspace", true)?,
        };
        for item in &artifacts {
            let (directory, name) =
                destination_directory(&workspace, &item.name, true)?.ok_or_else(invalid)?;
            let file = match read_artifact(&directory, &name)? {
                Some((file, bytes)) => {
                    if !item.generated {
                        continue;
                    }
                    if bytes.as_slice() != item.bytes.as_slice() {
                        return Err(invalid());
                    }
                    file
                }
                None => {
                    let mut temporary = directory.temporary(MAX_FILE_BYTES)?;
                    temporary.file.write_all(&item.bytes)?;
                    temporary.file.sync_all()?;
                    temporary.publish(&name, None)?;
                    temporary.file.try_clone()?
                }
            };
            rustix::fs::fchmod(
                &file,
                Mode::from_raw_mode(if item.executable { 0o700 } else { 0o600 }),
            )
            .map_err(std::io::Error::from)?;
            file.sync_all()?;
            directory.file.sync_all()?;
            #[cfg(test)]
            if let Some(remaining) = self.fail_after_member.as_mut() {
                *remaining -= 1;
                if *remaining == 0 {
                    self.fail_after_member = None;
                    return Err(std::io::Error::other("fixture interrupted onboard import").into());
                }
            }
        }
        // The caller still owns both admissions and the home flock here.
        let _ = permit;
        pair::publish(
            &self.home,
            &encoded,
            documents.security.as_deref().map(|s| s.as_slice()),
        )
        // The stage stays for the caller: a broker Onboard job retires it only
        // after its durable Committed.
    }
}
