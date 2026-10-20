//! Retained-owner support preparation and exact-pair exchange.
//!
//! Current transition epoch zero refuses preparation before namespace mutation.
//! The private staging core allocates all nine anonymous successors before a
//! durable plan, then links only those recorded inodes. No Drop-based cleanup,
//! generic orphan adoption, process launch or implicit app publication exists.
//! Recovery composes this journal under the retained native/update/writer fence.
//! Epoch0 stays until the complete protocol and acceptance gates are implemented.

use super::{AcceptedInstall, Identity, Phase as AppPhase, Record, Result, SlotError, Store};
use crate::{
    native_owner::broker::app_install::ClosedRuntime,
    update::{
        app_space::Capacity, boot_script_catalog, helper_family, restore_binding, restore_fs,
        support_abi_catalog,
    },
};
use rustix::fs::{
    AtFlags, Mode, OFlags, PROC_SUPER_MAGIC, RenameFlags, ResolveFlags, fchmod, fstatfs, linkat,
    mkdirat, openat2, renameat, renameat_with,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, Metadata},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt},
    },
};

const COUNT: usize = 9;
const DIRECTORY: &str = "application-support";
const PLAN: &str = "plan";
const NEXT: &str = "plan-next";
const NAMES: [&str; COUNT] = [
    "member-0", "member-1", "member-2", "member-3", "member-4", "member-5", "member-6", "member-7",
    "member-8",
];

#[path = "app_slot_support_record.rs"]
mod record;
use record::{Entry, Object, Phase as SupportPhase, Placement, Plan};
#[path = "app_slot_support_settle.rs"]
mod settlement;

/// Borrowing the accepted owner keeps its update/store/writer admission alive.
/// The closure token comes only from the SAME drained native install session.
/// No method here starts consumers or publishes/commits the app.
pub struct Prepared<'a> {
    install: &'a mut AcceptedInstall,
    closed: ClosedRuntime,
    directories: Directories,
    plan: Plan,
}

impl Prepared<'_> {
    /// Revalidate the exact fully linked preparation; this is not trial health.
    pub fn check(&self) -> Result<()> {
        prepared_record(self.install, &self.closed)?;
        self.directories.check(&self.install._store)?;
        let actual = load_plan(&self.directories, &self.install._store, PLAN)?;
        if actual != self.plan || actual.phase != SupportPhase::Ready {
            return Err(SlotError::Invalid);
        }
        let layout = inspect_layout(&self.directories, &self.install._store, &actual)?;
        if layout != [Placement::OldNew; COUNT] {
            return Err(SlotError::Invalid);
        }
        actual.check_layout(AppPhase::Prepared, &layout)
    }

    /// Forward-only support exchange while this same native session is drained.
    /// Errors retain this guard; a retry inspects exact inode pairs rather than
    /// repeating a rename whose outcome might already have been successful.
    pub fn exchange(&mut self) -> Result<()> {
        let record = accepted_context(self.install, &self.closed, &self.plan)?;
        if record.phase != AppPhase::Prepared {
            return Err(SlotError::Invalid);
        }
        self.ready_plan()?;
        reconcile_pairs(
            &self.install._store,
            &self.directories,
            &self.plan,
            Direction::New,
        )?;
        self.check_exchanged()
    }

    /// No process launch or app-health acknowledgement is supplied by this check.
    pub fn check_exchanged(&self) -> Result<()> {
        let record = accepted_context(self.install, &self.closed, &self.plan)?;
        self.ready_plan()?;
        let layout = inspect_layout(&self.directories, &self.install._store, &self.plan)?;
        self.plan.check_layout(record.phase, &layout)?;
        if layout != [Placement::NewOld; COUNT] {
            return Err(SlotError::Invalid);
        }
        Ok(())
    }

    /// Restore only this recorded uncommitted predecessor under the retained
    /// closure. Canonical app Committed is never an old-family selector.
    pub fn restore_predecessor(&mut self) -> Result<()> {
        let record = accepted_context(self.install, &self.closed, &self.plan)?;
        if record.phase == AppPhase::Committed {
            return Err(SlotError::Invalid);
        }
        self.ready_plan()?;
        reconcile_pairs(
            &self.install._store,
            &self.directories,
            &self.plan,
            Direction::Old,
        )
    }

    fn ready_plan(&self) -> Result<()> {
        self.directories.check(&self.install._store)?;
        let actual = load_plan(&self.directories, &self.install._store, PLAN)?;
        if actual != self.plan || actual.phase != SupportPhase::Ready {
            return Err(SlotError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Direction {
    Old,
    New,
}

fn normalized(mut record: Record) -> Record {
    record.phase = AppPhase::Prepared;
    record
}

fn bound_record(store: &Store, plan: &Plan) -> Result<Record> {
    let record = store.record()?;
    if normalized(record.clone()) != plan.app {
        return Err(SlotError::Invalid);
    }
    store.layout(&record)?;
    Ok(record)
}

fn accepted_context(
    install: &AcceptedInstall,
    closed: &ClosedRuntime,
    plan: &Plan,
) -> Result<Record> {
    if closed.transaction() != install.transaction()
        || normalized(install.record.clone()) != plan.app
    {
        return Err(SlotError::Invalid);
    }
    bound_record(&install._store, plan)
}

/// No path, manifest, live-version override or root-peer shortcut is accepted.
/// Unsupported ABI refuses BEFORE creating the private support directory.
pub(crate) fn prepare(
    install: &mut AcceptedInstall,
    closed: ClosedRuntime,
) -> Result<Prepared<'_>> {
    let sources = Sources::open(install, &closed)?;
    support_abi_catalog::check_transition(&sources.old.abi, &sources.new.abi)
        .map_err(|_| SlotError::Invalid)?;
    stage(install, closed, sources)
}

fn maximum(index: usize) -> u64 {
    match index {
        0 => restore_binding::MAX_HELPER,
        1..=4 => restore_binding::MAX_NATIVE_HELPER,
        _ => super::super::boot_script_binding::MAX_SCRIPT as u64,
    }
}

fn live_name(index: usize) -> &'static str {
    if index < 5 {
        helper_family::ROLES[index].filename()
    } else {
        boot_script_catalog::ROLES[index - 5].filename()
    }
}

fn prepared_record(install: &AcceptedInstall, closed: &ClosedRuntime) -> Result<Record> {
    let store = &install._store;
    let record = store.record()?;
    let layout = store.layout(&record)?;
    if closed.transaction() != install.transaction()
        || record != install.record
        || record.phase != AppPhase::Prepared
        || layout.live != Some(record.old)
        || layout.new != Some(record.new)
        || layout.old.is_some()
    {
        return Err(SlotError::Invalid);
    }
    Ok(record)
}

#[derive(Clone)]
struct Spec {
    start: u64,
    size: u64,
    sha256: [u8; 32],
}

struct Source {
    root: File,
    backend: File,
    stamp: [u64; 11],
    specs: [Spec; COUNT],
    abi: support_abi_catalog::Catalog,
}

struct Sources {
    old: Source,
    new: Source,
}

impl Sources {
    fn open(install: &AcceptedInstall, closed: &ClosedRuntime) -> Result<Self> {
        let record = prepared_record(install, closed)?;
        let old = restore_fs::open_beneath(
            &install._store.rootfs,
            "kvmapp",
            OFlags::RDONLY | OFlags::DIRECTORY,
        )?;
        let new = restore_fs::open_beneath(
            &install._store.current,
            "new",
            OFlags::RDONLY | OFlags::DIRECTORY,
        )?;
        Ok(Self {
            old: Source::open(old, record.old, &install._store)?,
            new: Source::open(new, record.new, &install._store)?,
        })
    }
    fn check(&self, install: &AcceptedInstall, closed: &ClosedRuntime) -> Result<()> {
        prepared_record(install, closed)?;
        self.old.check(&install._store)?;
        self.new.check(&install._store)
    }
}

impl Source {
    fn open(root: File, identity: Identity, store: &Store) -> Result<Self> {
        if Identity::of(&root, store.device, store.uid)? != identity {
            return Err(SlotError::Invalid);
        }
        let server = pin_directory(&root, "server", store, false)?;
        let backend = open_regular(&server, "NanoKVM-Server", store, 0o755, None)?;
        let metadata = backend.metadata()?;
        let stamp = metadata_stamp(&metadata);
        let size = metadata.len();
        if size > helper_family::MAX_BACKEND_BYTES {
            return Err(SlotError::Invalid);
        }
        let helpers = helper_family::inspect(&backend)?;
        let scripts = boot_script_catalog::inspect_in_family(&backend, size, &helpers)?;
        let abi = support_abi_catalog::inspect_in_catalogs(&backend, size, &helpers, &scripts)?;
        let specs = std::array::from_fn(|index| {
            if index < 5 {
                let member = &helpers.members()[index];
                Spec {
                    start: member.image_range().start,
                    size: member.size(),
                    sha256: *member.sha256(),
                }
            } else {
                let member = &scripts.members()[index - 5];
                Spec {
                    start: member.payload_range().start,
                    size: member.size(),
                    sha256: *member.sha256(),
                }
            }
        });
        let source = Self {
            root,
            backend,
            stamp,
            specs,
            abi,
        };
        source.check(store)?;
        Ok(source)
    }
    fn check(&self, store: &Store) -> Result<()> {
        super::protected_directory(&self.root, store.device, store.uid, false)?;
        let parent = pin_directory(&self.root, "server", store, false)?;
        let named = open_regular(&parent, "NanoKVM-Server", store, 0o755, None)?;
        if metadata_stamp(&named.metadata()?) != self.stamp
            || metadata_stamp(&self.backend.metadata()?) != self.stamp
        {
            return Err(SlotError::Invalid);
        }
        Ok(())
    }
}

struct Directories {
    config: File,
    support: File,
    executable: File,
    init: File,
    identities: [Identity; 7],
}

impl Directories {
    fn existing(store: &Store) -> Result<Option<Self>> {
        let config = match pin_directory(&store.rootfs, "etc/kvm", store, false) {
            Ok(config) => config,
            Err(SlotError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let directory = match restore_fs::open_beneath(
            &config,
            DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY,
        ) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        super::protected_directory(&directory, store.device, store.uid, true)?;
        if inventory(&directory)? == 0 {
            // The support plan is deleted before app archival. Recovery may
            // now select an archived current inode through its durable intent,
            // so a clear support namespace must not require a current name.
            directory.sync_all()?;
            let again_config = pin_directory(&store.rootfs, "etc/kvm", store, false)?;
            let again = pin_directory(&again_config, DIRECTORY, store, true)?;
            if Identity::of(&again_config, store.device, store.uid)?
                != Identity::of(&config, store.device, store.uid)?
                || Identity::of(&again, store.device, store.uid)?
                    != Identity::of(&directory, store.device, store.uid)?
                || inventory(&again)? != 0
            {
                return Err(SlotError::Invalid);
            }
            return Ok(None);
        }
        Ok(Some(Self::open_mode(store, false)?))
    }

    fn open_mode(store: &Store, create: bool) -> Result<Self> {
        let config = pin_directory(&store.rootfs, "etc/kvm", store, false)?;
        let executable = pin_directory(&store.rootfs, "usr/libexec", store, false)?;
        let init = pin_directory(&store.rootfs, "etc/init.d", store, false)?;
        let support = match restore_fs::open_beneath(
            &config,
            DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                let capacity = Capacity::read(&config)?;
                capacity.ensure(capacity.unit * 2, 1)?;
                let created = match mkdirat(&config, DIRECTORY, Mode::from_raw_mode(0o700)) {
                    Ok(()) => true,
                    Err(rustix::io::Errno::EXIST) => false,
                    Err(error) => return Err(error.into()),
                };
                let file = restore_fs::open_beneath(
                    &config,
                    DIRECTORY,
                    OFlags::RDONLY | OFlags::DIRECTORY,
                )?;
                super::protected_directory(&file, store.device, store.uid, false)?;
                if created {
                    fchmod(&file, Mode::from_raw_mode(0o700))?;
                }
                file
            }
            Err(error) => return Err(error.into()),
        };
        super::protected_directory(&support, store.device, store.uid, true)?;
        let identities = [
            Identity::of(&store.rootfs, store.device, store.uid)?,
            Identity::of(&store._lock.0, store.device, store.uid)?,
            Identity::of(&store.current, store.device, store.uid)?,
            Identity::of(&config, store.device, store.uid)?,
            Identity::of(&support, store.device, store.uid)?,
            Identity::of(&executable, store.device, store.uid)?,
            Identity::of(&init, store.device, store.uid)?,
        ];
        let directories = Self {
            config,
            support,
            executable,
            init,
            identities,
        };
        directories.check(store)?;
        directories.support.sync_all()?;
        directories.config.sync_all()?;
        Ok(directories)
    }
    fn check(&self, store: &Store) -> Result<()> {
        let config = pin_directory(&store.rootfs, "etc/kvm", store, false)?;
        let support = pin_directory(&config, DIRECTORY, store, true)?;
        let executable = pin_directory(&store.rootfs, "usr/libexec", store, false)?;
        let init = pin_directory(&store.rootfs, "etc/init.d", store, false)?;
        let current = pin_directory(&store._lock.0, super::CURRENT, store, true)?;
        let actual = [
            Identity::of(&store.rootfs, store.device, store.uid)?,
            Identity::of(&store._lock.0, store.device, store.uid)?,
            Identity::of(&current, store.device, store.uid)?,
            Identity::of(&config, store.device, store.uid)?,
            Identity::of(&support, store.device, store.uid)?,
            Identity::of(&executable, store.device, store.uid)?,
            Identity::of(&init, store.device, store.uid)?,
        ];
        if actual != self.identities {
            return Err(SlotError::Invalid);
        }
        for (file, expected) in [
            (&self.config, 3),
            (&self.support, 4),
            (&self.executable, 5),
            (&self.init, 6),
        ] {
            if Identity::of(file, store.device, store.uid)? != actual[expected] {
                return Err(SlotError::Invalid);
            }
        }
        Ok(())
    }
    fn live(&self, index: usize) -> &File {
        if index < 5 {
            &self.executable
        } else {
            &self.init
        }
    }
}

fn pin_directory(root: &File, path: &str, store: &Store, private: bool) -> Result<File> {
    // Every ancestor is inspected, not only the final inode opened by openat2.
    super::protected_directory(root, store.device, store.uid, false)?;
    for (index, _) in path.match_indices('/') {
        let parent =
            restore_fs::open_beneath(root, &path[..index], OFlags::RDONLY | OFlags::DIRECTORY)?;
        super::protected_directory(&parent, store.device, store.uid, false)?;
    }
    let directory = restore_fs::open_beneath(root, path, OFlags::RDONLY | OFlags::DIRECTORY)?;
    super::protected_directory(&directory, store.device, store.uid, private)?;
    Ok(directory)
}

fn metadata_stamp(metadata: &Metadata) -> [u64; 11] {
    [
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mode() as u64,
        metadata.uid() as u64,
        metadata.gid() as u64,
        metadata.nlink(),
        metadata.mtime() as u64,
        metadata.mtime_nsec() as u64,
        metadata.ctime() as u64,
        metadata.ctime_nsec() as u64,
    ]
}

fn safe_file(
    file: &File,
    store: &Store,
    mode: u32,
    size: Option<u64>,
    links: u64,
) -> Result<Metadata> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.dev() != store.device
        || metadata.ino() == 0
        || metadata.uid() != store.uid
        || metadata.gid() != store.rootfs.metadata()?.gid()
        || metadata.nlink() != links
        || metadata.mode() & 0o7777 != mode
        || metadata.len() == 0
        || size.is_some_and(|size| size != metadata.len())
    {
        return Err(SlotError::Unsafe);
    }
    Ok(metadata)
}

fn open_regular(
    parent: &File,
    name: &str,
    store: &Store,
    mode: u32,
    size: Option<u64>,
) -> Result<File> {
    let pinned = restore_fs::open_beneath(parent, name, OFlags::PATH)?;
    let identity = metadata_stamp(&safe_file(&pinned, store, mode, size, 1)?);
    let file = restore_fs::open_beneath(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
    if metadata_stamp(&safe_file(&file, store, mode, size, 1)?) != identity {
        return Err(SlotError::Unsafe);
    }
    Ok(file)
}

fn hash_at(file: &File, start: u64, size: u64, mut output: Option<&mut File>) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut offset = 0;
    while offset < size {
        let count = (size - offset).min(buffer.len() as u64) as usize;
        file.read_exact_at(
            &mut buffer[..count],
            start.checked_add(offset).ok_or(SlotError::Invalid)?,
        )?;
        #[cfg(test)]
        if output.is_some() {
            point("source-copy-chunk")?;
        }
        hash.update(&buffer[..count]);
        if let Some(output) = output.as_mut() {
            output.write_all(&buffer[..count])?;
            #[cfg(all(test, feature = "sandbox-test-fixture"))]
            point("source-copy-chunk-written")?;
        }
        offset += count as u64;
    }
    Ok(hash.finalize().into())
}

fn object(file: &File, store: &Store, size: u64, links: u64, sha256: [u8; 32]) -> Result<Object> {
    let m = safe_file(file, store, 0o755, Some(size), links)?;
    Ok(Object {
        identity: Identity {
            device: m.dev(),
            inode: m.ino(),
        },
        size,
        mode: 0o755,
        uid: m.uid(),
        gid: m.gid(),
        sha256,
    })
}

fn named_object(parent: &File, name: &str, store: &Store, expected: Object) -> Result<File> {
    let file = open_regular(parent, name, store, 0o755, Some(expected.size))?;
    let before = metadata_stamp(&file.metadata()?);
    let hash = hash_at(&file, 0, expected.size, None)?;
    if object(&file, store, expected.size, 1, hash)? != expected
        || metadata_stamp(&file.metadata()?) != before
        || metadata_stamp(
            &open_regular(parent, name, store, 0o755, Some(expected.size))?.metadata()?,
        ) != before
    {
        return Err(SlotError::Invalid);
    }
    Ok(file)
}

fn anonymous(parent: &File, mode: u32) -> Result<File> {
    let file: File = openat2(
        parent,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?
    .into();
    #[cfg(all(test, feature = "sandbox-test-fixture"))]
    point("anonymous-created")?;
    fchmod(&file, Mode::from_raw_mode(mode))?;
    Ok(file)
}

fn link_anonymous(file: &File, parent: &File, name: &str) -> Result<()> {
    let procfs = restore_fs::open_root(std::path::Path::new("/proc"), false)?;
    if fstatfs(&procfs)?.f_type != PROC_SUPER_MAGIC {
        return Err(SlotError::Unsafe);
    }
    linkat(
        &procfs,
        format!("self/fd/{}", file.as_raw_fd()),
        parent,
        name,
        AtFlags::SYMLINK_FOLLOW,
    )?;
    Ok(())
}

fn inventory(directory: &File) -> Result<u16> {
    let mut found = 0;
    for entry in rustix::fs::Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        let index = if name == PLAN.as_bytes() {
            COUNT
        } else if name == NEXT.as_bytes() {
            COUNT + 1
        } else {
            NAMES
                .iter()
                .position(|known| known.as_bytes() == name)
                .ok_or(SlotError::Invalid)?
        };
        let bit = 1 << index;
        if found & bit != 0 {
            return Err(SlotError::Invalid);
        }
        found |= bit;
    }
    Ok(found)
}

fn load_plan(directories: &Directories, store: &Store, name: &str) -> Result<Plan> {
    let mut file = open_regular(
        &directories.support,
        name,
        store,
        0o600,
        Some(record::BYTES as u64),
    )?;
    let before = metadata_stamp(&file.metadata()?);
    let mut bytes = [0; record::BYTES];
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0; 1])? != 0 || metadata_stamp(&file.metadata()?) != before {
        return Err(SlotError::Invalid);
    }
    let plan = Plan::decode(&bytes, store.uid, store.rootfs.metadata()?.gid())?;
    if plan.parents != directories.identities
        || metadata_stamp(
            &open_regular(
                &directories.support,
                name,
                store,
                0o600,
                Some(record::BYTES as u64),
            )?
            .metadata()?,
        ) != before
    {
        return Err(SlotError::Invalid);
    }
    Ok(plan)
}

fn publish_plan(
    directories: &Directories,
    store: &Store,
    plan: &Plan,
    predecessor: Option<&Plan>,
) -> Result<()> {
    let capacity = Capacity::read(&directories.support)?;
    let journal = (record::BYTES as u64).div_ceil(capacity.unit) * capacity.unit;
    capacity.ensure(journal + 2 * capacity.unit, 1)?;
    let mut file = anonymous(&directories.support, 0o600)?;
    file.write_all(&plan.encode(store.uid, store.rootfs.metadata()?.gid())?)?;
    file.sync_all()?;
    plan_point(plan.phase, "file-synced")?;
    let name = if predecessor.is_some() { NEXT } else { PLAN };
    let capacity = Capacity::read(&directories.support)?;
    capacity.ensure(2 * capacity.unit, 0)?;
    link_anonymous(&file, &directories.support, name)?;
    if load_plan(directories, store, name)? != *plan
        || open_regular(
            &directories.support,
            name,
            store,
            0o600,
            Some(record::BYTES as u64),
        )?
        .metadata()?
        .ino()
            != file.metadata()?.ino()
    {
        return Err(SlotError::Invalid);
    }
    plan_point(plan.phase, "linked")?;
    directories.support.sync_all()?;
    plan_point(plan.phase, "link-synced")?;
    if let Some(previous) = predecessor {
        if load_plan(directories, store, PLAN)? != *previous {
            return Err(SlotError::Invalid);
        }
        let capacity = Capacity::read(&directories.support)?;
        capacity.ensure(2 * capacity.unit, 0)?;
        renameat(&directories.support, NEXT, &directories.support, PLAN)?;
        plan_point(plan.phase, "renamed")?;
        directories.support.sync_all()?;
        plan_point(plan.phase, "rename-synced")?;
    }
    if load_plan(directories, store, PLAN)? != *plan {
        return Err(SlotError::Invalid);
    }
    Ok(())
}

fn inspect_layout(
    directories: &Directories,
    store: &Store,
    plan: &Plan,
) -> Result<[Placement; COUNT]> {
    let names = inventory(&directories.support)?;
    if names & (1 << COUNT) == 0 || names & (1 << (COUNT + 1)) != 0 {
        return Err(SlotError::Invalid);
    }
    inspect_members(directories, store, plan, names)
}

fn inspect_members(
    directories: &Directories,
    store: &Store,
    plan: &Plan,
    names: u16,
) -> Result<[Placement; COUNT]> {
    let mut layout = [Placement::OldMissing; COUNT];
    for (index, placement) in layout.iter_mut().enumerate() {
        *placement = inspect_pair(directories, store, plan, index, names)?;
    }
    Ok(layout)
}

fn inspect_pair(
    directories: &Directories,
    store: &Store,
    plan: &Plan,
    index: usize,
    names: u16,
) -> Result<Placement> {
    let entry = &plan.entries[index];
    let live = open_regular(
        directories.live(index),
        live_name(index),
        store,
        0o755,
        None,
    )?;
    let live_id = Identity {
        device: live.metadata()?.dev(),
        inode: live.metadata()?.ino(),
    };
    let old = if live_id == entry.old.identity {
        true
    } else if live_id == entry.new.identity {
        false
    } else {
        return Err(SlotError::Invalid);
    };
    named_object(
        directories.live(index),
        live_name(index),
        store,
        if old { entry.old } else { entry.new },
    )?;
    if names & (1 << index) != 0 {
        named_object(
            &directories.support,
            NAMES[index],
            store,
            if old { entry.new } else { entry.old },
        )?;
        Ok(if old {
            Placement::OldNew
        } else {
            Placement::NewOld
        })
    } else {
        Ok(if old {
            Placement::OldMissing
        } else {
            Placement::NewMissing
        })
    }
}

/// Low-level pair engine, not an ownership grant. Only the accepted drained
/// session calls it; recovery must supply its own retained fenced boundary.
/// Every pair is validated before the first mutation and again at completion.
fn reconcile_pairs(
    store: &Store,
    directories: &Directories,
    plan: &Plan,
    direction: Direction,
) -> Result<()> {
    directories.check(store)?;
    if load_plan(directories, store, PLAN)? != *plan || plan.phase != SupportPhase::Ready {
        return Err(SlotError::Invalid);
    }
    let record = bound_record(store, plan)?;
    let initial = inspect_layout(directories, store, plan)?;
    plan.check_layout(record.phase, &initial)?;
    let desired = if direction == Direction::New {
        Placement::NewOld
    } else {
        Placement::OldNew
    };
    for (index, name) in NAMES.iter().enumerate() {
        let record = bound_record(store, plan)?;
        if (direction == Direction::Old && record.phase == AppPhase::Committed)
            || (direction == Direction::New
                && matches!(record.phase, AppPhase::RollingBack | AppPhase::RolledBack))
        {
            return Err(SlotError::Invalid);
        }
        directories.check(store)?;
        if load_plan(directories, store, PLAN)? != *plan {
            return Err(SlotError::Invalid);
        }
        let names = inventory(&directories.support)?;
        if names != (1 << (COUNT + 1)) - 1 {
            return Err(SlotError::Invalid);
        }
        let before = inspect_pair(directories, store, plan, index, names)?;
        let capacity = Capacity::read(&directories.support)?;
        capacity.ensure(2 * capacity.unit, 0)?;
        if before != desired {
            let result = renameat_with(
                directories.live(index),
                live_name(index),
                &directories.support,
                *name,
                RenameFlags::EXCHANGE,
            );
            if let Err(error) = result {
                // Do not infer an unchanged namespace from an error return.
                // Inspect all recorded pairs, retain the owner and report it.
                inspect_layout(directories, store, plan)?;
                return Err(error.into());
            }
            #[cfg(test)]
            exchange_point(direction, index, "renamed")?;
            if inspect_pair(directories, store, plan, index, names)? != desired {
                return Err(SlotError::Invalid);
            }
        }
        // Even an already selected inode needs both barriers on an explicit
        // retry after a prior successful rename or ambiguous fsync result.
        directories.live(index).sync_all()?;
        #[cfg(test)]
        exchange_point(direction, index, "live-synced")?;
        directories.support.sync_all()?;
        #[cfg(test)]
        exchange_point(direction, index, "stage-synced")?;
    }
    let final_record = bound_record(store, plan)?;
    if (direction == Direction::Old && final_record.phase == AppPhase::Committed)
        || (direction == Direction::New
            && matches!(
                final_record.phase,
                AppPhase::RollingBack | AppPhase::RolledBack
            ))
    {
        return Err(SlotError::Invalid);
    }
    directories.check(store)?;
    if load_plan(directories, store, PLAN)? != *plan
        || inspect_layout(directories, store, plan)? != [desired; COUNT]
    {
        return Err(SlotError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
fn exchange_point(direction: Direction, index: usize, step: &str) -> Result<()> {
    point(&format!(
        "{}-{step}-{index}",
        if direction == Direction::New {
            "new"
        } else {
            "old"
        }
    ))
}

fn pending(
    install: &AcceptedInstall,
    closed: &ClosedRuntime,
) -> Result<Option<(Directories, Plan, Record)>> {
    if closed.transaction() != install.transaction() {
        return Err(SlotError::Invalid);
    }
    let Some(directories) = Directories::existing(&install._store)? else {
        return Ok(None);
    };
    if inventory(&directories.support)? == 0 {
        return Ok(None);
    }
    let plan = load_plan(&directories, &install._store, PLAN)?;
    let record = accepted_context(install, closed, &plan)?;
    directories.check(&install._store)?;
    Ok(Some((directories, plan, record)))
}

pub(super) fn before_publish(install: &AcceptedInstall, closed: &ClosedRuntime) -> Result<()> {
    let Some((directories, plan, record)) = pending(install, closed)? else {
        return if crate::update::support_abi::CURRENT.support_transition == 0 {
            Ok(())
        } else {
            Err(SlotError::Invalid)
        };
    };
    if record.phase != AppPhase::Prepared
        || plan.phase != SupportPhase::Ready
        || inspect_layout(&directories, &install._store, &plan)? != [Placement::NewOld; COUNT]
    {
        return Err(SlotError::Invalid);
    }
    Ok(())
}

pub(super) fn before_trial(install: &AcceptedInstall, closed: &ClosedRuntime) -> Result<()> {
    let Some((directories, plan, record)) = pending(install, closed)? else {
        return if crate::update::support_abi::CURRENT.support_transition == 0 {
            Ok(())
        } else {
            Err(SlotError::Invalid)
        };
    };
    if record.phase != AppPhase::Published
        || plan.phase != SupportPhase::Ready
        || inspect_layout(&directories, &install._store, &plan)? != [Placement::NewOld; COUNT]
    {
        return Err(SlotError::Invalid);
    }
    Ok(())
}

pub(super) fn before_rollback(install: &AcceptedInstall, closed: &ClosedRuntime) -> Result<()> {
    let Some((directories, _plan, record)) = pending(install, closed)? else {
        return Ok(());
    };
    if record.phase == AppPhase::Committed {
        return Err(SlotError::Invalid);
    }
    // Only the same retained, drained session may finish its exact pending
    // Ready publication before aborting. Validate accepted context FIRST.
    let plan = settlement::settle_publication(&install._store, &directories)?;
    accepted_context(install, closed, &plan)?;
    reconcile_before_app(&install._store, &directories, &plan)
}

/// Neither a public status nor availability of a file lock grants this boundary.
/// The caller retains native Stopping plus update/store/writer exclusions until
/// support and app recovery, archival, and intent completion are durable.
pub(super) fn recover_before_app(
    store: &Store,
    _native: &crate::native_owner::broker::FencedAppRecovery,
) -> Result<()> {
    let Some(directories) = Directories::existing(store)? else {
        return Ok(());
    };
    let plan = settlement::settle_publication(store, &directories)?;
    reconcile_before_app(store, &directories, &plan)
}

fn reconcile_before_app(store: &Store, directories: &Directories, plan: &Plan) -> Result<()> {
    let record = bound_record(store, plan)?;
    let layout = inspect_layout(directories, store, plan)?;
    match plan.phase {
        SupportPhase::Ready => {
            let direction = if record.phase == AppPhase::Committed {
                Direction::New
            } else {
                Direction::Old
            };
            reconcile_pairs(store, directories, plan, direction)
        }
        SupportPhase::Staging
            if matches!(
                record.phase,
                AppPhase::Prepared | AppPhase::RollingBack | AppPhase::RolledBack
            ) && store.layout(&record)?.live == Some(record.old)
                && layout
                    .iter()
                    .all(|p| matches!(p, Placement::OldNew | Placement::OldMissing)) =>
        {
            Ok(())
        }
        SupportPhase::CleanupOld | SupportPhase::CleanupNew => {
            plan.check_layout(record.phase, &layout)
        }
        _ => Err(SlotError::Invalid),
    }
}

pub(super) fn settle_recovered(
    store: &Store,
    record: &Record,
    _native: &crate::native_owner::broker::FencedAppRecovery,
) -> Result<()> {
    if !matches!(record.phase, AppPhase::Committed | AppPhase::RolledBack)
        || store.record()? != *record
    {
        return Err(SlotError::Invalid);
    }
    settlement::run(store)
}

pub(super) fn settle_terminal(
    install: &AcceptedInstall,
    boundary: &crate::native_owner::broker::app_install::TerminalBoundary,
) -> Result<()> {
    let record = install._store.record()?;
    if boundary.transaction() != install.transaction()
        || boundary.phase() != record.phase
        || !matches!(record.phase, AppPhase::Committed | AppPhase::RolledBack)
        || record != install.record
    {
        return Err(SlotError::Invalid);
    }
    // This boundary comes from the SAME live terminal owner, not a public
    // phase/status. Settlement never exchanges live files or starts consumers.
    settlement::run(&install._store)
}

/// Never retire the app's only recovery context or defer early consumers past
/// any nonempty/torn support namespace.
pub(super) fn require_clear(root: &File, uid: u32) -> Result<()> {
    let device = root.metadata()?.dev();
    super::protected_directory(root, device, uid, false)?;
    let mut parent = root.try_clone()?;
    for name in ["etc", "kvm", DIRECTORY] {
        parent = match restore_fs::open_beneath(&parent, name, OFlags::RDONLY | OFlags::DIRECTORY) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        super::protected_directory(&parent, device, uid, name == DIRECTORY)?;
    }
    if inventory(&parent)? != 0 {
        return Err(SlotError::Invalid);
    }
    Ok(())
}

pub(super) fn require_boot_clear() -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        return Err(SlotError::Unsafe);
    }
    let root = restore_fs::open_root(std::path::Path::new("/"), true)?;
    require_clear(&root, 0)
}

fn required_space(specs: &[Spec; COUNT], first: usize, unit: u64) -> Result<(u64, u64)> {
    if first > COUNT || !(512..=65536).contains(&unit) || !unit.is_power_of_two() {
        return Err(SlotError::Invalid);
    }
    let round = |bytes: u64| {
        bytes
            .checked_add(unit - 1)
            .map(|bytes| bytes / unit * unit)
            .ok_or(SlotError::Invalid)
    };
    // Space for all directory entries and two complete journal inodes even
    // while all payload FDs are anonymous; not a durable filesystem reservation.
    let mut bytes = (COUNT as u64 + 3) * unit + 2 * round(record::BYTES as u64)?;
    for spec in &specs[first..] {
        bytes = bytes
            .checked_add(round(spec.size)?)
            .ok_or(SlotError::Invalid)?;
    }
    Ok((bytes, (COUNT - first) as u64 + 2))
}

fn space(directories: &Directories, specs: &[Spec; COUNT], first: usize) -> Result<()> {
    let capacity = Capacity::read(&directories.support)?;
    let (bytes, inodes) = required_space(specs, first, capacity.unit)?;
    capacity.ensure(bytes, inodes)?;
    Ok(())
}

fn stage(
    install: &mut AcceptedInstall,
    closed: ClosedRuntime,
    sources: Sources,
) -> Result<Prepared<'_>> {
    sources.check(install, &closed)?;
    let store = &install._store;
    let directories = Directories::open_mode(store, true)?;
    if inventory(&directories.support)? != 0 {
        return Err(SlotError::Invalid);
    }
    let mut old_files: [Option<File>; COUNT] = std::array::from_fn(|_| None);
    let mut successors: [Option<File>; COUNT] = std::array::from_fn(|_| None);
    let mut entries = Vec::with_capacity(COUNT);
    for index in 0..COUNT {
        sources.check(install, &closed)?;
        directories.check(store)?;
        space(&directories, &sources.new.specs, index)?;
        let old = &sources.old.specs[index];
        let file = open_regular(
            directories.live(index),
            live_name(index),
            store,
            0o755,
            Some(old.size),
        )?;
        let old_object = object(&file, store, old.size, 1, old.sha256)?;
        named_object(directories.live(index), live_name(index), store, old_object)?;
        file.sync_all()?;
        old_files[index] = Some(file);
        let new = &sources.new.specs[index];
        #[cfg(all(test, feature = "sandbox-test-fixture"))]
        point(&format!("successor-preflight-{index}"))?;
        let mut file = anonymous(&directories.support, 0o755)?;
        let hash = hash_at(&sources.new.backend, new.start, new.size, Some(&mut file))?;
        if hash != new.sha256 {
            #[cfg(test)]
            point("source-copy-hash-mismatch")?;
            return Err(SlotError::Invalid);
        }
        file.sync_all()?;
        let new_object = object(&file, store, new.size, 0, hash)?;
        successors[index] = Some(file);
        entries.push(Entry {
            old: old_object,
            new: new_object,
        });
        #[cfg(test)]
        point(&format!("anonymous-{index}"))?;
    }
    point("predecessor-files-synced")?;
    directories.executable.sync_all()?;
    point("predecessor-executable-synced")?;
    directories.init.sync_all()?;
    point("predecessor-init-synced")?;
    for source in [&sources.old, &sources.new] {
        source.backend.sync_all()?;
        pin_directory(&source.root, "server", store, false)?.sync_all()?;
        source.root.sync_all()?;
    }
    point("source-roots-synced")?;
    sources.check(install, &closed)?;
    directories.check(store)?;
    space(&directories, &sources.new.specs, COUNT)?;
    let mut plan = Plan {
        phase: SupportPhase::Staging,
        app: prepared_record(install, &closed)?,
        parents: directories.identities,
        entries: entries.try_into().map_err(|_| SlotError::Invalid)?,
    };
    plan.validate(store.uid, store.rootfs.metadata()?.gid())?;
    for (index, entry) in plan.entries.iter().enumerate() {
        named_object(directories.live(index), live_name(index), store, entry.old)?;
    }
    publish_plan(&directories, store, &plan, None)?;
    point("staging-durable")?;
    for index in 0..COUNT {
        sources.check(install, &closed)?;
        directories.check(store)?;
        space(&directories, &sources.new.specs, COUNT)?;
        link_anonymous(
            successors[index].as_ref().ok_or(SlotError::Invalid)?,
            &directories.support,
            NAMES[index],
        )?;
        named_object(
            &directories.support,
            NAMES[index],
            store,
            plan.entries[index].new,
        )?;
        #[cfg(test)]
        point(&format!("member-linked-{index}"))?;
        directories.support.sync_all()?;
        #[cfg(test)]
        point(&format!("member-synced-{index}"))?;
    }
    let layout = inspect_layout(&directories, store, &plan)?;
    plan.check_layout(AppPhase::Prepared, &layout)?;
    if layout != [Placement::OldNew; COUNT] {
        return Err(SlotError::Invalid);
    }
    let previous = plan.clone();
    plan.phase = SupportPhase::Ready;
    publish_plan(&directories, store, &plan, Some(&previous))?;
    point("ready-durable")?;
    drop(old_files);
    drop(successors);
    let prepared = Prepared {
        install,
        closed,
        directories,
        plan,
    };
    prepared.check()?;
    Ok(prepared)
}

fn plan_point(phase: SupportPhase, step: &str) -> Result<()> {
    #[cfg(test)]
    {
        let phase = match phase {
            SupportPhase::Staging => "staging",
            SupportPhase::Ready => "ready",
            SupportPhase::CleanupOld => "cleanup-old",
            SupportPhase::CleanupNew => "cleanup-new",
        };
        point(&format!("{phase}-plan-{step}"))?;
    }
    #[cfg(not(test))]
    let _ = (phase, step);
    Ok(())
}

fn point(name: &str) -> Result<()> {
    #[cfg(test)]
    {
        tests::point(name)?;
    }
    #[cfg(not(test))]
    let _ = name;
    Ok(())
}

#[cfg(test)]
#[path = "app_slot_support_tests.rs"]
mod tests;
#[cfg(test)]
pub(crate) use tests::{
    fixture as accepted_fixture, populate_retained_fixture, prepare_retained_fixture,
};

#[cfg(test)]
#[path = "app_slot_support_exchange_tests.rs"]
mod exchange_tests;

#[cfg(all(test, feature = "sandbox-test-fixture"))]
#[path = "app_slot_support_recovery_tests.rs"]
mod recovery_tests;

#[cfg(all(test, feature = "sandbox-test-fixture"))]
#[path = "app_slot_support_capacity_tests.rs"]
mod capacity_tests;
