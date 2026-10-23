//! Filesystem component fixtures, NOT authenticated app/device acceptance.
//! Only this private test child bypasses transition0 to exercise staging I/O.
use super::*;
use crate::update::{app_bootstrap::BOOT_SCRIPTS, support_abi};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

fn write(path: &Path, bytes: &[u8], mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn family(variant: &str) -> Vec<u8> {
    let originals = helper_family::candidate_files_fixture();
    let mut backend = b"synthetic support backend; never executed\n".to_vec();
    for (index, role) in helper_family::ROLES.into_iter().enumerate() {
        let name = format!("kvmapp/system/bin/{}", role.filename());
        let mut image = originals
            .iter()
            .find(|(name_, _)| name_ == &name)
            .unwrap()
            .1
            .clone();
        image.extend_from_slice(variant.as_bytes());
        if index == 0
            && variant == "successor"
            && std::env::var_os("NANOKVM_SUPPORT_MUTATE").is_some()
        {
            image.resize(128 * 1024, b'P');
        }
        image.extend_from_slice(&support_abi::encode(support_abi::ROLES[index + 1]));
        let magic = if index == 0 {
            restore_binding::APP_RECOVERY_MAGIC
        } else {
            restore_binding::NATIVE_RUNTIMES[index - 1].magic()
        };
        backend.extend_from_slice(magic);
        backend.extend_from_slice(&(image.len() as u64).to_le_bytes());
        backend.extend_from_slice(&Sha256::digest(&image));
        backend.extend_from_slice(&image);
    }
    for ((_, body), role) in BOOT_SCRIPTS.iter().zip(boot_script_catalog::ROLES) {
        let mut body = body.to_vec();
        body.extend_from_slice(format!("\n# synthetic support {variant}\n").as_bytes());
        backend.extend_from_slice(role.magic());
        backend.extend_from_slice(&(body.len() as u64).to_le_bytes());
        backend.extend_from_slice(&Sha256::digest(&body));
        backend.extend_from_slice(&body);
    }
    backend.extend_from_slice(&support_abi::encode(support_abi::Role::Backend));
    backend
}

pub(crate) async fn fixture(root: &Path) -> AcceptedInstall {
    let install = super::super::issuer_tests::accepted_fixture(root).await;
    for (path, variant) in [
        (root.join("kvmapp"), "predecessor"),
        (root.join("application-slot/current/new"), "successor"),
    ] {
        write(&path.join("server/NanoKVM-Server"), &family(variant), 0o755);
    }
    for path in ["etc/kvm", "etc/init.d", "usr/libexec"] {
        fs::create_dir_all(root.join(path)).unwrap();
    }
    let source = Source::open(
        File::open(root.join("kvmapp")).unwrap(),
        install._store.record().unwrap().old,
        &install._store,
    )
    .unwrap();
    for (index, spec) in source.specs.iter().enumerate() {
        let mut bytes = vec![0; spec.size as usize];
        source
            .backend
            .read_exact_at(&mut bytes, spec.start)
            .unwrap();
        let parent = if index < 5 {
            "usr/libexec"
        } else {
            "etc/init.d"
        };
        write(&root.join(parent).join(live_name(index)), &bytes, 0o755);
    }
    install
}

fn fixture_directory(parent: &File, path: &str) -> File {
    let mut directory = parent.try_clone().unwrap();
    for component in path.split('/') {
        if let Err(error) = mkdirat(&directory, component, Mode::from_raw_mode(0o755)) {
            assert_eq!(error, rustix::io::Errno::EXIST);
        }
        directory =
            restore_fs::open_beneath(&directory, component, OFlags::RDONLY | OFlags::DIRECTORY)
                .unwrap();
    }
    directory
}

fn fixture_write_at(parent: &File, name: &str, bytes: &[u8]) {
    let mut file = File::from(
        openat2(
            parent,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o755),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .unwrap(),
    );
    fchmod(&file, Mode::from_raw_mode(0o755)).unwrap();
    file.write_all(bytes).unwrap();
}

/// Synthetic data for the engine's retained AcceptedInstall. Use its pinned
/// roots, including fixed-root chroot fixtures; no caller-selected live path.
/// Later installs retain the preceding published family and live inodes.
pub(crate) fn populate_retained_fixture(install: &AcceptedInstall) {
    let store = &install._store;
    let record = store.record().unwrap();
    assert_eq!(record.phase, AppPhase::Prepared);
    let old = restore_fs::open_beneath(&store.rootfs, "kvmapp", OFlags::RDONLY | OFlags::DIRECTORY)
        .unwrap();
    let new = restore_fs::open_beneath(&store.current, "new", OFlags::RDONLY | OFlags::DIRECTORY)
        .unwrap();
    let initial = match restore_fs::open_beneath(&old, "server/NanoKVM-Server", OFlags::RDONLY) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => panic!("fixture predecessor: {error}"),
    };
    if initial {
        fixture_write_at(
            &fixture_directory(&old, "server"),
            "NanoKVM-Server",
            &family("predecessor"),
        );
    }
    let variant = format!(
        "engine-successor-{:032x}",
        u128::from_be_bytes(record.transaction)
    );
    fixture_write_at(
        &fixture_directory(&new, "server"),
        "NanoKVM-Server",
        &family(&variant),
    );
    fixture_directory(&store.rootfs, "etc/kvm");
    let executable = fixture_directory(&store.rootfs, "usr/libexec");
    let init = fixture_directory(&store.rootfs, "etc/init.d");
    if initial {
        let source = Source::open(old, record.old, store).unwrap();
        for (index, spec) in source.specs.iter().enumerate() {
            let mut bytes = vec![0; spec.size as usize];
            source
                .backend
                .read_exact_at(&mut bytes, spec.start)
                .unwrap();
            fixture_write_at(
                if index < 5 { &executable } else { &init },
                live_name(index),
                &bytes,
            );
        }
    }
}

/// Exercise the private filesystem protocol with the caller's real drained
/// Session token. Only the unsupported transition-epoch check is bypassed;
/// source/context, ownership and all staging checks remain unchanged.
pub(crate) fn prepare_retained_fixture(
    install: &mut AcceptedInstall,
    closed: ClosedRuntime,
) -> Result<Prepared<'_>> {
    let _elapsed = diagnostics::Elapsed::start("fixture.prepare-total", None);
    let sources = Sources::open(install, &closed)?;
    match support_abi_catalog::check_transition(&sources.old.abi, &sources.new.abi) {
        Ok(()) | Err(support_abi_catalog::CompatibilityError::UnsupportedTransition) => {}
        Err(support_abi_catalog::CompatibilityError::UnknownOrIncompatible) => {
            return Err(SlotError::Invalid);
        }
    }
    stage(install, closed, sources)
}

#[test]
fn diagnostic_observation_evaluates_the_operation_once_and_preserves_its_error() {
    let mut calls = 0;
    let result: Result<()> = support_operation!("diagnostic-proof", None, {
        calls += 1;
        Err(SlotError::Invalid)
    });
    assert_eq!(calls, 1);
    assert!(matches!(result, Err(SlotError::Invalid)));
}

pub(super) fn support(root: &Path) -> PathBuf {
    root.join("etc/kvm").join(DIRECTORY)
}

pub(super) fn assert_old(root: &Path, plan: &Plan) {
    for (index, entry) in plan.entries.iter().enumerate() {
        let parent = if index < 5 {
            "usr/libexec"
        } else {
            "etc/init.d"
        };
        let path = root.join(parent).join(live_name(index));
        assert_eq!(path.metadata().unwrap().ino(), entry.old.identity.inode);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(fs::read(path).unwrap())),
            entry.old.sha256
        );
    }
}

#[tokio::test]
async fn current_unsupported_transition_refuses_before_private_namespace_creation() {
    let root = tempfile::tempdir().unwrap();
    let mut install = fixture(root.path()).await;
    let closed = ClosedRuntime::fixture(install.transaction());
    assert!(matches!(
        prepare(&mut install, closed),
        Err(SlotError::UnsupportedTransition)
    ));
    assert!(!support(root.path()).exists());
    super::super::issuer_tests::assert_excluded(root.path());
}

#[tokio::test]
async fn nine_real_anonymous_successors_become_one_bound_ready_plan_without_live_writes() {
    let root = tempfile::tempdir().unwrap();
    let mut install = fixture(root.path()).await;
    let closed = ClosedRuntime::fixture(install.transaction());
    let before = install._store.record().unwrap().encode().unwrap();
    let sources = Sources::open(&install, &closed).unwrap();
    let prepared = stage(&mut install, closed, sources).unwrap();
    prepared.check().unwrap();
    assert_eq!(
        inventory(&prepared.directories.support).unwrap(),
        (1 << (COUNT + 1)) - 1
    );
    assert!(prepared.plan.phase == SupportPhase::Ready);
    assert_eq!(prepared.plan.app.encode().unwrap(), before);
    assert_old(root.path(), &prepared.plan);
    for (index, entry) in prepared.plan.entries.iter().enumerate() {
        assert_ne!(entry.old.sha256, entry.new.sha256);
        assert_ne!(entry.old.identity, entry.new.identity);
        named_object(
            &prepared.directories.support,
            NAMES[index],
            &prepared.install._store,
            entry.new,
        )
        .unwrap();
    }
    super::super::issuer_tests::assert_excluded(root.path());
    let plan = prepared.plan.clone();
    drop(prepared);
    assert_eq!(install._store.record().unwrap().encode().unwrap(), before);
    assert_old(root.path(), &plan);
    assert!(support(root.path()).join(PLAN).is_file());
}

#[tokio::test]
async fn foreign_closure_or_changed_canonical_record_cannot_prepare_support() {
    let root = tempfile::tempdir().unwrap();
    let mut install = fixture(root.path()).await;
    let mut transaction = install.transaction();
    transaction[0] ^= 1;
    assert!(Sources::open(&install, &ClosedRuntime::fixture(transaction)).is_err());
    let closed = ClosedRuntime::fixture(install.transaction());
    install.record.version = "999.0.0".into();
    assert!(Sources::open(&install, &closed).is_err());
    assert!(!support(root.path()).exists());
}

#[tokio::test]
async fn changed_pinned_source_late_live_file_and_unknown_support_evidence_are_retained() {
    for kind in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let mut install = fixture(root.path()).await;
        let closed = ClosedRuntime::fixture(install.transaction());
        let sources = Sources::open(&install, &closed).unwrap();
        match kind {
            0 => {
                fs::write(
                    root.path()
                        .join("application-slot/current/new/server/NanoKVM-Server"),
                    b"changed",
                )
                .unwrap();
            }
            1 => {
                fs::write(
                    root.path().join("etc/init.d/S95nanokvm"),
                    b"unknown late live file",
                )
                .unwrap();
            }
            _ => {
                write(
                    &support(root.path()).join("foreign"),
                    b"retain unknown evidence",
                    0o600,
                );
                fs::set_permissions(support(root.path()), fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
        }
        assert!(stage(&mut install, closed, sources).is_err());
        if kind == 2 {
            assert_eq!(
                fs::read(support(root.path()).join("foreign")).unwrap(),
                b"retain unknown evidence"
            );
        } else if support(root.path()).exists() {
            assert_eq!(fs::read_dir(support(root.path())).unwrap().count(), 0);
        }
        assert_eq!(install._store.record().unwrap().phase, AppPhase::Prepared);
    }
}

#[tokio::test]
async fn staged_alias_or_replaced_parent_never_passes_the_retained_ready_check() {
    for kind in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let mut install = fixture(root.path()).await;
        let closed = ClosedRuntime::fixture(install.transaction());
        let sources = Sources::open(&install, &closed).unwrap();
        let prepared = stage(&mut install, closed, sources).unwrap();
        match kind {
            0 => {
                fs::hard_link(
                    support(root.path()).join(NAMES[8]),
                    root.path().join("alias"),
                )
                .unwrap();
            }
            1 => {
                fs::rename(
                    root.path().join("etc/init.d"),
                    root.path().join("etc/previous-init"),
                )
                .unwrap();
                fs::create_dir(root.path().join("etc/init.d")).unwrap();
            }
            _ => {
                fs::remove_file(support(root.path()).join(NAMES[8])).unwrap();
                symlink(
                    root.path().join("etc/init.d/S95nanokvm"),
                    support(root.path()).join(NAMES[8]),
                )
                .unwrap();
            }
        }
        assert!(prepared.check().is_err());
        assert!(support(root.path()).join(PLAN).is_file());
    }
}

#[tokio::test]
async fn fixed_plan_schema_rejects_all_corruption_truncation_and_identity_aliases() {
    let root = tempfile::tempdir().unwrap();
    let mut install = fixture(root.path()).await;
    let closed = ClosedRuntime::fixture(install.transaction());
    let sources = Sources::open(&install, &closed).unwrap();
    let prepared = stage(&mut install, closed, sources).unwrap();
    let uid = prepared.install._store.uid;
    let gid = prepared.install._store.rootfs.metadata().unwrap().gid();
    let bytes = prepared.plan.encode(uid, gid).unwrap();
    assert!(Plan::decode(&bytes, uid, gid).unwrap() == prepared.plan);
    for offset in 0..record::BYTES {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(
            Plan::decode(&changed, uid, gid).is_err(),
            "corruption {offset}"
        );
        assert!(
            Plan::decode(&bytes[..offset], uid, gid).is_err(),
            "truncation {offset}"
        );
    }
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert!(Plan::decode(&extended, uid, gid).is_err());
    // Reach strict decoding with an independently rebuilt outer checksum,
    // rather than stopping only at the damaged-checksum check above.
    let rehash = |bytes: &mut [u8; record::BYTES]| {
        let mut hash = Sha256::new();
        hash.update(b"NanoKVM app support transaction v1\0");
        hash.update(&bytes[..2016]);
        bytes[2016..].copy_from_slice(&hash.finalize());
    };
    for offset in [8, 9, 15, 1936, 2015] {
        let mut changed = bytes;
        changed[offset] = if offset == 8 { 255 } else { 1 };
        rehash(&mut changed);
        assert!(
            Plan::decode(&changed, uid, gid).is_err(),
            "checksummed unknown {offset}"
        );
    }
    for object in 0..COUNT * 2 {
        for reserved in 36..40 {
            let mut changed = bytes;
            changed[640 + object * 72 + reserved] = 1;
            rehash(&mut changed);
            assert!(Plan::decode(&changed, uid, gid).is_err());
        }
    }
    assert!(Plan::decode(&bytes, uid ^ 1, gid).is_err());
    assert!(Plan::decode(&bytes, uid, gid ^ 1).is_err());
    for index in 0..COUNT {
        let mut plan = prepared.plan.clone();
        plan.entries[index].new.identity = plan.entries[index].old.identity;
        assert!(plan.encode(uid, gid).is_err());
        let mut plan = prepared.plan.clone();
        plan.entries[index].new.uid ^= 1;
        assert!(plan.encode(uid, gid).is_err());
        let mut plan = prepared.plan.clone();
        plan.entries[index].new.mode = 0o777;
        assert!(plan.encode(uid, gid).is_err());
    }
}

#[tokio::test]
async fn all_512_subsets_pair_layouts_and_terminal_missing_sets_classify_without_authority() {
    let root = tempfile::tempdir().unwrap();
    let mut install = fixture(root.path()).await;
    let closed = ClosedRuntime::fixture(install.transaction());
    let sources = Sources::open(&install, &closed).unwrap();
    let prepared = stage(&mut install, closed, sources).unwrap();
    for mask in 0..1usize << COUNT {
        let staging = std::array::from_fn(|i| {
            if mask & (1 << i) == 0 {
                Placement::OldMissing
            } else {
                Placement::OldNew
            }
        });
        let ready = std::array::from_fn(|i| {
            if mask & (1 << i) == 0 {
                Placement::NewOld
            } else {
                Placement::OldNew
            }
        });
        let cleanup_new = std::array::from_fn(|i| {
            if mask & (1 << i) == 0 {
                Placement::NewMissing
            } else {
                Placement::NewOld
            }
        });
        let mut plan = prepared.plan.clone();
        plan.phase = SupportPhase::Staging;
        plan.check_layout(AppPhase::Prepared, &staging).unwrap();
        assert!(plan.check_layout(AppPhase::Committed, &staging).is_err());
        plan.phase = SupportPhase::Ready;
        for phase in [
            AppPhase::Prepared,
            AppPhase::Publishing,
            AppPhase::Published,
            AppPhase::Committed,
            AppPhase::RollingBack,
            AppPhase::RolledBack,
        ] {
            plan.check_layout(phase, &ready).unwrap();
        }
        if mask != (1 << COUNT) - 1 {
            assert!(plan.check_layout(AppPhase::Prepared, &staging).is_err());
        }
        plan.phase = SupportPhase::CleanupOld;
        plan.check_layout(AppPhase::RolledBack, &staging).unwrap();
        assert!(plan.check_layout(AppPhase::Committed, &staging).is_err());
        plan.phase = SupportPhase::CleanupNew;
        plan.check_layout(AppPhase::Committed, &cleanup_new)
            .unwrap();
        assert!(
            plan.check_layout(AppPhase::RolledBack, &cleanup_new)
                .is_err()
        );
    }
}

#[tokio::test]
async fn every_anonymous_allocation_budget_preserves_byte_and_inode_recovery_reserve() {
    let root = tempfile::tempdir().unwrap();
    let install = fixture(root.path()).await;
    let closed = ClosedRuntime::fixture(install.transaction());
    let sources = Sources::open(&install, &closed).unwrap();
    for first in 0..=COUNT {
        let (bytes, inodes) = required_space(&sources.new.specs, first, 4096).unwrap();
        let capacity = Capacity::fixture(
            4096,
            bytes + crate::update::app_space::RECOVERY_BYTES,
            inodes + 128,
        );
        capacity.ensure(bytes, inodes).unwrap();
        assert!(
            Capacity::fixture(
                4096,
                bytes + crate::update::app_space::RECOVERY_BYTES - 1,
                inodes + 128
            )
            .ensure(bytes, inodes)
            .is_err()
        );
        assert!(
            Capacity::fixture(
                4096,
                bytes + crate::update::app_space::RECOVERY_BYTES,
                inodes + 127
            )
            .ensure(bytes, inodes)
            .is_err()
        );
    }
    assert!(required_space(&sources.new.specs, COUNT + 1, 4096).is_err());
    assert!(required_space(&sources.new.specs, 0, 0).is_err());
    assert!(required_space(&sources.new.specs, 0, 513).is_err());
}

pub(super) fn point(name: &str) -> Result<()> {
    #[cfg(feature = "sandbox-test-fixture")]
    super::capacity_tests::pressure_point(name)?;
    if let Some(member) = std::env::var_os("NANOKVM_SUPPORT_INTERPOSE") {
        let member = member.to_str().unwrap();
        assert!([PLAN, NEXT, NAMES[0]].contains(&member));
        if (member == PLAN && name == "staging-plan-file-synced")
            || (member != PLAN && name == "staging-durable")
        {
            let root = PathBuf::from(std::env::var_os("NANOKVM_SUPPORT_ROOT").unwrap());
            write(
                &support(&root).join(member),
                b"foreign name must not be overwritten",
                if member == NAMES[0] { 0o755 } else { 0o600 },
            );
        }
    }
    if std::env::var_os("NANOKVM_SUPPORT_MUTATE").is_some() {
        let root = PathBuf::from(std::env::var_os("NANOKVM_SUPPORT_ROOT").unwrap());
        if name == "source-copy-chunk" && !root.join("mutation-fired").exists() {
            let path = root.join("application-slot/current/new/server/NanoKVM-Server");
            let backend = File::open(&path).unwrap();
            let helpers = helper_family::inspect(&backend).unwrap();
            let offset = helpers.members()[0].image_range().start + 64 * 1024;
            fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .write_all_at(b"X", offset)
                .unwrap();
            fs::write(root.join("mutation-fired"), b"synthetic").unwrap();
        }
        if name == "source-copy-hash-mismatch" {
            fs::write(root.join("copy-hash-mismatch"), b"synthetic").unwrap();
        }
    }
    // Separate private controls become active only INSIDE the disposable
    // chroot, after fixture preparation. No unsafe environment mutation and no
    // production selector/closure override is introduced.
    let recovery = std::env::var_os("NANOKVM_SUPPORT_RECOVERY_ROOT").is_some()
        && Path::new("/support-recovery-active").is_file();
    let fault = if recovery {
        "NANOKVM_SUPPORT_RECOVERY_FAULT"
    } else {
        "NANOKVM_SUPPORT_FAULT"
    };
    let stop = if recovery {
        "NANOKVM_SUPPORT_RECOVERY_STOP"
    } else {
        "NANOKVM_SUPPORT_STOP"
    };
    if std::env::var(fault).as_deref() == Ok(name) {
        if recovery {
            fs::write("/support-recovery-fault-reached", name).unwrap();
        }
        return Err(SlotError::Io(io::Error::other(
            "synthetic support I/O failure",
        )));
    }
    if std::env::var(stop).as_deref() == Ok(name) {
        println!("support-checkpoint-ready");
        io::stdout().flush().unwrap();
        let _ = io::stdin().read(&mut [0; 1]);
        panic!("parent must kill the support probe");
    }
    Ok(())
}

#[test]
fn support_child() {
    let Some(root) = std::env::var_os("NANOKVM_SUPPORT_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let mut install = runtime.block_on(fixture(&root));
    let closed = ClosedRuntime::fixture(install.transaction());
    let sources = Sources::open(&install, &closed).unwrap();
    let result = stage(&mut install, closed, sources);
    let action = std::env::var("NANOKVM_SUPPORT_ACTION").unwrap_or_else(|_| "stage".into());
    if action != "stage" {
        let mut prepared = result.unwrap();
        let result = match action.as_str() {
            "new" => prepared.exchange(),
            "old" => {
                prepared.exchange().unwrap();
                prepared.restore_predecessor()
            }
            "cleanup-new" | "cleanup-old" | "cleanup-next-new" | "cleanup-next-old" => {
                terminal_fixture(&mut prepared, action.ends_with("new"));
                if action.starts_with("cleanup-next-") {
                    // Explicit same-context interrupted-publication fixture.
                    let mut next = prepared.plan.clone();
                    next.phase = if action.ends_with("new") {
                        SupportPhase::CleanupNew
                    } else {
                        SupportPhase::CleanupOld
                    };
                    let mut file = anonymous(&prepared.directories.support, 0o600).unwrap();
                    file.write_all(
                        &next
                            .encode(
                                prepared.install._store.uid,
                                prepared.install._store.rootfs.metadata().unwrap().gid(),
                            )
                            .unwrap(),
                    )
                    .unwrap();
                    file.sync_all().unwrap();
                    link_anonymous(&file, &prepared.directories.support, NEXT).unwrap();
                    prepared.directories.support.sync_all().unwrap();
                }
                settlement::run(&prepared.install._store)
            }
            _ => panic!("unknown private support fixture action"),
        };
        if std::env::var_os("NANOKVM_SUPPORT_FAULT").is_some() {
            assert!(result.is_err());
        } else {
            panic!("parent must kill selected exchange checkpoint");
        }
        return;
    }
    if [
        "NANOKVM_SUPPORT_FAULT",
        "NANOKVM_SUPPORT_INTERPOSE",
        "NANOKVM_SUPPORT_MUTATE",
    ]
    .into_iter()
    .any(|key| std::env::var_os(key).is_some())
    {
        assert!(result.is_err());
    } else {
        panic!("parent must kill the child at the selected support checkpoint");
    }
}

pub(super) fn terminal_fixture(prepared: &mut Prepared<'_>, new: bool) {
    if new {
        prepared.exchange().unwrap();
        prepared.install.publish(&prepared.closed).unwrap();
        // Canonical-state fixture, NOT a TrialReady/actual health proof.
        let mut record = prepared.install._store.record().unwrap();
        record.phase = AppPhase::Committed;
        prepared.install._store.publish(&record).unwrap();
        prepared.install.record = record;
    } else {
        prepared.install.rollback(&prepared.closed).unwrap();
    }
}

fn boundaries() -> Vec<String> {
    let mut points = Vec::with_capacity(41);
    for index in 0..COUNT {
        points.push(format!("anonymous-{index}"));
    }
    points.extend(
        [
            "predecessor-files-synced",
            "predecessor-executable-synced",
            "predecessor-init-synced",
            "source-roots-synced",
        ]
        .map(String::from),
    );
    for step in ["file-synced", "linked", "link-synced"] {
        points.push(format!("staging-plan-{step}"));
    }
    points.push("staging-durable".into());
    for index in 0..COUNT {
        for step in ["linked", "synced"] {
            points.push(format!("member-{step}-{index}"));
        }
    }
    for step in [
        "file-synced",
        "linked",
        "link-synced",
        "renamed",
        "rename-synced",
    ] {
        points.push(format!("ready-plan-{step}"));
    }
    points.push("ready-durable".into());
    assert_eq!(points.len(), 41);
    points
}

pub(super) fn run_probe(root: &Path, control: &str, value: &str, stop: bool, action: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::app_slot::support::tests::support_child",
            "--nocapture",
        ])
        .env("NANOKVM_SUPPORT_ROOT", root)
        .env("NANOKVM_SUPPORT_ACTION", action)
        .env(control, value)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line.unwrap().ends_with("support-checkpoint-ready") {
                let _ = tx.send(());
            }
        }
    });
    let errors = std::thread::spawn(move || {
        let mut stderr = stderr;
        let mut bytes = Vec::with_capacity(65536);
        let mut buffer = [0; 4096];
        loop {
            let count = stderr.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            let keep = count.min(65536 - bytes.len());
            bytes.extend_from_slice(&buffer[..keep]);
        }
        bytes
    });
    if stop {
        let ready = rx.recv_timeout(Duration::from_secs(90));
        child.kill().unwrap();
        let status = child.wait().unwrap();
        reader.join().unwrap();
        let errors = errors.join().unwrap();
        assert!(
            ready.is_ok(),
            "{value}: {ready:?}, child={status}, stderr={}",
            String::from_utf8_lossy(&errors)
        );
    } else {
        let started = Instant::now();
        let mut expired = false;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() >= Duration::from_secs(90) {
                expired = true;
                child.kill().unwrap();
                break child.wait().unwrap();
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        reader.join().unwrap();
        let errors = errors.join().unwrap();
        assert!(
            !expired && status.success(),
            "{value}: child={status}, stderr={}",
            String::from_utf8_lossy(&errors)
        );
    }
}

fn assert_live_matches_predecessor(root: &Path) {
    let uid = nix::unistd::geteuid().as_raw();
    let store = Store::at_root(
        File::open(root).unwrap(),
        File::open(root.join("application-slot")).unwrap(),
        uid,
        true,
    )
    .unwrap()
    .unwrap();
    let record = store.record().unwrap();
    assert_eq!(record.phase, AppPhase::Prepared);
    let source =
        Source::open(File::open(root.join("kvmapp")).unwrap(), record.old, &store).unwrap();
    for (index, spec) in source.specs.iter().enumerate() {
        let parent = File::open(root.join(if index < 5 {
            "usr/libexec"
        } else {
            "etc/init.d"
        }))
        .unwrap();
        let file = open_regular(&parent, live_name(index), &store, 0o755, Some(spec.size)).unwrap();
        let expected = object(&file, &store, spec.size, 1, spec.sha256).unwrap();
        named_object(&parent, live_name(index), &store, expected).unwrap();
    }
    let directories = Directories::open_mode(&store, true).unwrap();
    if let Ok(plan) = load_plan(&directories, &store, PLAN) {
        assert_old(root, &plan);
    }
}

#[test]
fn interposed_member_or_journal_name_is_never_overwritten_or_adopted() {
    for member in [PLAN, NEXT, NAMES[0]] {
        let root = tempfile::tempdir().unwrap();
        run_probe(
            root.path(),
            "NANOKVM_SUPPORT_INTERPOSE",
            member,
            false,
            "stage",
        );
        assert_eq!(
            fs::read(support(root.path()).join(member)).unwrap(),
            b"foreign name must not be overwritten"
        );
        assert_live_matches_predecessor(root.path());
    }
}

#[test]
fn mid_copy_source_change_fails_at_content_hash_before_metadata_revalidation() {
    let root = tempfile::tempdir().unwrap();
    run_probe(
        root.path(),
        "NANOKVM_SUPPORT_MUTATE",
        "synthetic",
        false,
        "stage",
    );
    assert!(root.path().join("mutation-fired").is_file());
    assert!(root.path().join("copy-hash-mismatch").is_file());
    assert_eq!(fs::read_dir(support(root.path())).unwrap().count(), 0);
    assert_live_matches_predecessor(root.path());
}

#[test]
fn every_process_kill_and_post_success_io_failure_preserves_old_live_support_and_bounded_evidence()
{
    for fault in [false, true] {
        for point in boundaries() {
            let root = tempfile::tempdir().unwrap();
            run_probe(
                root.path(),
                if fault {
                    "NANOKVM_SUPPORT_FAULT"
                } else {
                    "NANOKVM_SUPPORT_STOP"
                },
                &point,
                !fault,
                "stage",
            );
            // Process-kill visibility, not power-cut durability/boot acceptance.
            let uid = nix::unistd::geteuid().as_raw();
            let store = Store::at_root(
                File::open(root.path()).unwrap(),
                File::open(root.path().join("application-slot")).unwrap(),
                uid,
                true,
            )
            .unwrap()
            .unwrap();
            let directories = Directories::open_mode(&store, true).unwrap();
            let names = inventory(&directories.support).unwrap();
            if names == 0 {
                continue;
            }
            assert_ne!(
                names & (1 << COUNT),
                0,
                "named successor without plan at {point}"
            );
            let plan = load_plan(&directories, &store, PLAN).unwrap();
            assert_old(root.path(), &plan);
            if names & (1 << (COUNT + 1)) != 0 {
                let next = load_plan(&directories, &store, NEXT).unwrap();
                assert!(plan.phase == SupportPhase::Staging && next.phase == SupportPhase::Ready);
                let mut normalized = next.clone();
                normalized.phase = SupportPhase::Staging;
                assert!(normalized == plan);
            } else {
                let layout = inspect_layout(&directories, &store, &plan).unwrap();
                plan.check_layout(AppPhase::Prepared, &layout).unwrap();
            }
        }
    }
}
