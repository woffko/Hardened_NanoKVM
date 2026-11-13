//! Real bounded tmpfs pressure, not ext4/media or native-health acceptance.
use super::tests::{fixture, support, terminal_fixture};
use super::*;
use nix::mount::{MsFlags, mount};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

const LIMIT: u64 = 64 * 1024 * 1024;
const INODES: u64 = 4096;
const OPTIONS: &str = "mode=0700,size=67108864,nr_inodes=4096";
const MARKER: &[u8; 8] = b"NKCAP001";

fn flags() -> MsFlags {
    MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC
}

fn remount(volume: &Path, readonly: bool) {
    mount(
        None::<&str>,
        volume,
        None::<&str>,
        flags()
            | MsFlags::MS_REMOUNT
            | if readonly {
                MsFlags::MS_RDONLY
            } else {
                MsFlags::empty()
            },
        Some(OPTIONS),
    )
    .unwrap();
}

fn checked_volume(volume: &Path) -> Result<File> {
    let directory = File::open(volume)?;
    let stat = rustix::fs::fstatvfs(&directory)?;
    if !nix::unistd::geteuid().is_root()
        || fstatfs(&directory)?.f_type != nix::sys::statfs::TMPFS_MAGIC.0
        || stat
            .f_blocks
            .checked_mul(stat.f_frsize)
            .is_none_or(|size| size == 0 || size > LIMIT)
        || stat.f_files == 0
        || stat.f_files > INODES
        || directory.metadata()?.dev() != volume.join("fixture").metadata()?.dev()
        || fs::read(volume.join("pressure/marker"))?.get(..8) != Some(MARKER.as_slice())
    {
        return Err(SlotError::Unsafe);
    }
    Ok(directory)
}

fn pressure_state(volume: &Path, count: u64, exhausted: bool) -> Result<()> {
    // This file's one data page and inode precede pressure. Updating it does
    // not need a fresh inode/block after the bounded filesystem becomes full.
    let marker = fs::OpenOptions::new()
        .write(true)
        .open(volume.join("pressure/marker"))?;
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(MARKER);
    bytes[8] = 1;
    bytes[9] = u8::from(exhausted);
    bytes[16..24].copy_from_slice(&count.to_le_bytes());
    marker.write_all_at(&bytes, 0)?;
    marker.sync_all()?;
    Ok(())
}

fn fill_bytes(volume: &Path, exhaust: bool) -> Result<()> {
    let directory = checked_volume(volume)?;
    let mut filler = fs::OpenOptions::new()
        .write(true)
        .open(volume.join("pressure/bytes"))?;
    let buffer = [0; 64 * 1024];
    for count in 0..=LIMIT / buffer.len() as u64 {
        let stat = rustix::fs::fstatvfs(&directory)?;
        let available = stat
            .f_bavail
            .checked_mul(stat.f_frsize)
            .ok_or(SlotError::Invalid)?;
        if !exhaust && available < crate::update::app_space::RECOVERY_BYTES {
            return pressure_state(volume, count, false);
        }
        match filler.write_all(&buffer) {
            Ok(()) => {}
            Err(error) if exhaust && error.raw_os_error() == Some(28) => {
                return pressure_state(volume, count, true);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(SlotError::Invalid)
}

fn fill_inodes(volume: &Path, exhaust: bool) -> Result<()> {
    let directory = checked_volume(volume)?;
    for count in 0..=INODES {
        if !exhaust && rustix::fs::fstatvfs(&directory)?.f_favail < 128 {
            return pressure_state(volume, count, false);
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(volume.join("pressure").join(format!("inode-{count}")))
        {
            Ok(file) => drop(file),
            Err(error) if exhaust && error.raw_os_error() == Some(28) => {
                return pressure_state(volume, count, true);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(SlotError::Invalid)
}

pub(super) fn pressure_point(name: &str) -> Result<()> {
    let Some(_volume) = std::env::var_os("NANOKVM_SUPPORT_CAPACITY_VOLUME") else {
        return Ok(());
    };
    let case = std::env::var("NANOKVM_SUPPORT_CAPACITY_CASE").unwrap();
    let inject = (case == "write-bytes" && name == "source-copy-chunk")
        || (case == "allocate-inodes" && name == "successor-preflight-0");
    let completed = (case == "write-bytes" && name == "source-copy-chunk-written")
        || (case == "allocate-inodes" && name == "anonymous-created");
    if !inject && !completed {
        return Ok(());
    }
    // The exact child enters its bounded tmpfs before fixture creation, so
    // production open_root(..., true) retains NO_XDEV relative to this root.
    let volume = Path::new("/");
    if !volume.join("pressure/armed").exists() {
        return Ok(());
    }
    let marker = fs::read(volume.join("pressure/marker"))?;
    if completed {
        if marker[8] != 0 {
            fs::OpenOptions::new()
                .write(true)
                .open(volume.join("pressure/marker"))?
                .write_all_at(&[1], 10)?;
        }
        return Ok(());
    }
    if marker[8] != 0 {
        return Ok(());
    }
    if case == "write-bytes" {
        fill_bytes(volume, true)?;
    } else {
        fill_inodes(volume, true)?;
    }
    // Deliberately return Ok. The caller's REAL write/O_TMPFILE operation,
    // not a synthetic injected errno, must now fail with ENOSPC.
    Ok(())
}

fn live(root: &Path) -> [(u64, u64, [u8; 32]); COUNT] {
    std::array::from_fn(|index| {
        let path = root
            .join(if index < 5 {
                "usr/libexec"
            } else {
                "etc/init.d"
            })
            .join(live_name(index));
        let metadata = path.metadata().unwrap();
        (
            metadata.dev(),
            metadata.ino(),
            Sha256::digest(fs::read(path).unwrap()).into(),
        )
    })
}

fn evidence(root: &Path) -> Vec<(std::ffi::OsString, u64, Vec<u8>)> {
    let entries = match fs::read_dir(support(root)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => panic!("support inventory: {error}"),
    };
    let mut snapshot = Vec::with_capacity(COUNT + 2);
    for entry in entries {
        let entry = entry.unwrap();
        snapshot.push((
            entry.file_name(),
            entry.metadata().unwrap().ino(),
            fs::read(entry.path()).unwrap(),
        ));
    }
    snapshot.sort_by(|left, right| left.0.cmp(&right.0));
    snapshot
}

fn free_pressure(volume: &Path) {
    let marker = fs::read(volume.join("pressure/marker")).unwrap();
    let count = u64::from_le_bytes(marker[16..24].try_into().unwrap());
    assert!(count <= INODES);
    let case = std::env::var("NANOKVM_SUPPORT_CAPACITY_CASE").unwrap();
    if case.ends_with("inodes") {
        for index in 0..count {
            fs::remove_file(volume.join("pressure").join(format!("inode-{index}"))).unwrap();
        }
    }
    fs::OpenOptions::new()
        .write(true)
        .open(volume.join("pressure/bytes"))
        .unwrap()
        .set_len(0)
        .unwrap();
}

#[test]
fn capacity_child() {
    let Some(volume) = std::env::var_os("NANOKVM_SUPPORT_CAPACITY_VOLUME") else {
        return;
    };
    let volume = PathBuf::from(volume);
    let case = std::env::var("NANOKVM_SUPPORT_CAPACITY_CASE").unwrap();
    assert!(
        [
            "ample",
            "reserve-bytes",
            "reserve-inodes",
            "write-bytes",
            "allocate-inodes",
            "settle-old-bytes",
            "settle-old-inodes",
            "settle-new-bytes",
            "settle-new-inodes",
            "readonly-prepare",
            "readonly-settle-old",
            "readonly-settle-new",
        ]
        .contains(&case.as_str())
    );
    mount(
        Some("nanokvm-support-capacity"),
        volume.as_path(),
        Some("tmpfs"),
        flags(),
        Some(OPTIONS),
    )
    .unwrap();
    fs::create_dir(volume.join("proc")).unwrap();
    fs::create_dir(volume.join("tmp")).unwrap();
    mount(
        Some("/proc"),
        volume.join("proc").as_path(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .unwrap();
    nix::unistd::chroot(&volume).unwrap();
    std::env::set_current_dir("/").unwrap();
    let volume = PathBuf::from("/");
    let root = volume.join("fixture");
    fs::create_dir(&root).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let mut install = runtime.block_on(fixture(&root));
    fs::create_dir(volume.join("pressure")).unwrap();
    let mut marker = [0; 32];
    marker[..8].copy_from_slice(MARKER);
    fs::write(volume.join("pressure/marker"), marker).unwrap();
    fs::write(volume.join("pressure/bytes"), []).unwrap();
    let terminal = case.starts_with("settle-") || case.starts_with("readonly-settle-");
    let new = case.contains("new");
    if terminal {
        let closed = ClosedRuntime::fixture(install.transaction());
        let mut prepared = super::prepare(&mut install, closed).unwrap();
        terminal_fixture(&mut prepared, new);
    }
    let before_live = live(&root);
    let before_record = install._store.record().unwrap();
    let before_evidence = evidence(&root);
    assert_eq!(before_evidence.len(), if terminal { 10 } else { 0 });
    checked_volume(&volume).unwrap();
    if case.starts_with("readonly-") {
        remount(&volume, true);
    } else if case.ends_with("bytes") && case != "write-bytes" {
        fill_bytes(&volume, false).unwrap();
    } else if case.ends_with("inodes") && case != "allocate-inodes" {
        fill_inodes(&volume, false).unwrap();
    }
    if !case.starts_with("readonly-") {
        fs::write(volume.join("pressure/armed"), b"only this child fixture").unwrap();
    }
    let result = if terminal {
        settlement::run(&install._store)
    } else if case == "ample" {
        let closed = ClosedRuntime::fixture(install.transaction());
        let mut prepared = super::prepare(&mut install, closed).unwrap();
        prepared.check().unwrap();
        prepared.exchange().unwrap();
        prepared.check_exchanged().unwrap();
        prepared.restore_predecessor().unwrap();
        assert_eq!(live(&root), before_live);
        Ok(())
    } else {
        let closed = ClosedRuntime::fixture(install.transaction());
        super::prepare(&mut install, closed)
            .map(drop)
            .map_err(|error| match error {
                SlotError::NotStaged(cause) => *cause,
                other => panic!("{case}: must stay a rollback, got {other:?}"),
            })
    };
    if case == "ample" {
        result.unwrap();
    } else {
        assert!(
            matches!(result, Err(SlotError::Io(ref error)) if error.raw_os_error() == Some(if case.starts_with("readonly-") {30} else {28})),
            "{case}: expected real capacity errno, got {result:?}"
        );
        assert_eq!(live(&root), before_live);
        assert!(install._store.record().unwrap() == before_record);
        assert_eq!(evidence(&root), before_evidence);
        super::super::issuer_tests::assert_excluded(&root);
        if matches!(case.as_str(), "write-bytes" | "allocate-inodes") {
            let marker = fs::read(volume.join("pressure/marker")).unwrap();
            assert_eq!(&marker[8..10], &[1, 1], "actual pressure was not reached");
            assert_eq!(marker[10], 0, "the intended real write/O_TMPFILE succeeded");
        }
        if case.starts_with("readonly-") {
            remount(&volume, false);
        } else {
            free_pressure(&volume);
        }
        if terminal {
            settlement::run(&install._store).unwrap();
            assert!(evidence(&root).is_empty());
        } else {
            let closed = ClosedRuntime::fixture(install.transaction());
            let mut prepared = super::prepare(&mut install, closed).unwrap();
            prepared.check().unwrap();
            prepared.exchange().unwrap();
            prepared.check_exchanged().unwrap();
            prepared.restore_predecessor().unwrap();
            assert_eq!(live(&root), before_live);
        }
    }
    assert!(install._store.record().unwrap() == before_record);
    super::super::issuer_tests::assert_excluded(&root);
    println!("support-capacity-completed: {case}");
}

#[test]
fn isolated_tmpfs_reserve_and_real_enospc_keep_exact_owner_evidence_and_retry() {
    for case in [
        "ample",
        "reserve-bytes",
        "reserve-inodes",
        "write-bytes",
        "allocate-inodes",
        "settle-old-bytes",
        "settle-old-inodes",
        "settle-new-bytes",
        "settle-new-inodes",
        "readonly-prepare",
        "readonly-settle-old",
        "readonly-settle-new",
    ] {
        let root = tempfile::tempdir().unwrap();
        let volume = root.path().join("volume");
        fs::create_dir(&volume).unwrap();
        let outside = root.path().join("outside-evidence");
        fs::write(&outside, b"preserve host-side fixture evidence").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        let identity = outside.metadata().unwrap().ino();
        let output = Command::new("/usr/bin/unshare")
            .args(["--user", "--map-root-user", "--mount", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::app_slot::support::capacity_tests::capacity_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("TMPDIR", "/tmp")
            .env("NANOKVM_SUPPORT_CAPACITY_VOLUME", &volume)
            .env("NANOKVM_SUPPORT_CAPACITY_CASE", case)
            .output()
            .unwrap();
        assert!(output.status.success(), "{case}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!("support-capacity-completed: {case}"))
        );
        assert_eq!(outside.metadata().unwrap().ino(), identity);
        assert_eq!(
            fs::read(outside).unwrap(),
            b"preserve host-side fixture evidence"
        );
        assert_eq!(fs::read_dir(volume).unwrap().count(), 0);
    }
}
