use super::*;
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
};

const PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/sh\nsshd:x:74:74:sshd:/var/empty:/bin/false\n";
const GROUP: &[u8] = b"root:x:0:\nsshd:x:74:\n";
const SHADOW: &[u8] = b"root:!:0:0:99999:7:::\nsshd:!:0:0:99999:7:::\n";

// Run owner-sensitive filesystem checks as mapped root in a disposable child.
// No host root, loop device, real account file or parent namespace is modified.
pub(super) fn in_user_namespace(name: &str) -> bool {
    if std::env::var_os("NANOKVM_ROOTFS_OWNER_FIXTURE").is_some() {
        return true;
    }
    let name = name.strip_prefix("nanokvm_rust_server::").unwrap();
    let before = fs::read("/proc/self/mountinfo").unwrap();
    let output = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env("NANOKVM_ROOTFS_OWNER_FIXTURE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "namespace fixture failed: {output:?}"
    );
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    assert!(
        stdout.contains("running 1 test\n") && stdout.contains("1 passed; 0 failed;"),
        "namespace fixture did not execute its exact test: {output:?}"
    );
    assert_eq!(fs::read("/proc/self/mountinfo").unwrap(), before);
    false
}

fn prepared() -> tempfile::TempDir {
    let temporary = tempfile::tempdir().unwrap();
    fs::create_dir_all(temporary.path().join("etc")).unwrap();
    fs::create_dir_all(temporary.path().join("root")).unwrap();
    fs::create_dir_all(temporary.path().join("bin")).unwrap();
    for (path, bytes) in [
        ("etc/passwd", PASSWD),
        ("etc/group", GROUP),
        ("etc/shadow", SHADOW),
    ] {
        fs::write(temporary.path().join(path), bytes).unwrap();
        fs::set_permissions(
            temporary.path().join(path),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    fs::write(
        temporary.path().join("bin/busybox"),
        b"synthetic executable metadata fixture",
    )
    .unwrap();
    fs::set_permissions(
        temporary.path().join("bin/busybox"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    symlink("busybox", temporary.path().join("bin/sh")).unwrap();
    temporary
}

#[test]
fn exact_account_reads_require_closed_fixed_files_and_validate_cross_file_consistency() {
    if !in_user_namespace(concat!(
        module_path!(),
        "::exact_account_reads_require_closed_fixed_files_and_validate_cross_file_consistency"
    )) {
        return;
    }
    let temporary = prepared();
    let root = File::open(temporary.path()).unwrap();
    let tables = read_accounts(&root).unwrap();
    assert_eq!(tables.as_files().passwd, PASSWD);
    assert_eq!(tables.as_files().group, GROUP);
    assert_eq!(tables.as_files().shadow, SHADOW);
    assert!(tables.as_files().gshadow.is_none());
    let path = temporary.path().join("etc/gshadow");
    fs::write(&path, b"root:!::\nsshd:!::\n").unwrap();
    assert!(read_accounts(&root).unwrap().as_files().gshadow.is_some());
    fs::write(&path, b"root:!::unknown\nsshd:!::\n").unwrap();
    assert!(matches!(read_accounts(&root), Err(RootfsError::Accounts)));
    fs::remove_file(&path).unwrap();
    for member in ["etc/passwd", "etc/group", "etc/shadow"] {
        let path = temporary.path().join(member);
        let saved = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(read_accounts(&root).is_err());
        symlink("/etc/passwd", &path).unwrap();
        assert!(read_accounts(&root).is_err());
        fs::remove_file(&path).unwrap();
        fs::write(&path, &saved).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_accounts(&root).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = temporary.path().join("hardlink");
        fs::hard_link(&path, &alias).unwrap();
        assert!(read_accounts(&root).is_err());
        fs::remove_file(&alias).unwrap();
        fs::write(&path, vec![b'x'; restore_native::MAX_TABLE_BYTES + 1]).unwrap();
        assert!(read_accounts(&root).is_err());
        fs::write(&path, &saved).unwrap();
        assert!(read_accounts(&root).is_ok());
    }
}

#[test]
fn login_open_retries_only_again_with_exact_finite_limit_and_preserves_fd() {
    use rustix::io::Errno;

    let temporary = tempfile::tempfile().unwrap();
    let expected = temporary.metadata().unwrap().ino();
    for transient in 0..LOGIN_OPEN_ATTEMPTS {
        let mut calls = 0;
        let opened: File = retry_login_open(|| {
            calls += 1;
            if calls <= transient {
                Err(Errno::AGAIN)
            } else {
                Ok(temporary.try_clone().unwrap().into())
            }
        })
        .unwrap()
        .into();
        assert_eq!(calls, transient + 1);
        assert_eq!(opened.metadata().unwrap().ino(), expected);
    }
    let mut calls = 0;
    assert_eq!(
        retry_login_open(|| {
            calls += 1;
            Err(Errno::AGAIN)
        })
        .unwrap_err(),
        Errno::AGAIN
    );
    assert_eq!(calls, LOGIN_OPEN_ATTEMPTS);
    for error in [
        Errno::ACCESS,
        Errno::XDEV,
        Errno::LOOP,
        Errno::NOENT,
        Errno::INTR,
        Errno::IO,
    ] {
        for transient in [0, LOGIN_OPEN_ATTEMPTS - 1] {
            let mut calls = 0;
            assert_eq!(
                retry_login_open(|| {
                    calls += 1;
                    Err(if calls <= transient {
                        Errno::AGAIN
                    } else {
                        error
                    })
                })
                .unwrap_err(),
                error
            );
            assert_eq!(calls, transient + 1);
        }
    }
}

#[test]
fn root_login_shell_symlinks_stay_inside_image_and_home_must_be_real_private_owner() {
    if !in_user_namespace(concat!(
        module_path!(),
        "::root_login_shell_symlinks_stay_inside_image_and_home_must_be_real_private_owner"
    )) {
        return;
    }
    let temporary = prepared();
    let root = File::open(temporary.path()).unwrap();
    let tables = read_accounts(&root).unwrap();
    assert!(check_root_login_paths(&root, &tables.as_files()).is_ok());
    let shell = temporary.path().join("bin/sh");
    for destination in ["/bin/busybox", "../../bin/busybox"] {
        fs::remove_file(&shell).unwrap();
        symlink(destination, &shell).unwrap();
        let result = check_root_login_paths(&root, &tables.as_files());
        assert!(result.is_ok(), "{destination}: {result:?}");
    }
    for destination in ["/bin/true", "/proc/self/exe", "/data/untrusted"] {
        fs::remove_file(&shell).unwrap();
        symlink(destination, &shell).unwrap();
        assert!(check_root_login_paths(&root, &tables.as_files()).is_err());
    }
    fs::remove_file(&shell).unwrap();
    symlink("busybox", &shell).unwrap();
    for mode in [0o644, 0o641, 0o777, 0o4755] {
        fs::set_permissions(
            temporary.path().join("bin/busybox"),
            fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert!(check_root_login_paths(&root, &tables.as_files()).is_err());
    }
    fs::set_permissions(
        temporary.path().join("bin/busybox"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    for mode in [0o600, 0o677, 0o777] {
        fs::set_permissions(
            temporary.path().join("root"),
            fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert!(check_root_login_paths(&root, &tables.as_files()).is_err());
    }
    fs::remove_dir(temporary.path().join("root")).unwrap();
    symlink("/", temporary.path().join("root")).unwrap();
    assert!(check_root_login_paths(&root, &tables.as_files()).is_err());
}

#[test]
fn rootfs_mount_requires_fresh_lease_and_empty_private_mountpoint() {
    assert!(matches!(
        require_fresh_process(0),
        Err(RootfsError::Process)
    ));
    assert!(matches!(
        require_fresh_process(1),
        Err(RootfsError::Process)
    ));
    assert!(matches!(
        require_fresh_process(std::process::id()),
        Err(RootfsError::Process)
    ));
    if !in_user_namespace(concat!(
        module_path!(),
        "::rootfs_mount_requires_fresh_lease_and_empty_private_mountpoint"
    )) {
        return;
    }
    // Hold an explicit second task, independent of test-harness implementation.
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            ready_tx.send(()).unwrap();
            let _ = stop_rx.recv();
        });
        ready_rx.recv().unwrap();
        let result = require_fresh_process(getppid().as_raw() as u32);
        drop(stop_tx);
        assert!(matches!(result, Err(RootfsError::Process)));
    });
    let temporary = tempfile::tempdir().unwrap();
    let root = File::open(temporary.path()).unwrap();
    assert!(check_mountpoint(&root).is_ok());
    fs::write(temporary.path().join("not-empty"), []).unwrap();
    assert!(matches!(check_mountpoint(&root), Err(RootfsError::Layout)));
    fs::remove_file(temporary.path().join("not-empty")).unwrap();
    for mode in [0o755, 0o777, 0o4700] {
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(check_mountpoint(&root), Err(RootfsError::Layout)));
    }
}

const RESTORE_HELPER: &str = "usr/libexec/nanokvm-early-restore";
const RESTORE_SCRIPT: &str = "etc/init.d/S01restore";

fn facts_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for directory in ["kvmapp", "etc/kvm", "etc/init.d", "usr/libexec"] {
        fs::create_dir_all(root.path().join(directory)).unwrap();
    }
    let write = |path: &str, bytes: &[u8], mode: u32| {
        let path = root.path().join(path);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    };
    write("kvmapp/version", b"2.1.0\n", 0o644);
    write(REQUIRED_PATH, REQUIRED_BYTES, 0o644);
    write(RESTORE_HELPER, b"\x7fELF", 0o755);
    write(RESTORE_SCRIPT, b"#!/bin/sh\n", 0o755);
    root
}

fn facts_of(root: &tempfile::TempDir) -> Result<ImageFacts, RootfsError> {
    let directory = restore_fs::open_root(root.path(), false).unwrap();
    read_facts(&directory, geteuid().as_raw())
}

#[test]
fn facts_report_the_image_version_and_a_complete_restore() {
    let facts = facts_of(&facts_root()).unwrap();
    assert_eq!(facts.app_version, "2.1.0");
    assert!(facts.restorable);
}

#[test]
fn an_image_missing_any_part_of_its_restore_is_not_restorable() {
    for missing in [REQUIRED_PATH, RESTORE_HELPER, RESTORE_SCRIPT] {
        let root = facts_root();
        fs::remove_file(root.path().join(missing)).unwrap();
        assert!(!facts_of(&root).unwrap().restorable, "{missing}");
    }
    let root = facts_root();
    fs::write(
        root.path().join(REQUIRED_PATH),
        b"nanokvm-raw-restore-required-v0\n",
    )
    .unwrap();
    assert!(!facts_of(&root).unwrap().restorable, "wrong marker bytes");
    let root = facts_root();
    let helper = root.path().join(RESTORE_HELPER);
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        !facts_of(&root).unwrap().restorable,
        "helper not executable"
    );
    let root = facts_root();
    fs::write(root.path().join(RESTORE_HELPER), b"").unwrap();
    assert!(!facts_of(&root).unwrap().restorable, "empty helper");
}

#[test]
fn a_malformed_or_missing_application_version_refuses_the_image() {
    for version in [
        &b""[..],
        b"\n",
        b"2.1.0-dev\n",
        b"2.1.0 extra\n",
        &[b'1'; 40],
    ] {
        let root = facts_root();
        fs::write(root.path().join("kvmapp/version"), version).unwrap();
        assert!(matches!(facts_of(&root), Err(RootfsError::Accounts)));
    }
    let root = facts_root();
    fs::remove_file(root.path().join("kvmapp/version")).unwrap();
    assert!(matches!(facts_of(&root), Err(RootfsError::Accounts)));
}

#[test]
fn a_symlinked_or_writable_fact_refuses_the_image() {
    let root = facts_root();
    let version = root.path().join("kvmapp/version");
    fs::remove_file(&version).unwrap();
    symlink("/etc/passwd", &version).unwrap();
    assert!(facts_of(&root).is_err());
    let root = facts_root();
    fs::set_permissions(
        root.path().join("kvmapp/version"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(facts_of(&root).is_err());
}
