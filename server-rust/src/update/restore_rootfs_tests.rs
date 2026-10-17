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
fn in_user_namespace(name: &str) -> bool {
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
        assert!(check_root_login_paths(&root, &tables.as_files()).is_ok());
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
