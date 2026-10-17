#![cfg(feature = "sandbox-test-fixture")]

use rustix::io::{FdFlags, fcntl_dupfd_cloexec, fcntl_setfd};
use std::{
    fs::{self, File},
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

struct PreparedRoot {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    outside: PathBuf,
}

impl PreparedRoot {
    fn new(executable: &Path) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for directory in [
            ".oldroot", "proc", "sys", "data", "dev", "etc/ssh", "usr/sbin",
        ] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(root.join("dev/null"), []).unwrap();
        fs::write(root.join("etc/ssh/sshd_config"), []).unwrap();
        let outside = temporary.path().join("outside-sentinel");
        fs::write(&outside, b"synthetic outside sentinel").unwrap();
        fs::write(
            root.join("etc/outside-path"),
            outside.as_os_str().as_encoded_bytes(),
        )
        .unwrap();
        let prepared = Self {
            _temporary: temporary,
            root,
            outside,
        };
        prepared.install_executable(executable);
        prepared
    }

    fn install_executable(&self, executable: &Path) {
        fs::copy(executable, self.root.join("usr/sbin/sshd")).unwrap();
        fs::set_permissions(
            self.root.join("usr/sbin/sshd"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        // Only inspect known locally built/installed host executables. Never run
        // ldd on an uploaded or unsigned target-image executable.
        let output = Command::new("/usr/bin/ldd")
            .arg(executable)
            .output()
            .unwrap();
        assert!(output.status.success(), "trusted host ldd failed");
        for word in std::str::from_utf8(&output.stdout)
            .unwrap()
            .split_whitespace()
        {
            if word.starts_with('/') {
                let source = Path::new(word);
                assert!(source.is_file(), "unresolved host runtime dependency");
                let destination = self.root.join(source.strip_prefix("/").unwrap());
                fs::create_dir_all(destination.parent().unwrap()).unwrap();
                fs::copy(source, destination).unwrap();
            }
        }
    }

    fn run(&self, parent: u32) -> Output {
        Command::new("/usr/bin/unshare")
            .args(["--user", "--map-root-user"])
            .arg(env!("CARGO_BIN_EXE_nanokvm-ssh-sandbox"))
            .arg("--root")
            .arg(&self.root)
            .arg("--parent-pid")
            .arg(parent.to_string())
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn expect_layout_rejection(&self) {
        let output = self.run(std::process::id());
        assert_eq!(output.status.code(), Some(71), "{:?}", output);
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            b"SSH sandbox root is not a bounded private prepared runtime\n"
        );
    }
}

#[test]
fn kernel_enforces_private_root_caps_fds_and_syscall_boundary() {
    // Run this host-only integration binary with --test-threads=1. The briefly
    // inherited descriptor contains only synthetic data; every sandbox helper
    // invocation closes it. --user grants fixture privilege, not target proof.
    let prepared = PreparedRoot::new(Path::new(env!("CARGO_BIN_EXE_nanokvm-sandbox-fixture")));
    let mountinfo = fs::read("/proc/self/mountinfo").unwrap();
    for stop in 0..=7 {
        fs::write(prepared.root.join("etc/probe-stop"), stop.to_string()).unwrap();
        let output = prepared.run(std::process::id());
        assert_eq!(
            output.status.code(),
            Some(100 + stop),
            "probe phase {stop}: {output:?}"
        );
    }
    fs::remove_file(prepared.root.join("etc/probe-stop")).unwrap();
    let outside_fd = File::open(&prepared.outside).unwrap();
    let inherited = fcntl_dupfd_cloexec(&outside_fd, 128).unwrap();
    fcntl_setfd(&inherited, FdFlags::empty()).unwrap();
    let control = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user"])
        .arg(env!("CARGO_BIN_EXE_nanokvm-sandbox-fixture"))
        .arg("--expect-inherited-fd128")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let output = prepared.run(std::process::id());
    fcntl_setfd(&inherited, FdFlags::CLOEXEC).unwrap();
    assert!(
        control.status.success(),
        "unshare unexpectedly closed the test fd: {control:?}"
    );
    assert_eq!(output.status.code(), Some(0), "sandbox fixture: {output:?}");
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(
        fs::read(&prepared.outside).unwrap(),
        b"synthetic outside sentinel"
    );
    assert_eq!(fs::read("/proc/self/mountinfo").unwrap(), mountinfo);
    assert!(!prepared.root.join("write-attempt").exists());

    let output = prepared.run(std::process::id() + 1);
    assert_eq!(output.status.code(), Some(70));
    assert_eq!(
        output.stderr,
        b"SSH sandbox requires a fresh privileged process and a live parent lease\n"
    );

    for mode in [0o755, 0o4700] {
        fs::set_permissions(&prepared.root, fs::Permissions::from_mode(mode)).unwrap();
        prepared.expect_layout_rejection();
    }
    fs::set_permissions(&prepared.root, fs::Permissions::from_mode(0o700)).unwrap();

    symlink(&prepared.outside, prepared.root.join("escape")).unwrap();
    prepared.expect_layout_rejection();
    fs::remove_file(prepared.root.join("escape")).unwrap();

    fs::hard_link(
        prepared.root.join("etc/outside-path"),
        prepared.root.join("hardlink"),
    )
    .unwrap();
    prepared.expect_layout_rejection();
    fs::remove_file(prepared.root.join("hardlink")).unwrap();

    for directory in [".oldroot", "proc", "sys", "data"] {
        let poison = prepared.root.join(directory).join("not-empty");
        fs::write(&poison, b"synthetic").unwrap();
        prepared.expect_layout_rejection();
        fs::remove_file(poison).unwrap();
    }
    fs::set_permissions(
        prepared.root.join("etc/outside-path"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    prepared.expect_layout_rejection();
}

#[test]
fn real_host_sshd_checks_valid_and_invalid_configuration_without_output() {
    let prepared = PreparedRoot::new(Path::new("/usr/sbin/sshd"));
    fs::create_dir_all(prepared.root.join("run/sshd")).unwrap();
    fs::write(
        prepared.root.join("etc/passwd"),
        b"root:x:0:0:root:/:/bin/sh\nsshd:x:999:999:sshd:/:/bin/false\n",
    )
    .unwrap();
    fs::write(prepared.root.join("etc/group"), b"root:x:0:\nsshd:x:999:\n").unwrap();
    fs::write(
        prepared.root.join("etc/nsswitch.conf"),
        b"passwd: files\ngroup: files\nhosts: files\n",
    )
    .unwrap();
    let key = prepared.root.join("etc/ssh/ssh_host_ed25519_key");
    let generated = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "synthetic host key generation failed"
    );
    fs::write(prepared.root.join("etc/ssh/sshd_config"), b"HostKey /etc/ssh/ssh_host_ed25519_key\nUsePAM no\nPermitRootLogin yes\nPasswordAuthentication yes\n").unwrap();
    let output = prepared.run(std::process::id());
    assert_eq!(output.status.code(), Some(0), "native sshd: {output:?}");
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    fs::write(
        prepared.root.join("etc/ssh/sshd_config"),
        b"InvalidSyntheticDirective yes\n",
    )
    .unwrap();
    let output = prepared.run(std::process::id());
    assert_eq!(
        output.status.code(),
        Some(255),
        "invalid native sshd: {output:?}"
    );
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    fs::write(
        prepared.root.join("etc/ssh/sshd_config"),
        b"HostKey /etc/ssh/ssh_host_ed25519_key\nUsePAM no\n",
    )
    .unwrap();
    fs::write(key, b"invalid synthetic private host key\n").unwrap();
    let output = prepared.run(std::process::id());
    assert_eq!(
        output.status.code(),
        Some(1),
        "invalid native key: {output:?}"
    );
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}
