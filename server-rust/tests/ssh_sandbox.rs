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
    fn split_image_runtime(&self) -> PathBuf {
        let source = self._temporary.path().join("synthetic-image");
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        for path in ["usr", "lib", "lib64", "bin", "sbin"] {
            if self.root.join(path).exists() {
                fs::rename(self.root.join(path), source.join(path)).unwrap();
            }
        }
        for path in ["usr", "lib", "usr/bin", "etc/ssl"] {
            fs::create_dir_all(source.join(path)).unwrap();
        }
        symlink("usr/bin", source.join("bin")).unwrap();
        fs::write(
            source.join("usr/runtime-proof"),
            b"synthetic signed-runtime bytes",
        )
        .unwrap();
        symlink("runtime-proof", source.join("usr/runtime-link")).unwrap();
        symlink(&self.outside, source.join("usr/link-outside")).unwrap();
        fs::write(
            source.join("etc/ssl/runtime-proof"),
            b"synthetic provider config",
        )
        .unwrap();
        fs::copy(
            env!("CARGO_BIN_EXE_nanokvm-sandbox-fixture"),
            source.join("etc/ssl/exec-probe"),
        )
        .unwrap();
        fs::set_permissions(
            source.join("etc/ssl/exec-probe"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(source.join("etc/ld-musl-riscv64.path"), b"/lib:/usr/lib\n").unwrap();
        fs::write(self.root.join("etc/runtime-bind-probe"), []).unwrap();
        source
    }

    fn run_image(&self, source: &Path) -> Output {
        Command::new("/usr/bin/unshare")
            .args(["--user", "--map-root-user"])
            .arg(env!("CARGO_BIN_EXE_nanokvm-image-runtime-fixture"))
            .arg(&self.root)
            .arg(source)
            .arg(std::process::id().to_string())
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
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
fn image_bind_runtime_keeps_private_identity_and_same_native_isolation() {
    let prepared = PreparedRoot::new(Path::new(env!("CARGO_BIN_EXE_nanokvm-sandbox-fixture")));
    let source = prepared.split_image_runtime();
    let before = fs::read("/proc/self/mountinfo").unwrap();
    let source_bytes = fs::read(source.join("usr/runtime-proof")).unwrap();
    let output = prepared.run_image(&source);
    assert_eq!(output.status.code(), Some(0), "image runtime: {output:?}");
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(fs::read("/proc/self/mountinfo").unwrap(), before);
    assert_eq!(
        fs::read(source.join("usr/runtime-proof")).unwrap(),
        source_bytes
    );
    assert_eq!(
        fs::read_dir(prepared.root.join("usr")).unwrap().count(),
        0,
        "child runtime mount leaked to parent (empty placeholder is expected)"
    );
    assert!(
        !prepared.root.join("etc/ld-musl-riscv64.path").exists()
            || fs::metadata(prepared.root.join("etc/ld-musl-riscv64.path"))
                .unwrap()
                .len()
                == 0
    );

    // A mutable prepopulated runtime/loader override cannot be covered up.
    fs::create_dir_all(prepared.root.join("usr")).unwrap();
    fs::write(prepared.root.join("usr/untrusted"), b"synthetic").unwrap();
    let output = prepared.run_image(&source);
    assert_eq!(output.status.code(), Some(72), "nonempty slot: {output:?}");
    fs::remove_dir_all(prepared.root.join("usr")).unwrap();
    fs::write(
        prepared.root.join("etc/ld-musl-riscv64.path"),
        b"/data/untrusted\n",
    )
    .unwrap();
    let output = prepared.run_image(&source);
    assert_eq!(
        output.status.code(),
        Some(72),
        "loader override: {output:?}"
    );
}

#[test]
fn real_host_sshd_uses_readonly_image_runtime_not_private_executable_tree() {
    let prepared = PreparedRoot::new(Path::new("/usr/sbin/sshd"));
    fs::create_dir_all(prepared.root.join("run/sshd")).unwrap();
    fs::write(
        prepared.root.join("etc/passwd"),
        b"root:x:0:0:root:/root:/bin/sh\nsshd:x:999:999:sshd:/:/bin/false\n",
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
    assert!(generated.status.success());
    fs::write(prepared.root.join("etc/ssh/sshd_config"),
        b"HostKey /etc/ssh/ssh_host_ed25519_key\nUsePAM no\nPermitRootLogin yes\nPasswordAuthentication yes\n").unwrap();
    let source = prepared.split_image_runtime();
    let before = fs::read("/proc/self/mountinfo").unwrap();
    let output = prepared.run_image(&source);
    assert_eq!(output.status.code(), Some(0), "image host sshd: {output:?}");
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    fs::write(
        prepared.root.join("etc/ssh/sshd_config"),
        b"InvalidSyntheticDirective yes\n",
    )
    .unwrap();
    let output = prepared.run_image(&source);
    assert_eq!(
        output.status.code(),
        Some(255),
        "invalid image host sshd: {output:?}"
    );
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(fs::read("/proc/self/mountinfo").unwrap(), before);
}

#[test]
fn authenticated_identity_builder_feeds_real_sshd_through_the_image_sandbox() {
    use nanokvm_rust_server::{auth::password::Account, config::Config};
    let mut prepared = PreparedRoot::new(Path::new("/usr/sbin/sshd"));
    let source = prepared.split_image_runtime();
    fs::copy("/usr/bin/ssh-keygen", source.join("usr/bin/ssh-keygen")).unwrap();
    let identity = prepared.root.clone();
    for (path, bytes) in [
        (
            "etc/passwd",
            b"root:x:0:0:root:/root:/bin/sh\nsshd:x:999:999:sshd:/var/empty:/bin/false\n"
                .as_slice(),
        ),
        ("etc/group", b"root:x:0:\nsshd:x:999:\n"),
        ("etc/shadow", b"root:!:::::::\nsshd:!:::::::\n"),
        ("etc/hostname", b"synthetic-preflight\n"),
    ] {
        fs::write(identity.join(path), bytes).unwrap();
    }
    fs::create_dir_all(identity.join("etc/kvm")).unwrap();
    let mut config = Config::default();
    config.jwt.secret_key = "synthetic image builder fixture, not a credential".to_string();
    fs::write(
        identity.join("etc/kvm/server.yaml"),
        serde_yaml::to_string(&config).unwrap(),
    )
    .unwrap();
    let account = Account {
        username: "operator".to_string(),
        password: bcrypt::hash("synthetic fixture password", 4).unwrap(),
    };
    fs::write(
        identity.join("etc/kvm/pwd"),
        serde_json::to_vec(&account).unwrap(),
    )
    .unwrap();
    let key = identity.join("etc/ssh/ssh_host_ed25519_key");
    assert!(
        Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()
            .unwrap()
            .status
            .success()
    );
    for (kind, bits) in [("rsa", "2048"), ("ecdsa", "256")] {
        assert!(
            Command::new("/usr/bin/ssh-keygen")
                .args(["-q", "-t", kind, "-b", bits, "-N", "", "-f"])
                .arg(identity.join(format!("etc/ssh/ssh_host_{kind}_key")))
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    fs::create_dir_all(identity.join("etc/ssh/sshd_config.d")).unwrap();
    fs::write(
        identity.join("etc/ssh/sshd_config.d/root.conf"),
        b"Match User root\nMaxAuthTries 3\n",
    )
    .unwrap();
    fs::write(identity.join("etc/ssh/banner"), b"").unwrap();
    fs::write(identity.join("etc/ssh/sshd_config"), b"HostKey /etc/ssh/ssh_host_ed25519_key\nUsePAM no\nPermitRootLogin yes\nPasswordAuthentication yes\nBanner /etc/ssh/banner\nInclude /etc/ssh/sshd_config.d/*.conf\n").unwrap();
    prepared.root = prepared._temporary.path().join("built-identity");
    fs::create_dir(&prepared.root).unwrap();
    fs::set_permissions(&prepared.root, fs::Permissions::from_mode(0o700)).unwrap();
    let before = fs::read("/proc/self/mountinfo").unwrap();
    let output = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user"])
        .arg(env!("CARGO_BIN_EXE_nanokvm-image-runtime-fixture"))
        .arg(&prepared.root)
        .arg(&source)
        .arg(std::process::id().to_string())
        .arg("--prepare-identity")
        .arg(&identity)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "builder + image + native sshd: {output:?}"
    );
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(fs::read("/proc/self/mountinfo").unwrap(), before);
    assert_eq!(fs::read_dir(prepared.root.join("usr")).unwrap().count(), 0);
    assert!(!prepared.root.join("etc/kvm").exists());
    assert_eq!(
        fs::read(prepared.root.join("etc/shadow")).unwrap(),
        b"root:!:::::::\nsshd:!:::::::\n"
    );
    assert_eq!(
        fs::read(prepared.root.join("etc/ssh/ssh_host_ed25519_key")).unwrap(),
        fs::read(&key).unwrap()
    );
    // exec replaces the child (no Rust Drop); this fixture's parent TempDir owns
    // cleanup after wait. The production parent must retain its own root guard.
    use nanokvm_rust_server::update::restore_effective::{RootContext, RootLogin, read_policy};
    fs::write(
        identity.join("etc/ssh/sshd_config.d/specific.conf"),
        b"Match Address 198.51.100.7\nPasswordAuthentication no\n",
    )
    .unwrap();
    let mut policies = Vec::new();
    for (index, address) in ["198.51.100.8", "198.51.100.7", "198.51.100.8"]
        .into_iter()
        .enumerate()
    {
        let root = prepared
            ._temporary
            .path()
            .join(format!("effective-{index}"));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let context = RootContext::new(
            "fixture.example",
            address.parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            22,
            None,
        )
        .unwrap();
        let output = Command::new("/usr/bin/unshare")
            .args(["--user", "--map-root-user"])
            .arg(env!("CARGO_BIN_EXE_nanokvm-image-runtime-fixture"))
            .arg(root)
            .arg(&source)
            .arg(std::process::id().to_string())
            .arg("--prepare-identity")
            .arg(&identity)
            .arg("--effective-root")
            .arg(context.as_argument())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "private effective-policy child failed"
        );
        assert!(output.stderr.is_empty());
        let policy = read_policy(&mut std::io::Cursor::new(output.stdout), &context).unwrap();
        assert_eq!(policy.summary().root_login, RootLogin::Yes);
        assert_eq!(policy.summary().password_authentication, index != 1);
        assert_eq!(policy.summary().max_auth_tries, 3);
        policies.push(policy);
    }
    assert!(policies[0].same_policy_as(&policies[2]));
    assert!(!policies[0].same_policy_as(&policies[1]));
    let sink = prepared._temporary.path().join("not-a-pipe");
    let rejected = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user"])
        .arg(env!("CARGO_BIN_EXE_nanokvm-image-runtime-fixture"))
        .arg(&prepared.root)
        .arg(&source)
        .arg(std::process::id().to_string())
        .arg("--effective-root")
        .arg("user=root,host=fixture.example,addr=198.51.100.8,laddr=192.0.2.2,lport=22")
        .stdin(Stdio::null())
        .stdout(fs::File::create(&sink).unwrap())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(rejected.code(), Some(72));
    assert_eq!(fs::metadata(sink).unwrap().len(), 0);
    for nonblocking in [false, true] {
        let flags = nix::fcntl::OFlag::O_CLOEXEC
            | if nonblocking {
                nix::fcntl::OFlag::O_NONBLOCK
            } else {
                nix::fcntl::OFlag::empty()
            };
        let (read, write) = nix::unistd::pipe2(flags).unwrap();
        let (bad_stdout, retained) = if nonblocking {
            (write, read)
        } else {
            (read, write)
        };
        let rejected = Command::new("/usr/bin/unshare")
            .args(["--user", "--map-root-user"])
            .arg(env!("CARGO_BIN_EXE_nanokvm-image-runtime-fixture"))
            .arg(&prepared.root)
            .arg(&source)
            .arg(std::process::id().to_string())
            .arg("--effective-root")
            .arg("user=root,host=fixture.example,addr=198.51.100.8,laddr=192.0.2.2,lport=22")
            .stdin(Stdio::null())
            .stdout(Stdio::from(bad_stdout))
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(
            rejected.code(),
            Some(72),
            "read-end/nonblocking output must fail before native output"
        );
        drop(retained);
    }
    assert_eq!(fs::read("/proc/self/mountinfo").unwrap(), before);
    // REAL parent ownership spans sequential native image-bind children, then
    // cleanup checks both identity/proof files and child-created mount slots.
    let owned = |name: &str, mode: &str| {
        let root = prepared._temporary.path().join(name);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let output = Command::new("/usr/bin/unshare")
            .args(["--user", "--map-root-user"])
            .arg(env!("CARGO_BIN_EXE_nanokvm-image-runtime-fixture"))
            .arg(&root)
            .arg(&source)
            .arg(std::process::id().to_string())
            .arg("--prepare-identity")
            .arg(&identity)
            .arg(mode)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(
            fs::read_dir(&root).unwrap().count(),
            0,
            "owned root was not cleaned after reaped native child"
        );
        output
    };
    let output = owned("owned-syntax", "--owned-syntax");
    assert!(output.status.success(), "owned syntax: {output:?}");
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let output = owned("owned-keys", "--owned-keys");
    assert!(output.status.success(), "isolated sign/verify: {output:?}");
    assert_eq!(output.stdout, b"keys=3\n");
    assert!(output.stderr.is_empty());
    // OpenSSH 10.6 reads no key of the type 10.5 generated: such a pair goes
    // along unproved, and no other unreadable key does.
    let unreadable = identity.join("etc/ssh/ssh_host_mldsa44_ed25519_key");
    let unreadable_public = identity.join("etc/ssh/ssh_host_mldsa44_ed25519_key.pub");
    fs::write(
        &unreadable,
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        &unreadable_public,
        b"ssh-mldsa44-ed25519@openssh.com AAAAH3NzaC1tbGRzYTQ0 root@old\n",
    )
    .unwrap();
    let output = owned("owned-retired-type", "--owned-keys");
    assert!(output.status.success(), "retired key type: {output:?}");
    assert_eq!(output.stdout, b"keys=3\n");
    fs::write(
        &unreadable_public,
        b"ssh-mldsa44-ed25519 AAAAE3NzaC1tbGRzYTQ0 root@new\n",
    )
    .unwrap();
    let output = owned("owned-unreadable-current-type", "--owned-keys");
    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    fs::remove_file(&unreadable_public).unwrap();
    let output = owned("owned-unreadable-no-companion", "--owned-keys");
    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    fs::remove_file(&unreadable).unwrap();
    // Missing optional public companion remains supported, not factory-filled.
    let companion_path = identity.join("etc/ssh/ssh_host_ed25519_key.pub");
    let companion = fs::read(&companion_path).unwrap();
    fs::remove_file(&companion_path).unwrap();
    let output = owned("owned-no-companion", "--owned-keys");
    assert!(
        output.status.success(),
        "missing public companion: {output:?}"
    );
    fs::write(&companion_path, &companion).unwrap();
    fs::write(
        &companion_path,
        fs::read(identity.join("etc/ssh/ssh_host_rsa_key.pub")).unwrap(),
    )
    .unwrap();
    let output = owned("owned-wrong-companion", "--owned-keys");
    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    fs::write(&companion_path, companion).unwrap();
    // A changed Ed25519 seed with both stored public fields intact can pass
    // native -y. It MUST fail the isolated sign/verify proof and still clean up.
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use zeroize::Zeroizing;
    let original = Zeroizing::new(fs::read(&key).unwrap());
    let mut encoded = Zeroizing::new(Vec::with_capacity(original.len()));
    for line in original.split(|b| *b == b'\n') {
        if !line.starts_with(b"-----") {
            encoded.extend_from_slice(line);
        }
    }
    let mut blob = Zeroizing::new(STANDARD.decode(&*encoded).unwrap());
    fn skip_string(bytes: &[u8], at: &mut usize) -> std::ops::Range<usize> {
        let length = u32::from_be_bytes(bytes[*at..*at + 4].try_into().unwrap()) as usize;
        *at += 4;
        let range = *at..*at + length;
        *at += length;
        range
    }
    let mut at = b"openssh-key-v1\0".len();
    for _ in 0..3 {
        skip_string(&blob, &mut at);
    }
    assert_eq!(&blob[at..at + 4], &1_u32.to_be_bytes());
    at += 4;
    skip_string(&blob, &mut at);
    let block = skip_string(&blob, &mut at);
    at = block.start + 8;
    skip_string(&blob, &mut at);
    skip_string(&blob, &mut at);
    let secret = skip_string(&blob, &mut at);
    assert_eq!(secret.len(), 64);
    blob[secret.start] ^= 1;
    let encoded = Zeroizing::new(STANDARD.encode(&*blob));
    let changed = Zeroizing::new(format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
        *encoded
    ));
    fs::write(&key, changed.as_bytes()).unwrap();
    assert!(
        Command::new("/usr/bin/ssh-keygen")
            .args(["-y", "-P", "", "-f"])
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let output = owned("owned-altered-seed", "--owned-keys");
    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    fs::write(&key, &*original).unwrap();
    // Disabled SSH with no keys is preserved as an explicit count=0 result,
    // never force-enabled or silently supplied with factory identity.
    for kind in ["rsa", "ecdsa", "ed25519"] {
        fs::remove_file(identity.join(format!("etc/ssh/ssh_host_{kind}_key"))).unwrap();
        fs::remove_file(identity.join(format!("etc/ssh/ssh_host_{kind}_key.pub"))).unwrap();
    }
    fs::write(identity.join("etc/kvm/ssh_stop"), []).unwrap();
    let output = owned("owned-disabled-no-keys", "--owned-keys");
    assert!(
        output.status.success(),
        "disabled zero-key state: {output:?}"
    );
    assert_eq!(output.stdout, b"keys=0\n");
    assert_eq!(fs::read("/proc/self/mountinfo").unwrap(), before);
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
