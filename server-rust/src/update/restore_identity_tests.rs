use super::*;
use crate::update::{
    restore_capsule::{open_capsule, prepare_capsule},
    restore_policy,
};
use std::{
    fs,
    io::{Cursor, Read},
    os::unix::fs::symlink,
};
use tar::{Archive, Builder};
use tempfile::{TempDir, tempdir};

// Owner-sensitive builder tests run in one exact disposable mapped-root test.
// No real host identity or parent namespaces/resources are changed.
fn preflight_namespace(name: &str) -> bool {
    if std::env::var_os("NANOKVM_PREFLIGHT_OWNER_FIXTURE").is_some() {
        return true;
    }
    let before = fs::read("/proc/self/mountinfo").unwrap();
    let output = std::process::Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            name.strip_prefix("nanokvm_rust_server::").unwrap(),
            "--test-threads=1",
            "--nocapture",
        ])
        .env("NANOKVM_PREFLIGHT_OWNER_FIXTURE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "private preflight fixture: {output:?}"
    );
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    assert!(
        stdout.contains("running 1 test\n") && stdout.contains("1 passed; 0 failed;"),
        "exact preflight fixture did not run: {output:?}"
    );
    assert_eq!(fs::read("/proc/self/mountinfo").unwrap(), before);
    false
}

#[test]
fn private_ssh_root_uses_only_authenticated_native_identity_and_inert_server_data() {
    if !preflight_namespace(concat!(
        module_path!(),
        "::private_ssh_root_uses_only_authenticated_native_identity_and_inert_server_data"
    )) {
        return;
    }
    use crate::update::restore_preflight::prepare_sshd_root;
    use std::os::unix::fs::MetadataExt;
    let (source, config) = fixture();
    put(
        source.path(),
        "etc/ssh/sshd_config.d/extra.conf",
        b"Match User root\nMaxAuthTries 3\n",
    );
    put(source.path(), "etc/ssh/banner", b"");
    put(source.path(), "root/.ssh/authorized_keys", b"");
    for path in [
        "root/.ssh/id_rsa",
        "root/.ssh/config",
        "etc/kvm/scripts/task.sh",
        "root/.picoclaw/workspace/note.txt",
    ] {
        put(
            source.path(),
            path,
            b"synthetic unrelated state, never execute",
        );
    }
    let mut identity = checked(&captured(source.path(), &config, CWD, CONFIG_PATH)).unwrap();
    let original_shadow = member(&mut identity, "etc/shadow");
    let target = tempdir().unwrap();
    let prepared = prepare_sshd_root(&mut identity, target.path()).unwrap();
    assert_eq!(prepared.checked_path().unwrap(), target.path());
    for path in [
        "etc/passwd",
        "etc/group",
        "etc/shadow",
        "etc/ssh/sshd_config",
        "etc/ssh/sshd_config.d/extra.conf",
        "etc/ssh/ssh_host_ed25519_key",
        "etc/ssh/banner",
        "root/.ssh/authorized_keys",
    ] {
        assert_eq!(
            fs::read(target.path().join(path)).unwrap(),
            member(&mut identity, path)
        );
        let metadata = fs::metadata(target.path().join(path)).unwrap();
        assert!(metadata.is_file());
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.nlink()),
            (0, 0, 1)
        );
        let expected = if matches!(path, "etc/passwd" | "etc/group") {
            0o644
        } else {
            0o600
        };
        assert_eq!(metadata.mode() & 0o7777, expected);
    }
    for path in [
        "etc/kvm",
        "boot",
        "kvmapp",
        "root/.ssh/id_rsa",
        "root/.ssh/config",
        "root/.picoclaw",
        "usr",
        "lib",
        "bin",
        "sbin",
        "lib64",
    ] {
        assert!(
            !target.path().join(path).exists(),
            "unrelated data/runtime imported: {path}"
        );
    }
    for path in [".oldroot", "proc", "sys", "data", "var/empty"] {
        assert_eq!(fs::read_dir(target.path().join(path)).unwrap().count(), 0);
    }
    assert!(fs::read(target.path().join("dev/null")).unwrap().is_empty());
    assert_eq!(
        fs::read(target.path().join("etc/nsswitch.conf")).unwrap(),
        b"passwd: files\ngroup: files\nshadow: files\nhosts: files\n"
    );
    assert_eq!(
        fs::read(source.path().join("etc/shadow")).unwrap(),
        original_shadow
    );
    prepared.cleanup().unwrap();
    assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
    let prepared = prepare_sshd_root(&mut identity, target.path()).unwrap();
    drop(prepared);
    assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
}

#[test]
fn owned_ssh_job_cleans_typed_identity_on_success_cancel_transfer_and_native_failure() {
    if !preflight_namespace(concat!(
        module_path!(),
        "::owned_ssh_job_cleans_typed_identity_on_success_cancel_transfer_and_native_failure"
    )) {
        return;
    }
    use crate::update::{
        raw_transport::TransferContext,
        restore_job::{Check, JobError, Outcome, PinnedSshHelper, SshPreflightJob},
        restore_preflight::prepare_sshd_root,
    };
    use std::{fs::File, io::Write, os::fd::AsRawFd, sync::atomic::AtomicBool};
    fn image(size: usize) -> File {
        let mut writable = tempfile::tempfile().unwrap();
        writable.write_all(&vec![0x42; size]).unwrap();
        let readonly = File::open(format!("/proc/self/fd/{}", writable.as_raw_fd())).unwrap();
        drop(writable);
        readonly
    }
    let (source, config) = fixture();
    let mut identity = checked(&captured(source.path(), &config, CWD, CONFIG_PATH)).unwrap();
    for (program, cancelled, bad_images, unexpected) in [
        ("/usr/bin/true", false, false, false),
        ("/usr/bin/true", true, false, false),
        ("/usr/bin/true", false, true, false),
        ("/usr/bin/false", false, false, false),
        ("/usr/bin/true", false, false, true),
    ] {
        let target = tempdir().unwrap();
        let prepared = prepare_sshd_root(&mut identity, target.path()).unwrap();
        if unexpected {
            put(
                target.path(),
                "etc/ssh/unexpected.conf",
                b"do not remove unknown recovery state",
            );
        }
        // Unit-only helper provenance bypass. These installed host programs do
        // NOT validate SSH/images: the test establishes lifecycle/cleanup only.
        let helper = PinnedSshHelper::host_fixture(Path::new(program), target.path());
        let result = SshPreflightJob {
            helper,
            identity: prepared,
            images: if bad_images {
                [File::open("/dev/null").unwrap(), image(65537)]
            } else {
                [image(1025), image(65537)]
            },
            transfer: TransferContext::new([42; 16], "0.3.0-raw.fixture", [1025, 65537]).unwrap(),
            image_mountpoint: target.path().join("unused-host-fixture-mountpoint"),
            check: Check::Syntax,
        }
        .run(&AtomicBool::new(cancelled));
        if unexpected {
            assert!(matches!(result, Err(JobError::Cleanup)));
            assert_eq!(
                fs::read(target.path().join("etc/ssh/unexpected.conf")).unwrap(),
                b"do not remove unknown recovery state"
            );
        } else {
            assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
            if cancelled {
                assert!(matches!(result, Err(JobError::Cancelled)));
            } else if bad_images {
                assert!(matches!(result, Err(JobError::Process)));
            } else if program.ends_with("false") {
                assert!(matches!(result, Err(JobError::Native)));
            } else {
                assert!(matches!(result, Ok(Outcome::Syntax)));
            }
        }
    }
}

#[test]
fn private_ssh_root_rejects_existing_unsafe_redirected_or_nested_mount_roots() {
    if !preflight_namespace(concat!(
        module_path!(),
        "::private_ssh_root_rejects_existing_unsafe_redirected_or_nested_mount_roots"
    )) {
        return;
    }
    use crate::update::restore_preflight::prepare_sshd_root;
    use std::os::unix::fs::PermissionsExt;
    let (source, config) = fixture();
    let mut identity = checked(&captured(source.path(), &config, CWD, CONFIG_PATH)).unwrap();
    let target = tempdir().unwrap();
    for mode in [0o755, 0o770, 0o1700] {
        fs::set_permissions(target.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(prepare_sshd_root(&mut identity, target.path()).is_err());
        assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
    }
    fs::set_permissions(target.path(), fs::Permissions::from_mode(0o700)).unwrap();
    put(target.path(), "unrelated", b"keep synthetic existing state");
    assert!(prepare_sshd_root(&mut identity, target.path()).is_err());
    assert_eq!(
        fs::read(target.path().join("unrelated")).unwrap(),
        b"keep synthetic existing state"
    );
    fs::remove_file(target.path().join("unrelated")).unwrap();
    let alias = source.path().join("target-alias");
    symlink(target.path(), &alias).unwrap();
    assert!(prepare_sshd_root(&mut identity, &alias).is_err());
    assert!(prepare_sshd_root(&mut identity, Path::new("relative-root")).is_err());
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .unwrap();
    let replacement = tempdir().unwrap();
    nix::mount::mount(
        Some(replacement.path()),
        target.path(),
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .unwrap();
    let rejected = prepare_sshd_root(&mut identity, target.path()).is_err();
    nix::mount::umount2(target.path(), nix::mount::MntFlags::empty()).unwrap();
    assert!(
        rejected,
        "same-filesystem bind mount is not private rootfs staging"
    );
    assert_eq!(fs::read_dir(replacement.path()).unwrap().count(), 0);
    assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
}

#[test]
fn private_ssh_root_enforces_new_host_file_budget_before_creating_entries() {
    if !preflight_namespace(concat!(
        module_path!(),
        "::private_ssh_root_enforces_new_host_file_budget_before_creating_entries"
    )) {
        return;
    }
    use crate::update::restore_preflight::{PrepareRootError, prepare_sshd_root};
    let (source, config) = fixture();
    put(source.path(), "etc/hosts", &vec![b'x'; 64 * 1024 + 1]);
    let mut identity = checked(&captured(source.path(), &config, CWD, CONFIG_PATH)).unwrap();
    let target = tempdir().unwrap();
    assert!(matches!(
        prepare_sshd_root(&mut identity, target.path()),
        Err(PrepareRootError::Input)
    ));
    assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
}

#[test]
fn private_ssh_root_cleanup_does_not_follow_parent_links_or_delete_replacements() {
    if !preflight_namespace(concat!(
        module_path!(),
        "::private_ssh_root_cleanup_does_not_follow_parent_links_or_delete_replacements"
    )) {
        return;
    }
    use crate::update::restore_preflight::prepare_sshd_root;
    let (source, config) = fixture();
    let mut identity = checked(&captured(source.path(), &config, CWD, CONFIG_PATH)).unwrap();
    for kind in 0..3 {
        let target = tempdir().unwrap();
        let prepared = prepare_sshd_root(&mut identity, target.path()).unwrap();
        let outside = tempdir().unwrap();
        put(
            outside.path(),
            "shadow",
            b"outside synthetic state must survive",
        );
        match kind {
            0 => put(target.path(), "root/unknown", b"untracked synthetic state"),
            1 => {
                fs::rename(
                    target.path().join("etc/shadow"),
                    outside.path().join("original-shadow"),
                )
                .unwrap();
                put(target.path(), "etc/shadow", b"replacement synthetic state");
            }
            _ => {
                fs::rename(
                    target.path().join("etc"),
                    outside.path().join("original-etc"),
                )
                .unwrap();
                symlink(outside.path(), target.path().join("etc")).unwrap();
            }
        }
        assert!(prepared.cleanup().is_err());
        assert_eq!(
            fs::read(outside.path().join("shadow")).unwrap(),
            b"outside synthetic state must survive"
        );
        if kind == 0 {
            assert_eq!(
                fs::read(target.path().join("root/unknown")).unwrap(),
                b"untracked synthetic state"
            );
        }
        if kind == 1 {
            assert_eq!(
                fs::read(target.path().join("etc/shadow")).unwrap(),
                b"replacement synthetic state"
            );
        }
    }
    let parent = tempdir().unwrap();
    let target = parent.path().join("root");
    fs::create_dir(&target).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let prepared = prepare_sshd_root(&mut identity, &target).unwrap();
    let original = parent.path().join("original");
    fs::rename(&target, &original).unwrap();
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    put(&target, "keep", b"new outer root must survive");
    assert!(prepared.checked_path().is_err());
    prepared.cleanup().unwrap();
    assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
    assert_eq!(
        fs::read(target.join("keep")).unwrap(),
        b"new outer root must survive"
    );
}

#[test]
fn private_ssh_root_cleans_partial_native_inputs_after_actual_kernel_write_failure() {
    if !preflight_namespace(concat!(
        module_path!(),
        "::private_ssh_root_cleans_partial_native_inputs_after_actual_kernel_write_failure"
    )) {
        return;
    }
    use crate::update::restore_preflight::{PrepareRootError, prepare_sshd_root};
    use nix::sys::{
        resource::{Resource, getrlimit, setrlimit},
        signal::{SigSet, SigmaskHow, Signal, pthread_sigmask},
    };
    let (source, config) = fixture();
    let mut identity = checked(&captured(source.path(), &config, CWD, CONFIG_PATH)).unwrap();
    let target = tempdir().unwrap();
    let previous = getrlimit(Resource::RLIMIT_FSIZE).unwrap();
    let config_index = identity
        .members()
        .iter()
        .position(|m| m.path == "etc/ssh/sshd_config")
        .unwrap();
    assert!(identity.members()[config_index].size > 64);
    for path in ["etc/passwd", "etc/group", "etc/shadow"] {
        let index = identity
            .members()
            .iter()
            .position(|m| m.path == path)
            .unwrap();
        assert!(index < config_index && identity.members()[index].size <= 64);
    }
    let mut blocked = SigSet::empty();
    blocked.add(Signal::SIGXFSZ);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked), None).unwrap();
    // NSS and native tables fit; sshd_config then writes partially and gets
    // EFBIG. Cleanup must remove the already-copied synthetic shadow as well.
    setrlimit(Resource::RLIMIT_FSIZE, 64, previous.1).unwrap();
    let result = prepare_sshd_root(&mut identity, target.path());
    setrlimit(Resource::RLIMIT_FSIZE, previous.0, previous.1).unwrap();
    assert!(matches!(result, Err(PrepareRootError::Io)));
    assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
    // SIGXFSZ stays blocked only in this disposable exact-test child.
}

const CONFIG_PATH: &str = "/etc/kvm/server.yaml";
const CWD: &str = "/etc/kvm";
const NATIVE_PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/sh\n";
const NATIVE_GROUP: &[u8] = b"root:x:0:\n";
const NATIVE_SHADOW: &[u8] = b"root:!:::::::\n";

fn signed_accounts() -> AccountFiles<'static> {
    AccountFiles {
        passwd: NATIVE_PASSWD,
        group: NATIVE_GROUP,
        shadow: NATIVE_SHADOW,
        gshadow: None,
    }
}

fn put(root: &Path, path: &str, bytes: &[u8]) {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}
fn write_config(root: &Path, path: &str, config: &Config) {
    put(
        root,
        path,
        serde_yaml::to_string(config).unwrap().as_bytes(),
    );
}
fn fixture() -> (TempDir, Config) {
    let root = tempdir().unwrap();
    for path in restore_policy::REQUIRED {
        put(root.path(), path, b"synthetic OS identity\n");
    }
    put(root.path(), "etc/passwd", NATIVE_PASSWD);
    put(root.path(), "etc/group", NATIVE_GROUP);
    put(root.path(), "etc/shadow", NATIVE_SHADOW);
    put(
        root.path(),
        "etc/ssh/sshd_config",
        include_bytes!(
            "../../../buildroot-external/hardened-sg2002/board/sg2002/overlay/etc/ssh/sshd_config"
        ),
    );
    put(
        root.path(),
        "etc/ssh/ssh_host_ed25519_key",
        b"synthetic path-guard fixture, not a valid host key",
    );
    let account = Account {
        username: "operator".to_string(),
        password: bcrypt::hash("synthetic fixture password", 4).unwrap(),
    };
    put(root.path(), ACCOUNT, &serde_json::to_vec(&account).unwrap());
    let mut config = Config::default();
    config.jwt.secret_key = "synthetic runtime key, not a credential".to_string();
    write_config(root.path(), CONFIG_PATH, &config);
    (root, config)
}
fn captured(root: &Path, config: &Config, cwd: &str, config_path: &str) -> Vec<u8> {
    let staging = tempdir().unwrap();
    let mut archive = capture_effective(
        root,
        staging.path(),
        config,
        Path::new(cwd),
        Path::new(config_path),
        &signed_accounts(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    archive.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.len() as u64, archive.size());
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    bytes
}
fn checked(bytes: &[u8]) -> Result<IdentityCheckedRestore> {
    checked_for_image(bytes, &signed_accounts())
}
fn checked_for_image(bytes: &[u8], signed: &AccountFiles<'_>) -> Result<IdentityCheckedRestore> {
    let staging = tempdir().unwrap();
    let mut ciphertext = Vec::new();
    let secret = prepare_capsule(
        "0.3.0-raw.13",
        bytes.len() as u64,
        &mut Cursor::new(bytes),
        &mut ciphertext,
    )
    .unwrap();
    let plaintext = open_capsule(&secret, &mut Cursor::new(ciphertext), staging.path()).unwrap();
    check_identity(restore_archive::validate(plaintext).unwrap(), signed)
}
fn member(archive: &mut IdentityCheckedRestore, path: &str) -> Vec<u8> {
    let index = archive
        .members()
        .iter()
        .position(|m| m.path == path)
        .unwrap();
    let mut bytes = Vec::new();
    archive.copy_file(index, &mut bytes).unwrap();
    bytes
}
fn alter(bytes: &[u8], path: &str, replacement: Option<&[u8]>) -> Vec<u8> {
    let mut result = Vec::new();
    {
        let mut out = Builder::new(&mut result);
        let mut archive = Archive::new(Cursor::new(bytes));
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            let mut header = entry.header().clone();
            if header.path_bytes() == format!("files/{path}").as_bytes() {
                let Some(replacement) = replacement else {
                    continue;
                };
                data = replacement.to_vec();
                header.set_size(data.len() as u64);
                header.set_cksum();
            }
            out.append(&header, &data[..]).unwrap();
        }
        out.finish().unwrap();
    }
    result
}

#[test]
fn absent_optional_config_uses_defaults_and_existing_effective_file_secret() {
    let (root, config) = fixture();
    fs::remove_file(root.path().join(CONFIG)).unwrap();
    put(
        root.path(),
        SESSION,
        format!("{}\n", config.jwt.secret_key).as_bytes(),
    );
    let original = fs::read(root.path().join(ACCOUNT)).unwrap();
    let mut restored = checked(&captured(root.path(), &config, CWD, CONFIG_PATH)).unwrap();
    let canonical: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(canonical.proto, "http");
    assert_eq!(canonical.jwt.secret_key, config.jwt.secret_key);
    assert_eq!(canonical.cert.crt, "/etc/kvm/server.crt");
    assert_eq!(member(&mut restored, ACCOUNT), original);
    assert!(!root.path().join(CONFIG).exists());
    assert_eq!(fs::read(root.path().join(ACCOUNT)).unwrap(), original);
}

#[test]
fn embedded_whitespace_key_without_session_file_is_preserved_verbatim() {
    let (root, mut config) = fixture();
    config.jwt.secret_key = "  synthetic\tkey\nwith trailing whitespace  ".to_string();
    write_config(root.path(), CONFIG_PATH, &config);
    assert!(!root.path().join(SESSION).exists());
    let mut restored = checked(&captured(root.path(), &config, CWD, CONFIG_PATH)).unwrap();
    let canonical: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(canonical.jwt.secret_key, config.jwt.secret_key);
    assert_eq!(
        member(&mut restored, SESSION),
        format!("{}\n", config.jwt.secret_key).as_bytes()
    );
}

#[test]
fn custom_config_account_secret_and_relative_tls_paths_become_canonical() {
    let (root, mut effective) = fixture();
    let account = fs::read(root.path().join(ACCOUNT)).unwrap();
    put(root.path(), "root/custom/account", &account);
    effective.paths.account_file = PathBuf::from("account");
    effective.paths.session_secret_file = PathBuf::from("secret");
    effective.cert.crt = "tls/certificate.pem".to_string();
    effective.cert.key = "tls/private.pem".to_string();
    effective.proto = "https".to_string();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["fixture.invalid".to_string()]).unwrap();
    put(
        root.path(),
        "root/custom/tls/certificate.pem",
        cert.pem().as_bytes(),
    );
    put(
        root.path(),
        "root/custom/tls/private.pem",
        key_pair.serialize_pem().as_bytes(),
    );
    put(
        root.path(),
        "root/custom/secret",
        format!("{}\n", effective.jwt.secret_key).as_bytes(),
    );
    let mut persisted = effective.clone();
    persisted.jwt.secret_key.clear();
    write_config(root.path(), "/root/custom/config.yaml", &persisted);
    put(root.path(), ACCOUNT, b"stale default account must not win");
    put(root.path(), KEY, b"stale default key must not win");
    let mut restored = checked(&captured(
        root.path(),
        &effective,
        "/root/custom",
        "/root/custom/config.yaml",
    ))
    .unwrap();
    let config: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(config.proto, "https");
    assert_eq!(config.paths.account_file, Path::new("/etc/kvm/pwd"));
    assert_eq!(
        config.paths.session_secret_file,
        Path::new("/etc/kvm/session_secret")
    );
    assert_eq!(member(&mut restored, ACCOUNT), account);
    assert_eq!(member(&mut restored, CERT), cert.pem().as_bytes());
    assert_eq!(
        member(&mut restored, KEY),
        key_pair.serialize_pem().as_bytes()
    );
    assert!(
        !restored
            .members()
            .iter()
            .any(|m| m.path.starts_with("root/custom/"))
    );
}

#[test]
fn newer_persisted_preferences_are_not_overwritten_by_startup_config() {
    let (root, effective) = fixture();
    let mut persisted = effective.clone();
    persisted.security.allow_raw_system_updates = true;
    persisted.security.allow_terminal = true;
    persisted.security.access_token_duration = 1800;
    persisted.host = "127.0.0.1".to_string();
    persisted.port.http = 8080;
    persisted.turn.turn_cred = "synthetic saved preference".to_string();
    write_config(root.path(), CONFIG_PATH, &persisted);
    let before = fs::read(root.path().join(CONFIG)).unwrap();
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let config: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(config.host, persisted.host);
    assert_eq!(config.port.http, 8080);
    assert!(config.security.allow_raw_system_updates && config.security.allow_terminal);
    assert_eq!(config.security.access_token_duration, 1800);
    assert_eq!(config.turn.turn_cred, persisted.turn.turn_cred);
    assert_eq!(fs::read(root.path().join(CONFIG)).unwrap(), before);
}

#[test]
fn valid_pending_tls_preferences_are_preserved_but_http_is_not_forced_to_https() {
    let (root, effective) = fixture();
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let unchanged: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(unchanged.proto, "http");
    assert!(
        !restored
            .members()
            .iter()
            .any(|m| m.path == CERT || m.path == KEY)
    );
    let pair = rcgen::generate_simple_self_signed(vec!["fixture.invalid".to_string()]).unwrap();
    let mut persisted = effective.clone();
    persisted.proto = "https".to_string();
    persisted.cert.crt = "/root/pending/certificate".to_string();
    persisted.cert.key = "/root/pending/key".to_string();
    put(
        root.path(),
        "root/pending/certificate",
        pair.cert.pem().as_bytes(),
    );
    put(
        root.path(),
        "root/pending/key",
        pair.key_pair.serialize_pem().as_bytes(),
    );
    write_config(root.path(), CONFIG_PATH, &persisted);
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let next_boot: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(next_boot.proto, "https");
    assert_eq!(member(&mut restored, CERT), pair.cert.pem().as_bytes());
}

#[test]
fn canonicalization_preserves_all_known_config_fields_except_fixed_paths_and_legacy_alias() {
    let (root, effective) = fixture();
    let mut persisted = effective.clone();
    persisted.authentication = "disable".to_string();
    persisted.security.allow_auth_disable = true;
    persisted.security.allowed_origins = vec!["https://fixture.invalid".to_string()];
    persisted.logger.level = "debug".to_string();
    persisted.logger.file = "stdout".to_string();
    persisted.stun = "stun:fixture.invalid:3478".to_string();
    persisted.turn.turn_user = "synthetic turn user".to_string();
    persisted.turn.turn_cred = "synthetic turn preference".to_string();
    persisted.compatibility_mode = true;
    write_config(root.path(), CONFIG_PATH, &persisted);
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let actual: serde_yaml::Value = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    persisted.cert.crt = "/etc/kvm/server.crt".to_string();
    persisted.cert.key = "/etc/kvm/server.key".to_string();
    let expected = serde_yaml::to_value(&persisted).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn legacy_embedded_key_and_media_alias_are_normalized_without_losing_secret() {
    let (root, effective) = fixture();
    put(
        root.path(),
        CONFIG,
        format!(
            "jwt:\n  secretKey: '{}'\npaths:\n  image_directory: /data\n",
            effective.jwt.secret_key
        )
        .as_bytes(),
    );
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let canonical: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(canonical.jwt.secret_key, effective.jwt.secret_key);
    assert!(canonical.jwt.secret_key_legacy.is_empty());
    assert_eq!(
        canonical.paths.image_directory,
        Paths::default().image_directory
    );
}

#[test]
fn maximum_file_secret_with_crlf_is_accepted_without_trimming_embedded_keys() {
    let (root, mut effective) = fixture();
    effective.jwt.secret_key = "s".repeat(MAX_SECRET);
    let mut persisted = effective.clone();
    persisted.jwt.secret_key.clear();
    write_config(root.path(), CONFIG_PATH, &persisted);
    put(
        root.path(),
        SESSION,
        format!("{}\r\n", effective.jwt.secret_key).as_bytes(),
    );
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let canonical: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(canonical.jwt.secret_key, effective.jwt.secret_key);
}

#[test]
fn pending_identity_changes_fail_before_creating_any_capture_spool() {
    for kind in [0, 1, 2] {
        let (root, effective) = fixture();
        let staging = tempdir().unwrap();
        let mut persisted = effective.clone();
        match kind {
            0 => persisted.paths.account_file = PathBuf::from("/root/other-account"),
            1 => persisted.jwt.secret_key = "synthetic pending rotation".to_string(),
            _ => {
                persisted.jwt.secret_key.clear();
                put(root.path(), SESSION, b"synthetic mismatched file key\n");
            }
        }
        write_config(root.path(), CONFIG_PATH, &persisted);
        assert!(matches!(
            capture_effective(
                root.path(),
                staging.path(),
                &effective,
                Path::new(CWD),
                Path::new(CONFIG_PATH),
                &signed_accounts()
            ),
            Err(RestoreIdentityError::InvalidState)
        ));
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    }
}

#[test]
fn malformed_account_or_config_has_no_fallback_and_no_secret_in_error() {
    for path in [ACCOUNT, CONFIG] {
        let (root, config) = fixture();
        let staging = tempdir().unwrap();
        put(root.path(), path, b"synthetic-secret-marker: [malformed");
        let error = capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
            &signed_accounts(),
        )
        .err()
        .unwrap();
        assert!(!format!("{error:?} {error}").contains("synthetic-secret-marker"));
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    }
}

#[test]
fn invalid_account_hashes_and_missing_identity_are_not_restore_ready() {
    let (root, config) = fixture();
    let bytes = captured(root.path(), &config, CWD, CONFIG_PATH);
    for hash in [
        "plaintext is not a hash",
        "$2b$99$invalid",
        "$argon2id$v=19$m=0,t=0,p=0$salt$hash",
    ] {
        let account = serde_json::to_vec(&Account {
            username: "operator".to_string(),
            password: hash.to_string(),
        })
        .unwrap();
        assert!(checked(&alter(&bytes, ACCOUNT, Some(&account))).is_err());
    }
    assert!(checked(&alter(&bytes, CONFIG, None)).is_err());
    // Structural validation rejects missing/empty account and secret already.
    assert!(checked(&alter(&bytes, CERT, None)).is_ok());
}

#[test]
fn existing_argon2_hashes_are_preserved_without_rehashing() {
    let (root, config) = fixture();
    let account = Account {
        username: "operator".to_string(),
        password: crate::auth::password::hash_password("synthetic fixture password").unwrap(),
    };
    let bytes = serde_json::to_vec(&account).unwrap();
    put(root.path(), ACCOUNT, &bytes);
    let mut restored = checked(&captured(root.path(), &config, CWD, CONFIG_PATH)).unwrap();
    assert_eq!(member(&mut restored, ACCOUNT), bytes);
}

#[test]
fn https_missing_malformed_and_mismatched_keys_are_rejected() {
    let (root, mut config) = fixture();
    config.proto = "https".to_string();
    write_config(root.path(), CONFIG_PATH, &config);
    let staging = tempdir().unwrap();
    assert!(
        capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
            &signed_accounts()
        )
        .is_err()
    );
    put(root.path(), CERT, b"not a certificate");
    put(root.path(), KEY, b"not a private key");
    assert!(
        capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
            &signed_accounts()
        )
        .is_err()
    );
    let a = rcgen::generate_simple_self_signed(vec!["fixture.invalid".to_string()]).unwrap();
    let b = rcgen::generate_simple_self_signed(vec!["fixture.invalid".to_string()]).unwrap();
    put(root.path(), CERT, a.cert.pem().as_bytes());
    put(root.path(), KEY, b.key_pair.serialize_pem().as_bytes());
    assert!(
        capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
            &signed_accounts()
        )
        .is_err()
    );
    put(root.path(), KEY, a.key_pair.serialize_pem().as_bytes());
    let bytes = captured(root.path(), &config, CWD, CONFIG_PATH);
    assert!(
        checked(&alter(
            &bytes,
            KEY,
            Some(b.key_pair.serialize_pem().as_bytes())
        ))
        .is_err()
    );
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
}

#[test]
fn restored_config_cannot_redirect_identity_or_weaken_signed_layout() {
    let (root, config) = fixture();
    let bytes = captured(root.path(), &config, CWD, CONFIG_PATH);
    for kind in [0, 1, 2, 3] {
        let mut canonical = checked(&bytes).unwrap();
        let mut changed: Config = serde_yaml::from_slice(&member(&mut canonical, CONFIG)).unwrap();
        match kind {
            0 => changed.paths.account_file = PathBuf::from("/data/media/account"),
            1 => changed.paths.system_update_public_key = PathBuf::from("/data/key"),
            2 => changed.paths.image_directory = PathBuf::from("/"),
            _ => changed.jwt.secret_key = "synthetic replaced secret".to_string(),
        }
        assert!(
            checked(&alter(
                &bytes,
                CONFIG,
                Some(serde_yaml::to_string(&changed).unwrap().as_bytes())
            ))
            .is_err()
        );
    }
}

#[test]
fn custom_source_aliases_traversal_and_oversized_state_fail_closed() {
    let (root, mut config) = fixture();
    config.paths.account_file = PathBuf::from("/root/custom-account");
    write_config(root.path(), CONFIG_PATH, &config);
    fs::create_dir_all(root.path().join("root")).unwrap();
    symlink(
        root.path().join(ACCOUNT),
        root.path().join("root/custom-account"),
    )
    .unwrap();
    let staging = tempdir().unwrap();
    assert!(
        capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
            &signed_accounts()
        )
        .is_err()
    );
    fs::remove_file(root.path().join("root/custom-account")).unwrap();
    put(
        root.path(),
        "root/custom-account",
        &vec![b'a'; MAX_ACCOUNT + 1],
    );
    assert!(
        capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
            &signed_accounts()
        )
        .is_err()
    );
    assert!(source_path(Path::new("../account"), Path::new(CWD)).is_err());
    assert!(source_path(Path::new("account"), Path::new("relative-cwd")).is_err());
    assert!(source_path(Path::new(""), Path::new(CWD)).is_err());
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
}

#[test]
fn identity_resource_limits_and_secret_consistency_are_enforced() {
    let (root, config) = fixture();
    let bytes = captured(root.path(), &config, CWD, CONFIG_PATH);
    assert!(checked(&alter(&bytes, CONFIG, Some(&vec![b'a'; MAX_CONFIG + 1]))).is_err());
    assert!(
        checked(&alter(
            &bytes,
            SESSION,
            Some(b"synthetic different secret\n")
        ))
        .is_err()
    );
    let mut out = PrivateBuffer {
        bytes: Zeroizing::new(Vec::with_capacity(4)),
        limit: 4,
    };
    out.write_all(b"1234").unwrap();
    assert!(out.write_all(b"5").is_err());
    assert_eq!(&*out.bytes, b"1234");
}

#[test]
fn unknown_config_fields_never_disappear_silently_during_capture() {
    for section in [
        "", "port", "cert", "logger", "jwt", "turn", "security", "paths",
    ] {
        let (root, effective) = fixture();
        let staging = tempdir().unwrap();
        let original = serde_yaml::to_string(&effective).unwrap();
        let changed = if section.is_empty() {
            format!("{original}future_extension: synthetic-extension-marker\n")
        } else {
            original.replacen(
                &format!("{section}:\n"),
                &format!("{section}:\n  future_extension: synthetic-extension-marker\n"),
                1,
            )
        };
        // Normal server parsing is intentionally unchanged and historically
        // ignores these fields. Restore must stop, not silently discard them.
        assert!(serde_yaml::from_str::<Config>(&changed).is_ok());
        put(root.path(), CONFIG, changed.as_bytes());
        let result = capture_effective(
            root.path(),
            staging.path(),
            &effective,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
            &signed_accounts(),
        );
        assert!(result.is_err(), "unknown field in {section} was dropped");
        let error = result.err().unwrap();
        assert!(matches!(error, RestoreIdentityError::UnsupportedConfig));
        assert!(!format!("{error:?} {error}").contains("synthetic-extension-marker"));
        assert_eq!(
            fs::read(root.path().join(CONFIG)).unwrap(),
            changed.as_bytes()
        );
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    }
}

#[test]
fn authenticated_restore_still_rejects_unknown_config_extensions() {
    let (root, effective) = fixture();
    let bytes = captured(root.path(), &effective, CWD, CONFIG_PATH);
    let mut canonical = checked(&bytes).unwrap();
    let original = String::from_utf8(member(&mut canonical, CONFIG)).unwrap();
    for section in [
        "", "port", "cert", "logger", "jwt", "turn", "security", "paths",
    ] {
        let changed = if section.is_empty() {
            format!("{original}future_extension: synthetic-extension-marker\n")
        } else {
            original.replacen(
                &format!("{section}:\n"),
                &format!("{section}:\n  future_extension: synthetic-extension-marker\n"),
                1,
            )
        };
        assert!(checked(&alter(&bytes, CONFIG, Some(changed.as_bytes()))).is_err());
    }
}

#[test]
fn all_legacy_config_aliases_remain_supported_by_the_restore_inventory() {
    let yaml = b"jwt:\n  secretKey: synthetic-key\n  refreshTokenDuration: 123\n  revokeTokensOnLogout: false\nturn:\n  turnAddr: relay.invalid\n  turnUser: synthetic-user\n  turnCred: synthetic-credential\nsecurity:\n  loginLockoutDuration: 23\n  loginMaxFailures: 7\n";
    let mut config = parse_config(yaml).unwrap();
    config.0.normalize_legacy_fields();
    assert_eq!(config.0.jwt.secret_key, "synthetic-key");
    assert_eq!(config.0.jwt.refresh_token_duration, 123);
    assert!(!config.0.jwt.revoke_tokens_on_logout);
    assert_eq!(config.0.turn.turn_addr, "relay.invalid");
    assert_eq!(config.0.turn.turn_user, "synthetic-user");
    assert_eq!(config.0.turn.turn_cred, "synthetic-credential");
    assert_eq!(config.0.security.login_lockout_duration, 23);
    assert_eq!(config.0.security.login_max_failures, 7);
}

#[test]
fn supported_config_comments_partial_defaults_and_known_anchors_still_parse() {
    for yaml in [
        "{}",
        "",
        "# comment only\n",
        "host: &host 0.0.0.0\nstun: *host\n",
        "security: {allowed_origins: ['https://fixture.invalid']}\n",
        "jwt: {secret_key: 'synthetic # quoted : key'}\n",
        "port: {http: 8080}\n",
    ] {
        let normal = serde_yaml::from_str::<Config>(yaml).unwrap();
        let restored = parse_config(yaml.as_bytes()).unwrap();
        assert_eq!(
            serde_yaml::to_string(&normal).unwrap(),
            serde_yaml::to_string(&restored.0).unwrap()
        );
    }
}

#[test]
fn unsupported_yaml_merge_fields_are_not_silently_discarded() {
    let yaml = b"security: {<<: {future_extension: synthetic-marker}}\n";
    assert!(serde_yaml::from_slice::<Config>(yaml).is_ok());
    assert!(matches!(
        parse_config(yaml),
        Err(RestoreIdentityError::UnsupportedConfig)
    ));
}

#[test]
fn duplicate_aliases_wrong_types_and_multiple_documents_have_no_fallback() {
    for yaml in [
        "null\n",
        "host: 0.0.0.0\nhost: 127.0.0.1\n",
        "jwt: {refreshTokenDuration: 1, refresh_token_duration: 2}\n",
        "turn: {turnAddr: one.invalid, turn_addr: two.invalid}\n",
        "security: {loginMaxFailures: 3, login_max_failures: 4}\n",
        "port: {http: {future_extension: synthetic-marker}}\n",
        "security: {allowed_origins: [{future_extension: synthetic-marker}]}\n",
        "{}\n---\n{future_extension: synthetic-marker}\n",
        "{[future_extension]: synthetic-marker}\n",
    ] {
        let error = parse_config(yaml.as_bytes()).err().unwrap();
        assert!(!format!("{error:?} {error}").contains("synthetic-marker"));
    }
}

#[test]
fn capture_merges_signed_native_services_without_mutating_source_or_root_hash() {
    let (root, config) = fixture();
    let original_shadow =
        b"root:$5$synthetic$...........................................:20000:0:99999:7:::\n";
    put(root.path(), "etc/shadow", original_shadow);
    let signed = AccountFiles {
        passwd: b"root:x:0:0:root:/root:/bin/sh\npicoclaw:x:200:200:Service:/var/lib/picoclaw:/bin/false\n",
        group: b"root:x:0:\npicoclaw:x:200:\n",
        shadow: b"root:*:::::::\npicoclaw:!:::::::\n",
        gshadow: None,
    };
    let staging = tempdir().unwrap();
    let mut snapshot = capture_effective(
        root.path(),
        staging.path(),
        &config,
        Path::new(CWD),
        Path::new(CONFIG_PATH),
        &signed,
    )
    .unwrap();
    let mut bytes = Vec::new();
    snapshot.read_to_end(&mut bytes).unwrap();
    let mut restored = checked_for_image(&bytes, &signed).unwrap();
    assert_eq!(member(&mut restored, "etc/passwd"), signed.passwd);
    assert!(member(&mut restored, "etc/shadow").starts_with(original_shadow));
    assert_eq!(
        fs::read(root.path().join("etc/passwd")).unwrap(),
        NATIVE_PASSWD
    );
    assert_eq!(
        fs::read(root.path().join("etc/shadow")).unwrap(),
        original_shadow
    );
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    for (path, mode) in [
        ("etc/passwd", 0o644),
        ("etc/group", 0o644),
        ("etc/shadow", 0o600),
    ] {
        assert_eq!(
            restored
                .members()
                .iter()
                .find(|m| m.path == path)
                .unwrap()
                .mode,
            mode
        );
    }
    // Fully authenticated, internally consistent old tables are still invalid
    // if they omit the service identities required by the exact signed image.
    let missing = alter(
        &alter(
            &alter(&bytes, "etc/passwd", Some(NATIVE_PASSWD)),
            "etc/group",
            Some(NATIVE_GROUP),
        ),
        "etc/shadow",
        Some(original_shadow),
    );
    assert!(matches!(
        checked_for_image(&missing, &signed),
        Err(RestoreIdentityError::Native(
            restore_native::NativeAccountError::Conflict
        ))
    ));
}

#[test]
fn native_preflight_failures_leave_source_unchanged_and_create_no_capture_spool() {
    for kind in 0..4 {
        let (root, config) = fixture();
        match kind {
            0 => put(
                root.path(),
                "etc/passwd",
                b"root:x:0:0:root:/root:/bin/false\n",
            ),
            1 => put(
                root.path(),
                "etc/shadow",
                b"root:$unknown$salt$synthetic-marker:::::::\n",
            ),
            2 => put(
                root.path(),
                "etc/shadow",
                &vec![b'x'; restore_native::MAX_TABLE_BYTES + 1],
            ),
            _ => {
                fs::rename(
                    root.path().join("etc/passwd"),
                    root.path().join("etc/original-passwd"),
                )
                .unwrap();
                symlink("original-passwd", root.path().join("etc/passwd")).unwrap();
            }
        }
        let before = fs::read(root.path().join("etc/shadow")).unwrap();
        let staging = tempdir().unwrap();
        let error = capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
            &signed_accounts(),
        )
        .err()
        .unwrap();
        assert!(!format!("{error:?} {error}").contains("synthetic-marker"));
        assert_eq!(fs::read(root.path().join("etc/shadow")).unwrap(), before);
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    }
}

#[test]
fn authenticated_native_rows_are_rechecked_not_trusted_as_opaque_payload() {
    let (root, config) = fixture();
    let bytes = captured(root.path(), &config, CWD, CONFIG_PATH);
    for (path, data) in [
        ("etc/passwd", &b"root:x:0:0:root:/root:/bin/false\n"[..]),
        (
            "etc/shadow",
            &b"root:$unknown$salt$synthetic-marker:::::::\n"[..],
        ),
        ("etc/group", &b"root:x:0:missing-user\n"[..]),
    ] {
        assert!(checked(&alter(&bytes, path, Some(data))).is_err());
    }
}

#[test]
fn ssh_fragments_empty_trust_files_and_root_password_policy_survive_authenticated_roundtrip() {
    let (root, config) = fixture();
    let main = b"Include sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\nBanner /etc/ssh/banner\nTrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pub\n";
    let fragment = "etc/ssh/sshd_config.d/operator.conf";
    put(root.path(), "etc/ssh/sshd_config", main);
    put(
        root.path(),
        fragment,
        b"Match User root\n  MaxAuthTries 3\n",
    );
    let empty_paths = [
        "root/.ssh/authorized_keys",
        "root/.ssh/authorized_keys2",
        "etc/ssh/banner",
        "etc/ssh/trusted-user-ca-keys.pub",
    ];
    for path in empty_paths {
        put(root.path(), path, b"");
    }
    let key = fs::read(root.path().join("etc/ssh/ssh_host_ed25519_key")).unwrap();
    let mut restored = checked(&captured(root.path(), &config, CWD, CONFIG_PATH)).unwrap();
    assert_eq!(member(&mut restored, "etc/ssh/sshd_config"), main);
    assert_eq!(
        member(&mut restored, fragment),
        b"Match User root\n  MaxAuthTries 3\n"
    );
    assert_eq!(member(&mut restored, "etc/ssh/ssh_host_ed25519_key"), key);
    for path in empty_paths {
        assert!(member(&mut restored, path).is_empty());
        assert_eq!(
            restored.members().iter().filter(|m| m.path == path).count(),
            1
        );
    }
    assert_eq!(member(&mut restored, "etc/shadow"), NATIVE_SHADOW);
    assert_eq!(
        fs::read(root.path().join("etc/ssh/sshd_config")).unwrap(),
        main
    );
}

#[test]
fn ssh_unsupported_authority_and_aliases_fail_before_capture_without_source_mutation() {
    for kind in 0..6 {
        let (root, config) = fixture();
        let path = "etc/ssh/sshd_config";
        match kind {
            0 => put(
                root.path(),
                path,
                b"Banner /etc/shadow # synthetic-marker\n",
            ),
            1 => put(
                root.path(),
                "etc/ssh/sshd_config.d/latent.conf",
                b"Match User nobody\nAuthorizedKeysCommand /data/synthetic-marker\n",
            ),
            2 => put(root.path(), "root/.ssh/rc", b"synthetic-marker\n"),
            3 => put(
                root.path(),
                "root/.ssh/environment",
                b"ENV=/data/synthetic-marker\n",
            ),
            4 => {
                fs::remove_file(root.path().join(path)).unwrap();
                put(root.path(), "etc/ssh/real.conf", b"PermitRootLogin yes\n");
                symlink("real.conf", root.path().join(path)).unwrap();
            }
            _ => put(root.path(), path, &vec![b'x'; 64 * 1024 + 1]),
        }
        let before = fs::read(root.path().join(path)).unwrap();
        let staging = tempdir().unwrap();
        let error = capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
            &signed_accounts(),
        )
        .err()
        .unwrap();
        assert!(!format!("{error:?} {error}").contains("synthetic-marker"));
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
        assert_eq!(fs::read(root.path().join(path)).unwrap(), before);
    }
}

#[test]
fn authenticated_ssh_state_is_rechecked_and_keyless_start_once_never_passes_preflight() {
    let (root, config) = fixture();
    let fragment = "etc/ssh/sshd_config.d/operator.conf";
    put(root.path(), fragment, b"PasswordAuthentication yes\n");
    let bytes = captured(root.path(), &config, CWD, CONFIG_PATH);
    for (path, replacement) in [
        ("etc/ssh/sshd_config", Some(&b"Include /data/*.conf\n"[..])),
        (
            fragment,
            Some(&b"Match User nobody\nForceCommand /data/helper\n"[..]),
        ),
        ("etc/ssh/ssh_host_ed25519_key", None),
    ] {
        assert!(matches!(
            checked(&alter(&bytes, path, replacement)),
            Err(RestoreIdentityError::Ssh(_))
        ));
    }
    fs::remove_file(root.path().join("etc/ssh/ssh_host_ed25519_key")).unwrap();
    put(root.path(), "etc/kvm/ssh_stop", b"");
    checked(&captured(root.path(), &config, CWD, CONFIG_PATH)).unwrap();
    put(root.path(), "boot/start_ssh_once", b"");
    let staging = tempdir().unwrap();
    assert!(matches!(
        capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
            &signed_accounts()
        ),
        Err(RestoreIdentityError::Ssh(_))
    ));
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn native_key_probe_checks_the_authenticated_archive_without_changing_identity_bytes() {
    let (root, config) = fixture();
    let key_path = root.path().join("etc/ssh/ssh_host_ed25519_key");
    fs::remove_file(&key_path).unwrap();
    assert!(
        std::process::Command::new("/usr/bin/ssh-keygen")
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "synthetic archive fixture",
                "-f"
            ])
            .arg(&key_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let key = Zeroizing::new(fs::read(&key_path).unwrap());
    let public_path = root.path().join("etc/ssh/ssh_host_ed25519_key.pub");
    let public = Zeroizing::new(fs::read(&public_path).unwrap());
    let bytes = Zeroizing::new(captured(root.path(), &config, CWD, CONFIG_PATH));
    let mut restored = checked(&bytes).unwrap();
    let staging = tempdir().unwrap();
    restored
        .check_native_host_keys(staging.path())
        .await
        .unwrap();
    assert!(
        Zeroizing::new(member(&mut restored, "etc/ssh/ssh_host_ed25519_key")).as_slice()
            == key.as_slice()
    );
    assert!(
        Zeroizing::new(member(&mut restored, "etc/ssh/ssh_host_ed25519_key.pub")).as_slice()
            == public.as_slice()
    );
    assert!(Zeroizing::new(fs::read(key_path).unwrap()).as_slice() == key.as_slice());
    assert!(Zeroizing::new(fs::read(public_path).unwrap()).as_slice() == public.as_slice());
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    let changed = Zeroizing::new(alter(
        &bytes,
        "etc/ssh/ssh_host_ed25519_key.pub",
        Some(b"ssh-ed25519 AAAA synthetic-marker\n"),
    ));
    let mut restored = checked(&changed).unwrap();
    let error = restored
        .check_native_host_keys(staging.path())
        .await
        .err()
        .unwrap();
    assert!(!format!("{error:?} {error}").contains("synthetic-marker"));
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn native_key_probe_keeps_disabled_ssh_keyless_but_rejects_invalid_latent_identity() {
    for kind in 0..4 {
        let (root, config) = fixture();
        put(root.path(), "etc/kvm/ssh_stop", b"");
        match kind {
            0 | 1 => {
                fs::remove_file(root.path().join("etc/ssh/ssh_host_ed25519_key")).unwrap();
                if kind == 1 {
                    put(
                        root.path(),
                        "etc/ssh/ssh_host_ed25519_key.pub",
                        b"ssh-ed25519 AAAA",
                    );
                }
            }
            2 => put(root.path(), "etc/ssh/ssh_host_ed25519_key", b""),
            _ => put(
                root.path(),
                "etc/ssh/ssh_host_ed25519_key.pub",
                &vec![b'x'; 16 * 1024 + 1],
            ),
        }
        let mut restored = checked(&captured(root.path(), &config, CWD, CONFIG_PATH)).unwrap();
        let staging = tempdir().unwrap();
        let result = restored.check_native_host_keys(staging.path()).await;
        if kind == 0 {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(RestoreIdentityError::Ssh(_))));
        }
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    }
}
