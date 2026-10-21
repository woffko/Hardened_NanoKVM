use super::*;
use std::{
    io::Read,
    os::unix::fs::MetadataExt,
    process::{Child, Command, Stdio},
};

struct OwnedProbe(Option<Child>);
impl Drop for OwnedProbe {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_private_root(case: &str) {
    let root = tempfile::tempdir().unwrap();
    for directory in ["root/custom pico", "writers", "outside"] {
        fs::create_dir_all(root.path().join(directory)).unwrap();
        fs::set_permissions(
            root.path().join(directory),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let child = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "api::picoclaw::config_publication_tests::private_root_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_PICO_CONFIG_FIXTURE", root.path())
        .env("NANOKVM_PICO_CONFIG_CASE", case)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut probe = OwnedProbe(Some(child));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if probe.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "owned fixture timed out: {case}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = probe.0.take().unwrap().wait_with_output().unwrap();
    assert!(output.status.success(), "{case}: {output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("pico-config-fixture-ran")
    );
}

#[test]
fn actual_json_publication_rejects_symlinks_without_touching_the_destination() {
    run_private_root("symlink");
}

#[test]
fn actual_yaml_publication_rejects_hardlinks_without_touching_the_destination() {
    run_private_root("hardlink");
}

#[test]
fn actual_json_publication_replaces_an_inode_instead_of_truncating_live_readers() {
    run_private_root("replace");
}

#[test]
fn actual_first_creation_and_missing_yaml_keep_the_legacy_document_shape() {
    run_private_root("create");
}

#[test]
fn actual_malformed_documents_fail_without_reset_or_replacement() {
    run_private_root("malformed");
}

#[test]
fn actual_config_io_rejects_unsafe_modes_directories_and_fifos() {
    run_private_root("types");
}

#[test]
fn actual_config_io_rejects_symlink_and_writable_ancestors() {
    run_private_root("ancestors");
}

#[test]
fn actual_config_io_rejects_oversize_without_truncating_or_leaving_temporaries() {
    run_private_root("size");
}

#[test]
fn actual_first_run_preflight_creates_private_home_but_never_repairs_bad_config() {
    run_private_root("home");
}

#[test]
fn actual_relative_home_stays_relative_to_the_selected_cwd() {
    run_private_root("relative");
}

#[test]
fn actual_config_io_never_crosses_a_private_mount_boundary() {
    run_private_root("mount");
}

fn put_private(path: &Path, data: &[u8]) {
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn private_root_child() {
    let Ok(root) = std::env::var("NANOKVM_PICO_CONFIG_FIXTURE") else {
        return;
    };
    let case = std::env::var("NANOKVM_PICO_CONFIG_CASE").unwrap();
    nix::unistd::chroot(Path::new(&root)).unwrap();
    std::env::set_current_dir("/").unwrap();
    let writers = crate::update::state_writers::StateWriters::for_test_parent(
        fs::File::open("/writers").unwrap(),
    );
    let permit = writers.configuration().unwrap();
    let directory = Path::new("/root/custom pico");
    let sentinel = Path::new("/outside/synthetic-sentinel");
    fs::write(sentinel, b"synthetic-sentinel-unchanged").unwrap();
    fs::set_permissions(sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    match case.as_str() {
        "symlink" => {
            let target = directory.join("config.json");
            std::os::unix::fs::symlink(sentinel, &target).unwrap();
            assert!(save_json(&permit, &target, &json!({"fixture": "new"})).is_err());
            assert_eq!(fs::read(sentinel).unwrap(), b"synthetic-sentinel-unchanged");
            assert!(target.symlink_metadata().unwrap().is_symlink());
        }
        "hardlink" => {
            let target = directory.join(".security.yml");
            fs::hard_link(sentinel, &target).unwrap();
            assert!(
                save_yaml(
                    &permit,
                    &target,
                    &serde_yaml::Value::String("synthetic-new".into())
                )
                .is_err()
            );
            assert_eq!(fs::read(sentinel).unwrap(), b"synthetic-sentinel-unchanged");
            assert_eq!(
                target.metadata().unwrap().ino(),
                sentinel.metadata().unwrap().ino()
            );
        }
        "replace" => {
            let target = directory.join("config.json");
            fs::write(&target, b"synthetic-old-reader").unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
            let before = target.metadata().unwrap();
            let mut old_reader = fs::File::open(&target).unwrap();
            save_json(&permit, &target, &json!({"fixture": "new"})).unwrap();
            let mut old_bytes = Vec::new();
            old_reader.read_to_end(&mut old_bytes).unwrap();
            assert_eq!(old_bytes, b"synthetic-old-reader");
            assert_ne!(target.metadata().unwrap().ino(), before.ino());
            assert_eq!(target.metadata().unwrap().mode() & 0o7777, 0o600);
            assert_eq!(
                serde_json::from_slice::<JsonValue>(&fs::read(target).unwrap()).unwrap(),
                json!({"fixture": "new"})
            );
        }
        "create" => {
            let target = directory.join("config.json");
            let value = json!({"custom": {"preserved": "тест"}, "model_list": []});
            save_json(&permit, &target, &value).unwrap();
            let loaded = load_config_document_at(target.clone()).unwrap();
            assert_eq!(loaded.raw, value);
            assert_eq!(
                loaded.security,
                serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
            );
            assert!(!directory.join(".security.yml").exists());
            save_yaml(
                &permit,
                &directory.join(".security.yml"),
                &serde_yaml::Value::String("synthetic".into()),
            )
            .unwrap();
            assert_eq!(target.metadata().unwrap().mode() & 0o7777, 0o600);
            assert_eq!(
                directory.join(".security.yml").metadata().unwrap().mode() & 0o7777,
                0o600
            );
            assert_eq!(fs::read_dir(directory).unwrap().count(), 2);
        }
        "malformed" => {
            let target = directory.join("config.json");
            assert!(load_config_document_at(target.clone()).is_err());
            assert!(!target.exists());
            put_private(&target, b"{synthetic-malformed-json");
            assert!(load_config_document_at(target.clone()).is_err());
            assert_eq!(fs::read(&target).unwrap(), b"{synthetic-malformed-json");
            put_private(&target, b"{}");
            let security = directory.join(".security.yml");
            put_private(&security, b"fixture: [not-closed");
            assert!(load_config_document_at(target.clone()).is_err());
            assert_eq!(fs::read(&security).unwrap(), b"fixture: [not-closed");
            assert_eq!(fs::read(target).unwrap(), b"{}");
        }
        "types" => {
            let target = directory.join("config.json");
            for mode in [0o644, 0o400, 0o660, 0o1600] {
                put_private(&target, b"{}");
                fs::set_permissions(&target, fs::Permissions::from_mode(mode)).unwrap();
                assert!(load_config_document_at(target.clone()).is_err());
                assert!(save_json(&permit, &target, &json!({"new": true})).is_err());
                assert_eq!(target.metadata().unwrap().mode() & 0o7777, mode);
                assert_eq!(fs::read(&target).unwrap(), b"{}");
                fs::remove_file(&target).unwrap();
            }
            fs::create_dir(&target).unwrap();
            assert!(load_config_document_at(target.clone()).is_err());
            assert!(save_json(&permit, &target, &json!({})).is_err());
            fs::remove_dir(&target).unwrap();
            nix::unistd::mkfifo(&target, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
            assert!(load_config_document_at(target.clone()).is_err());
            assert!(save_json(&permit, &target, &json!({})).is_err());
            assert_eq!(fs::read_dir(directory).unwrap().count(), 1);
        }
        "ancestors" => {
            put_private(&directory.join("config.json"), b"{}");
            fs::set_permissions(directory, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(load_config_document_at(directory.join("config.json")).is_err());
            assert!(save_json(&permit, &directory.join("config.json"), &json!({})).is_err());
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
            std::os::unix::fs::symlink(directory, "/root/alias").unwrap();
            assert!(load_config_document_at(PathBuf::from("/root/alias/config.json")).is_err());
            assert!(save_json(&permit, Path::new("/root/alias/config.json"), &json!({})).is_err());
            assert_eq!(fs::read(directory.join("config.json")).unwrap(), b"{}");
        }
        "size" => {
            let target = directory.join("config.json");
            put_private(&target, b"{}");
            let limit = crate::update::picoclaw_config::MAX_FILE_BYTES;
            fs::OpenOptions::new()
                .write(true)
                .open(&target)
                .unwrap()
                .set_len(limit as u64 + 1)
                .unwrap();
            let before = target.metadata().unwrap();
            assert!(load_config_document_at(target.clone()).is_err());
            assert!(save_json(&permit, &target, &json!({})).is_err());
            assert_eq!(target.metadata().unwrap().len(), before.len());
            assert_eq!(target.metadata().unwrap().ino(), before.ino());
            put_private(&target, b"{}");
            assert!(save_json(&permit, &target, &json!({"oversize": "x".repeat(limit)})).is_err());
            assert_eq!(fs::read(target).unwrap(), b"{}");
            assert_eq!(fs::read_dir(directory).unwrap().count(), 1);
        }
        "home" => {
            let target = Path::new("/root/new pico/nested/config.json");
            assert!(crate::update::picoclaw_config::needs_onboard(&permit, target).unwrap());
            assert_eq!(
                target.parent().unwrap().metadata().unwrap().mode() & 0o7777,
                0o700
            );
            assert!(!target.exists());
            save_json(&permit, target, &json!({})).unwrap();
            assert!(!crate::update::picoclaw_config::needs_onboard(&permit, target).unwrap());
            put_private(target, b"{bad-fixture");
            assert!(!crate::update::picoclaw_config::needs_onboard(&permit, target).unwrap());
            assert!(load_config_document_at(target.to_path_buf()).is_err());
            assert_eq!(fs::read(target).unwrap(), b"{bad-fixture");
        }
        "relative" => {
            std::env::set_current_dir("/root").unwrap();
            let target = Path::new("custom pico/config.json");
            save_json(&permit, target, &json!({"relative": true})).unwrap();
            assert_eq!(
                load_config_document_at(target.to_path_buf()).unwrap().raw,
                json!({"relative": true})
            );
        }
        "mount" => {
            let mount = Path::new("/root/mounted");
            fs::create_dir(mount).unwrap();
            nix::mount::mount(
                Some("tmpfs"),
                mount,
                Some("tmpfs"),
                nix::mount::MsFlags::MS_NODEV | nix::mount::MsFlags::MS_NOEXEC,
                Some("size=1m"),
            )
            .unwrap();
            let target = mount.join("config.json");
            assert!(crate::update::picoclaw_config::needs_onboard(&permit, &target).is_err());
            assert!(load_config_document_at(target.clone()).is_err());
            assert!(save_json(&permit, &target, &json!({})).is_err());
            assert_eq!(fs::read_dir(mount).unwrap().count(), 0);
        }
        _ => panic!("unknown fixture case"),
    }
    println!("pico-config-fixture-ran");
}
