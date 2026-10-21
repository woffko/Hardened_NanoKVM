use super::*;
use std::{
    io::Read,
    os::unix::fs::MetadataExt,
    process::{Child, Command, Stdio},
};

#[path = "picoclaw_onboard_tests.rs"]
mod onboard;
#[path = "picoclaw_config_pair_tests.rs"]
mod pair;

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
        .env("PICOCLAW_HOME", "/root/custom pico")
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

#[test]
fn actual_model_pair_preflights_both_documents_before_changing_either() {
    run_private_root("pair-preflight");
}

#[test]
fn actual_model_pair_keeps_custom_fields_and_publishes_the_matching_secret() {
    run_private_root("pair-model");
}

#[test]
fn actual_launch_generation_binds_both_documents_and_explicit_security_absence() {
    run_private_root("generation");
}

#[test]
fn actual_startup_defaults_do_not_republish_an_unchanged_pair() {
    run_private_root("startup-noop");
}

#[test]
fn actual_startup_defaults_preserve_explicit_local_tool_restrictions() {
    run_private_root("startup-policy");
}

#[test]
fn actual_startup_defaults_reject_malformed_local_policy_before_publication() {
    run_private_root("startup-invalid-policy");
}

#[test]
fn actual_api_control_without_current_support_preserves_config_and_uninstall_state() {
    run_private_root("native-control-unavailable");
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
    let directory = Path::new("/root/custom pico");
    if case == "pair-lock-read" {
        assert!(matches!(
            load_config_document_at(directory.join("config.json")),
            Err(AppError::Conflict(_))
        ));
        println!("pico-config-fixture-ran");
        return;
    }
    let permit = writers.configuration().unwrap();
    let sentinel = Path::new("/outside/synthetic-sentinel");
    fs::write(sentinel, b"synthetic-sentinel-unchanged").unwrap();
    fs::set_permissions(sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    if case.starts_with("onboard-") {
        onboard::exercise(&case, &permit, directory);
        println!("pico-config-fixture-ran");
        return;
    }
    match case.as_str() {
        "native-control-unavailable" => {
            startup_fixture(directory, json!({}));
            fs::create_dir_all("/usr/bin").unwrap();
            let binary = Path::new(PICOCLAW_BINARY_PATH);
            put_private(binary, b"synthetic, never executed runtime\n");
            let config = directory.join("config.json");
            let security = directory.join(".security.yml");
            let before = [fs::read(&config).unwrap(), fs::read(&security).unwrap()];
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let blocker = crate::update::operation_lock::ProcessLock::acquire().unwrap();
                assert!(matches!(
                    native_control_ready().await,
                    Err(AppError::Conflict(message))
                        if message == "picoclaw native control admission unavailable"
                ));
                drop(blocker);
                assert!(start_runtime_inner().await.is_err());
                assert_eq!(
                    [fs::read(&config).unwrap(), fs::read(&security).unwrap()],
                    before,
                    "native refusal must precede startup/default publication"
                );
                assert!(stop_runtime_inner().await.is_err());
                assert!(onboard_runtime_config().await.is_err());
                assert_ne!(runtime_status().status, "stopped");
                let response = uninstall_runtime().await.unwrap();
                let bytes = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                let body: JsonValue = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(body["code"], CODE_RUNTIME_START_FAILED);
            });
            assert_eq!(
                [fs::read(&config).unwrap(), fs::read(&security).unwrap()],
                before,
                "unverified Stop must not delete either configuration file"
            );
            assert_eq!(
                fs::read(binary).unwrap(),
                b"synthetic, never executed runtime\n"
            );
            assert_eq!(fs::read_dir(directory).unwrap().count(), 2);
        }
        "startup-noop" => {
            startup_fixture(directory, json!({}));
            write_startup_defaults(&permit).unwrap();
            let config = directory.join("config.json");
            let security = directory.join(".security.yml");
            // Formatting/comments are not a reason to replace either inode.
            let doc = load_config_document().unwrap();
            put_private(&config, &serde_json::to_vec(&doc.raw).unwrap());
            let yaml = format!(
                "# synthetic user comment\n{}",
                serde_yaml::to_string(&doc.security).unwrap()
            );
            put_private(&security, yaml.as_bytes());
            let before = [fs::read(&config).unwrap(), fs::read(&security).unwrap()];
            let identity = |path: &Path| {
                let metadata = path.metadata().unwrap();
                (
                    metadata.ino(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            };
            let revisions = [identity(&config), identity(&security)];
            let generation = crate::update::picoclaw_config::current_generation(&config).unwrap();
            for _ in 0..3 {
                write_startup_defaults(&permit).unwrap();
                assert_eq!(
                    [identity(&config), identity(&security)],
                    revisions,
                    "a gateway connection must not republish an unchanged pair"
                );
                assert_eq!(
                    [fs::read(&config).unwrap(), fs::read(&security).unwrap()],
                    before
                );
                assert!(
                    crate::update::picoclaw_config::current_generation(&config).unwrap()
                        == generation
                );
            }
            assert_eq!(fs::read_dir(directory).unwrap().count(), 2);
            let mut changed = load_config_document().unwrap();
            changed.raw["gateway"]["port"] = json!(1);
            put_private(&config, &serde_json::to_vec(&changed.raw).unwrap());
            let changed_generation =
                crate::update::picoclaw_config::current_generation(&config).unwrap();
            write_startup_defaults(&permit).unwrap();
            let restored = load_config_document().unwrap();
            assert_eq!(restored.raw["gateway"]["port"], DEFAULT_GATEWAY_PORT);
            assert_eq!(restored.raw["custom"], "retained");
            assert_eq!(
                resolved_pico_token(&restored.raw, &restored.security),
                "synthetic-gateway-token"
            );
            assert!(
                crate::update::picoclaw_config::current_generation(&config).unwrap()
                    != changed_generation
            );
        }
        "startup-policy" => {
            for (policy, expected) in [
                (json!({}), (true, false)),
                (json!({"restrict_to_workspace": true}), (true, false)),
                (
                    json!({"allow_read_outside_workspace": false}),
                    (true, false),
                ),
                (
                    json!({"restrict_to_workspace": true, "allow_read_outside_workspace": false}),
                    (true, false),
                ),
                (
                    json!({"restrict_to_workspace": false, "allow_read_outside_workspace": true}),
                    (false, true),
                ),
            ] {
                startup_fixture(directory, json!({"agents": {"defaults": policy}}));
                write_startup_defaults(&permit).unwrap();
                let doc = load_config_document().unwrap();
                assert_eq!(
                    doc.raw
                        .pointer("/agents/defaults/restrict_to_workspace")
                        .and_then(JsonValue::as_bool),
                    Some(expected.0)
                );
                assert_eq!(
                    doc.raw
                        .pointer("/agents/defaults/allow_read_outside_workspace")
                        .and_then(JsonValue::as_bool),
                    Some(expected.1)
                );
                assert_eq!(doc.raw["custom"], "retained");
                assert_eq!(doc.raw["tools"]["mcp"]["enabled"], true);
            }
        }
        "startup-invalid-policy" => {
            for raw in [
                json!({"agents": {"defaults": {"restrict_to_workspace": "true"}}}),
                json!({"agents": {"defaults": {"restrict_to_workspace": null}}}),
                json!({"agents": {"defaults": {"allow_read_outside_workspace": 1}}}),
                json!({"agents": {"defaults": {"allow_read_outside_workspace": []}}}),
                json!({"agents": false}),
                json!({"agents": {"defaults": []}}),
            ] {
                startup_fixture(directory, raw);
                fs::remove_file("/etc/kvm/.picoclaw_internal_token").unwrap();
                let config = directory.join("config.json");
                let security = directory.join(".security.yml");
                let before = [fs::read(&config).unwrap(), fs::read(&security).unwrap()];
                assert!(write_startup_defaults(&permit).is_err());
                assert_eq!(
                    [fs::read(&config).unwrap(), fs::read(&security).unwrap()],
                    before
                );
                assert_eq!(fs::read_dir(directory).unwrap().count(), 2);
                assert!(!Path::new("/etc/kvm/.picoclaw_internal_token").exists());
            }
        }
        "generation" => {
            use crate::update::picoclaw_config::{
                current_generation, prepare_launch, replace_pair,
            };
            let config = directory.join("config.json");
            let security = directory.join(".security.yml");
            assert!(prepare_launch(&permit, &config).is_err());
            assert!(!config.exists());
            put_private(&config, br#"{"synthetic":1}"#);
            let absent = current_generation(&config).unwrap();
            let inode = config.metadata().unwrap().ino();
            assert!(prepare_launch(&permit, &config).unwrap() == absent);
            assert_eq!(config.metadata().unwrap().ino(), inode);
            put_private(&security, b"");
            let empty = current_generation(&config).unwrap();
            assert!(empty != absent);
            replace_pair(
                &permit,
                &config,
                br#"{"synthetic":2}"#,
                Some(b"key: synthetic\n"),
            )
            .unwrap();
            let changed = current_generation(&config).unwrap();
            assert!(changed != empty && changed != absent);
            assert!(prepare_launch(&permit, &config).unwrap() == changed);
            fs::set_permissions(&security, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(current_generation(&config).is_err());
            assert!(prepare_launch(&permit, &config).is_err());
            assert_eq!(fs::read(&security).unwrap(), b"key: synthetic\n");
        }
        "generation-pending" => {
            use crate::update::picoclaw_config::{current_generation, prepare_launch};
            let config = directory.join("config.json");
            let security = directory.join(".security.yml");
            let before = [fs::read(&config).unwrap(), fs::read(&security).unwrap()];
            seed_internal_token();
            assert!(write_startup_defaults(&permit).is_err());
            assert!(current_generation(&config).is_err());
            assert_eq!(
                [fs::read(&config).unwrap(), fs::read(&security).unwrap()],
                before
            );
            let generation = prepare_launch(&permit, &config).unwrap();
            assert!(current_generation(&config).unwrap() == generation);
            assert!(!directory.join(".picoclaw-config-pair").exists());
            assert_eq!(load_config_document_at(config).unwrap().raw["epoch"], "new");
            assert_eq!(fs::read(security).unwrap(), b"epoch: new\n");
        }
        "pair-write" => pair::write(&permit, directory),
        "pair-recover" => pair::recover(&permit, directory),
        "pair-refuse" => pair::refuse(&permit, directory, sentinel),
        "pair-model" => {
            let config = directory.join("config.json");
            let security = directory.join(".security.yml");
            let original = json!({"custom": {"keep": true}, "agents": {"defaults": {"custom": "retained"}}, "model_list": [{"model_name": "chosen", "model": "old/chosen", "api_base": "https://old.invalid", "api_key": "synthetic-legacy", "custom": "retained"}]});
            put_private(&config, &serde_json::to_vec(&original).unwrap());
            put_private(&security, b"custom: retained\nmodel_list: {}\n");
            assert_eq!(
                update_model_config_file(
                    &permit,
                    "https://new.invalid/v1",
                    "synthetic-new-key",
                    "new/chosen"
                )
                .unwrap(),
                "chosen"
            );
            let loaded = load_config_document_at(config).unwrap();
            assert_eq!(loaded.raw["custom"], original["custom"]);
            assert_eq!(loaded.raw["agents"]["defaults"]["custom"], "retained");
            assert_eq!(loaded.raw["model_list"][0]["custom"], "retained");
            assert_eq!(
                loaded.raw["model_list"][0]["api_base"],
                "https://new.invalid/v1"
            );
            assert!(loaded.raw["model_list"][0].get("api_key").is_none());
            assert_eq!(loaded.security["custom"].as_str(), Some("retained"));
            assert_eq!(
                loaded.security["model_list"]["chosen:0"]["api_keys"][0].as_str(),
                Some("synthetic-new-key")
            );
            assert!(is_model_configured(&loaded.raw, &loaded.security, "chosen"));
            assert_eq!(fs::read_dir(directory).unwrap().count(), 2);
        }
        "pair-preflight" => {
            let target = directory.join("config.json");
            let security = directory.join(".security.yml");
            let old_config = br#"{"model_list":[],"agents":{"defaults":{"model_name":"old"}}}"#;
            let old_security = b"model_list: {}\n";
            put_private(&target, old_config);
            put_private(&security, old_security);
            let oversized_key = "x".repeat(crate::update::picoclaw_config::MAX_FILE_BYTES);
            assert!(
                update_model_config_file(
                    &permit,
                    "https://fixture.invalid/v1",
                    &oversized_key,
                    "fixture/new-model"
                )
                .is_err()
            );
            assert_eq!(fs::read(&target).unwrap(), old_config);
            assert_eq!(fs::read(&security).unwrap(), old_security);
            assert_eq!(fs::read_dir(directory).unwrap().count(), 2);
        }
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

fn startup_fixture(directory: &Path, mut raw: JsonValue) {
    seed_internal_token();
    raw["custom"] = json!("retained");
    put_private(
        &directory.join("config.json"),
        &serde_json::to_vec(&raw).unwrap(),
    );
    put_private(
        &directory.join(".security.yml"),
        b"channel_list:\n  pico:\n    settings:\n      token: synthetic-gateway-token\n",
    );
}

fn seed_internal_token() {
    fs::create_dir_all("/etc/kvm").unwrap();
    put_private(
        Path::new("/etc/kvm/.picoclaw_internal_token"),
        b"synthetic-internal-token\n",
    );
}
