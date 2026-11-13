use super::*;
use std::os::unix::process::ExitStatusExt;

const HOME: &str = "root/custom pico";
const JOURNAL: &str = ".picoclaw-config-pair";
const OLD_CONFIG: &[u8] = b"{\"epoch\":\"old\"}";
const OLD_SECURITY: &[u8] = b"epoch: old\n";

fn fixture(empty: bool) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for directory in [HOME, "writers", "outside"] {
        fs::create_dir_all(root.path().join(directory)).unwrap();
        fs::set_permissions(
            root.path().join(directory),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    if !empty {
        put_private(&root.path().join(HOME).join("config.json"), OLD_CONFIG);
        put_private(&root.path().join(HOME).join(".security.yml"), OLD_SECURITY);
    }
    root
}

fn command(root: &Path, case: &str) -> Command {
    let mut command = Command::new("/usr/bin/unshare");
    command
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "api::picoclaw::config_publication_tests::private_root_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_PICO_CONFIG_FIXTURE", root)
        .env("NANOKVM_PICO_CONFIG_CASE", case)
        .env("PICOCLAW_HOME", "/root/custom pico")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn stopped_at_with(mut command: Command, point: &str) -> OwnedProbe {
    let child = command
        .env("NANOKVM_PICO_PAIR_CUT", point)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut probe = OwnedProbe(Some(child));
    let output = probe.0.as_mut().unwrap().stdout.as_mut().unwrap();
    let flags = rustix::fs::fcntl_getfl(&*output).unwrap();
    rustix::fs::fcntl_setfl(&*output, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
    let mut bytes = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let expected = format!("pico-pair-cut:{point}\n");
    loop {
        let mut chunk = [0; 1024];
        match output.read(&mut chunk) {
            Ok(0) => panic!("writer ended before {point}"),
            Ok(size) => bytes.extend_from_slice(&chunk[..size]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("checkpoint read: {error}"),
        }
        if bytes
            .windows(expected.len())
            .any(|part| part == expected.as_bytes())
        {
            return probe;
        }
        assert!(bytes.len() < 16384, "unexpected fixture output size");
        assert!(
            std::time::Instant::now() < deadline,
            "checkpoint not reached: {point}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn kill(mut probe: OwnedProbe) {
    let child = probe.0.as_mut().unwrap();
    child.kill().unwrap();
    assert_eq!(child.wait().unwrap().signal(), Some(9));
    probe.0.take();
}

fn finish(mut command: Command) {
    finish_probe(OwnedProbe(Some(command.spawn().unwrap())));
}

fn finish_probe(mut probe: OwnedProbe) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if probe.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "owned recovery fixture timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = probe.0.take().unwrap().wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("pico-config-fixture-ran")
    );
}

#[test]
fn real_sigkill_at_every_pair_publication_boundary_has_a_coherent_recoverable_view() {
    for variant in 0..3 {
        for point in [
            "journal-file-synced",
            "journal-published",
            "journal-parent-synced",
            "config-published",
            "config-parent-synced",
            "security-published",
            "security-parent-synced",
            "pair-verified",
            "journal-removed",
            "journal-retired",
        ] {
            let empty = variant == 1;
            let root = fixture(empty);
            if variant == 2 {
                fs::remove_file(root.path().join(HOME).join(".security.yml")).unwrap();
            }
            let writer = stopped_at_with(command(root.path(), "pair-write"), point);
            if point == "config-published" && variant == 0 {
                let home = root.path().join(HOME);
                assert_eq!(
                    serde_json::from_slice::<JsonValue>(
                        &fs::read(home.join("config.json")).unwrap()
                    )
                    .unwrap()["epoch"],
                    "new"
                );
                assert_eq!(fs::read(home.join(".security.yml")).unwrap(), OLD_SECURITY);
                finish(command(root.path(), "pair-lock-read"));
            }
            kill(writer);
            let mut recovery = command(root.path(), "pair-recover");
            recovery.env(
                "NANOKVM_PICO_PAIR_EXPECT",
                if point == "journal-file-synced" {
                    if empty {
                        "missing"
                    } else if variant == 2 {
                        "old-no-security"
                    } else {
                        "old"
                    }
                } else {
                    "new"
                },
            );
            finish(recovery);
        }
    }
}

#[test]
fn actual_pair_recovery_refuses_corrupt_unsafe_and_foreign_state_without_repair() {
    for damage in [
        "corrupt",
        "foreign-config",
        "foreign-security",
        "mode",
        "symlink",
        "hardlink",
    ] {
        let root = fixture(false);
        kill(stopped_at_with(
            command(root.path(), "pair-write"),
            "config-published",
        ));
        let mut recovery = command(root.path(), "pair-refuse");
        recovery.env("NANOKVM_PICO_PAIR_DAMAGE", damage);
        finish(recovery);
    }
}

#[test]
fn launch_preparation_settles_a_real_interrupted_pair_but_live_comparison_never_does() {
    let root = fixture(false);
    kill(stopped_at_with(
        command(root.path(), "pair-write"),
        "config-published",
    ));
    finish(command(root.path(), "generation-pending"));
}

#[test]
fn actual_pair_retirement_refuses_a_replaced_journal_inode() {
    use std::io::Write;
    let root = fixture(false);
    let mut command = command(root.path(), "pair-write");
    command.env("NANOKVM_PICO_PAIR_EXPECT_FAILURE", "1");
    let mut writer = stopped_at_with(command, "pair-verified");
    let journal = root.path().join(HOME).join(JOURNAL);
    let previous = journal.with_file_name("preserve-foreign-journal");
    let bytes = fs::read(&journal).unwrap();
    fs::rename(&journal, &previous).unwrap();
    put_private(&journal, &bytes);
    let replacement = journal.metadata().unwrap().ino();
    writer
        .0
        .as_mut()
        .unwrap()
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"r")
        .unwrap();
    finish_probe(writer);
    assert_eq!(journal.metadata().unwrap().ino(), replacement);
    assert_eq!(fs::read(&journal).unwrap(), bytes);
    assert!(previous.exists());
}

#[test]
fn actual_recovery_fences_visible_intent_before_publishing_and_survives_another_kill() {
    let root = fixture(false);
    kill(stopped_at_with(
        command(root.path(), "pair-write"),
        "journal-published",
    ));
    let mut recovery = command(root.path(), "pair-recover");
    recovery.env("NANOKVM_PICO_PAIR_EXPECT", "new");
    let recovering = stopped_at_with(recovery, "recovery-intent-synced");
    let home = root.path().join(HOME);
    assert_eq!(fs::read(home.join("config.json")).unwrap(), OLD_CONFIG);
    assert_eq!(fs::read(home.join(".security.yml")).unwrap(), OLD_SECURITY);
    assert!(home.join(JOURNAL).is_file());
    kill(recovering);
    let mut recovery = command(root.path(), "pair-recover");
    recovery.env("NANOKVM_PICO_PAIR_EXPECT", "new");
    finish(recovery);
}

pub(super) fn write(permit: &crate::update::state_writers::ConfigPermit, directory: &Path) {
    // A launchable pair: launch preparation settles it after a cut.
    let mut raw = json!({"epoch": "new"});
    crate::update::picoclaw_policy::enforce(&mut raw, directory).unwrap();
    let doc = ConfigDocument {
        raw,
        security: serde_yaml::from_slice(b"epoch: new\n").unwrap(),
    };
    let result = save_config_document(permit, &directory.join("config.json"), &doc);
    if std::env::var_os("NANOKVM_PICO_PAIR_EXPECT_FAILURE").is_some() {
        assert!(result.is_err());
    } else {
        result.unwrap();
    }
}

pub(super) fn recover(permit: &crate::update::state_writers::ConfigPermit, directory: &Path) {
    let expected = std::env::var("NANOKVM_PICO_PAIR_EXPECT").unwrap();
    let no_security = expected == "old-no-security";
    let epoch = if no_security {
        "old"
    } else {
        expected.as_str()
    };
    let config = directory.join("config.json");
    let security = directory.join(".security.yml");
    let before = [
        fs::read(&config).ok(),
        fs::read(&security).ok(),
        fs::read(directory.join(JOURNAL)).ok(),
    ];
    let loaded = load_config_document_at(config.clone());
    if expected == "missing" {
        assert!(loaded.is_err());
    } else {
        let loaded = loaded.unwrap();
        assert_eq!(loaded.raw["epoch"], epoch);
        if no_security {
            assert!(loaded.security.as_mapping().unwrap().is_empty());
        } else {
            assert_eq!(loaded.security["epoch"].as_str(), Some(epoch));
        }
    }
    assert_eq!(
        [
            fs::read(&config).ok(),
            fs::read(&security).ok(),
            fs::read(directory.join(JOURNAL)).ok()
        ],
        before,
        "reader performed recovery writes"
    );
    assert_eq!(
        crate::update::picoclaw_config::needs_onboard(permit, &config).unwrap(),
        expected == "missing"
    );
    if expected != "missing" {
        assert_eq!(
            serde_json::from_slice::<JsonValue>(&fs::read(&config).unwrap()).unwrap()["epoch"],
            epoch
        );
        if no_security {
            assert!(!security.exists());
        } else {
            assert_eq!(
                serde_yaml::from_slice::<serde_yaml::Value>(&fs::read(&security).unwrap()).unwrap()
                    ["epoch"]
                    .as_str(),
                Some(epoch)
            );
        }
        let inodes = [
            Some(config.metadata().unwrap().ino()),
            security.metadata().ok().map(|value| value.ino()),
        ];
        assert!(!crate::update::picoclaw_config::needs_onboard(permit, &config).unwrap());
        assert_eq!(
            [
                Some(config.metadata().unwrap().ino()),
                security.metadata().ok().map(|value| value.ino())
            ],
            inodes
        );
    }
    assert!(!directory.join(JOURNAL).exists());
    for entry in fs::read_dir(directory).unwrap() {
        let metadata = entry.unwrap().metadata().unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!((metadata.uid(), metadata.nlink()), (0, 1));
    }
    // A killed pre-commit temporary is private but not durable-GC authority.
    // A later transaction must neither adopt nor delete it.
    let orphans: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".picoclaw-config-")
        })
        .map(|path| {
            let bytes = fs::read(&path).unwrap();
            let inode = path.metadata().unwrap().ino();
            (path, bytes, inode)
        })
        .collect();
    if !orphans.is_empty() {
        write(permit, directory);
        for (path, bytes, inode) in orphans {
            assert_eq!(path.metadata().unwrap().ino(), inode);
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
        assert_eq!(load_config_document_at(config).unwrap().raw["epoch"], "new");
    }
}

pub(super) fn refuse(
    permit: &crate::update::state_writers::ConfigPermit,
    directory: &Path,
    sentinel: &Path,
) {
    let journal = directory.join(JOURNAL);
    let config = directory.join("config.json");
    let security = directory.join(".security.yml");
    match std::env::var("NANOKVM_PICO_PAIR_DAMAGE").unwrap().as_str() {
        "corrupt" => {
            let mut data = fs::read(&journal).unwrap();
            *data.last_mut().unwrap() ^= 1;
            put_private(&journal, &data);
        }
        "foreign-config" => put_private(&config, br#"{"epoch":"foreign"}"#),
        "foreign-security" => put_private(&security, b"epoch: foreign\n"),
        "mode" => fs::set_permissions(&journal, fs::Permissions::from_mode(0o644)).unwrap(),
        "symlink" => {
            fs::remove_file(&journal).unwrap();
            std::os::unix::fs::symlink(sentinel, &journal).unwrap();
        }
        "hardlink" => fs::hard_link(&journal, directory.join("foreign-journal-link")).unwrap(),
        _ => panic!("unknown damage"),
    }
    let before = [
        fs::read(&config).unwrap(),
        fs::read(&security).unwrap(),
        fs::read(&journal).unwrap(),
        fs::read(sentinel).unwrap(),
    ];
    assert!(load_config_document_at(config.clone()).is_err());
    assert!(crate::update::picoclaw_config::needs_onboard(permit, &config).is_err());
    assert_eq!(
        [
            fs::read(&config).unwrap(),
            fs::read(&security).unwrap(),
            fs::read(&journal).unwrap(),
            fs::read(sentinel).unwrap()
        ],
        before
    );
}
