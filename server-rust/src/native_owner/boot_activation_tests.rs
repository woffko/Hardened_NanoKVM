use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
const OTHER: &str = "87654321-4321-4321-4321-cba987654321";
fn epoch(value: &str) -> Epoch {
    Epoch::parse(value.as_bytes()).unwrap()
}
fn acquire(root: &std::path::Path, exclusive: bool) -> Result<Permit, Error> {
    lock(
        &File::open(root).unwrap(),
        true,
        exclusive,
        nix::unistd::geteuid().as_raw(),
    )
}

#[test]
fn factory_and_old_epoch_activate_but_current_armed_or_absent_never_do() {
    for source in [
        None,
        Some(State::Factory),
        Some(State::Armed(epoch(BOOT))),
        Some(State::Armed(epoch(OTHER))),
        Some(State::Ready(epoch(BOOT))),
        Some(State::Ready(epoch(OTHER))),
    ] {
        let root = tempfile::tempdir().unwrap();
        let permit = acquire(root.path(), true).unwrap();
        if let Some(state) = source {
            publish(&permit, state).unwrap();
        }
        let result = activate(&permit, epoch(BOOT), nix::unistd::geteuid().as_raw());
        let allowed = source.is_some() && source != Some(State::Armed(epoch(BOOT)));
        assert_eq!(result.is_ok(), allowed);
        assert!(
            load(&permit, nix::unistd::geteuid().as_raw()).unwrap()
                == if allowed {
                    Some(State::Ready(epoch(BOOT)))
                } else {
                    source
                }
        );
    }
}

#[test]
fn shared_broker_permit_blocks_rearm_and_survives_another_shared_drop() {
    let root = tempfile::tempdir().unwrap();
    let first = acquire(root.path(), false).unwrap();
    let second = acquire(root.path(), false).unwrap();
    assert!(matches!(acquire(root.path(), true), Err(Error::Busy)));
    drop(first);
    assert!(matches!(acquire(root.path(), true), Err(Error::Busy)));
    drop(second);
    let exclusive = acquire(root.path(), true).unwrap();
    assert!(matches!(acquire(root.path(), false), Err(Error::Busy)));
    drop(exclusive);
    assert!(acquire(root.path(), true).is_ok());
}

#[test]
fn malformed_or_unsafe_state_is_never_repaired_or_promoted() {
    for fault in [
        "mode",
        "symlink",
        "hardlink",
        "fifo",
        "size",
        "hash",
        "magic",
        "phase",
        "reserved",
        "factory-epoch",
    ] {
        let root = tempfile::tempdir().unwrap();
        let permit = acquire(root.path(), true).unwrap();
        publish(&permit, State::Factory).unwrap();
        let path = root.path().join(DIRECTORY).join("state");
        match fault {
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "symlink" => {
                fs::remove_file(&path).unwrap();
                symlink("outside", &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, path.with_extension("alias")).unwrap(),
            "fifo" => {
                fs::remove_file(&path).unwrap();
                nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
            }
            _ => {
                let mut bytes = record(State::Factory).to_vec();
                match fault {
                    "size" => bytes.push(0),
                    "hash" => bytes[79] ^= 1,
                    "magic" => bytes[0] ^= 1,
                    "phase" => bytes[44] = 99,
                    "reserved" => bytes[45] = 1,
                    "factory-epoch" => bytes[8] = 1,
                    _ => unreachable!(),
                }
                if !matches!(fault, "hash" | "size") {
                    let hash = Sha256::digest(&bytes[..48]);
                    bytes[48..80].copy_from_slice(&hash);
                }
                fs::write(&path, bytes).unwrap();
            }
        }
        let before = fs::symlink_metadata(&path).unwrap();
        assert!(
            activate(&permit, epoch(BOOT), nix::unistd::geteuid().as_raw()).is_err(),
            "{fault}"
        );
        assert_eq!(fs::symlink_metadata(path).unwrap().ino(), before.ino());
    }
}

#[test]
fn exclusive_orphan_temporaries_never_override_canonical_state() {
    let root = tempfile::tempdir().unwrap();
    let permit = acquire(root.path(), true).unwrap();
    let orphan = root.path().join(DIRECTORY).join(".state-next-orphan");
    fs::write(&orphan, record(State::Ready(epoch(BOOT)))).unwrap();
    assert!(matches!(
        activate(&permit, epoch(BOOT), nix::unistd::geteuid().as_raw()),
        Err(Error::Inactive)
    ));
    publish(&permit, State::Armed(epoch(BOOT))).unwrap();
    assert!(activate(&permit, epoch(BOOT), nix::unistd::geteuid().as_raw()).is_err());
    assert_eq!(fs::read(orphan).unwrap(), record(State::Ready(epoch(BOOT))));
    activate(&permit, epoch(OTHER), nix::unistd::geteuid().as_raw()).unwrap();
}

#[test]
fn all_script_identities_and_protected_paths_are_required() {
    for fault in [
        "valid", "bytes", "missing", "mode", "symlink", "hardlink", "parent",
    ] {
        for (index, selected) in SCRIPTS.iter().enumerate() {
            let root = tempfile::tempdir().unwrap();
            let init = root.path().join("etc/init.d");
            fs::create_dir_all(&init).unwrap();
            for name in SCRIPTS {
                let path = init.join(name);
                fs::write(&path, name).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
            let mut digests = [0; 128];
            for (i, name) in SCRIPTS.iter().enumerate() {
                digests[i * 32..(i + 1) * 32].copy_from_slice(&Sha256::digest(name.as_bytes()));
            }
            let path = init.join(selected);
            match fault {
                "bytes" => fs::write(&path, b"changed").unwrap(),
                "missing" => fs::remove_file(&path).unwrap(),
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap(),
                "symlink" => {
                    fs::remove_file(&path).unwrap();
                    symlink("outside", &path).unwrap();
                }
                "hardlink" => fs::hard_link(&path, init.join("alias")).unwrap(),
                "parent" => fs::set_permissions(&init, fs::Permissions::from_mode(0o777)).unwrap(),
                _ => {}
            }
            assert_eq!(
                scripts_at(
                    &File::open(root.path()).unwrap(),
                    nix::unistd::geteuid().as_raw(),
                    &digests
                )
                .is_ok(),
                fault == "valid",
                "{fault}/{index}"
            );
        }
    }
}

#[test]
fn boot_publication_child() {
    let Some(root) = std::env::var_os("NANOKVM_NATIVE_BOOT_FIXTURE") else {
        return;
    };
    let permit = acquire(std::path::Path::new(&root), true).unwrap();
    publish(&permit, State::Armed(epoch(BOOT))).unwrap();
}

#[test]
fn actual_process_death_at_each_publish_boundary_never_grants_same_boot_start() {
    use std::{
        io::{BufRead, BufReader},
        process::{Command, Stdio},
        sync::mpsc,
        time::Duration,
    };
    struct Paused {
        child: std::process::Child,
        reader: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Paused {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(reader) = self.reader.take() {
                reader.join().unwrap();
            }
        }
    }
    for step in [
        "before-create",
        "created",
        "written",
        "file-synced",
        "renamed",
        "directory-synced",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_owner::broker::journal::boot::tests::boot_publication_child",
                "--nocapture",
            ])
            .env_clear()
            .env("NANOKVM_NATIVE_BOOT_FIXTURE", root.path())
            .env("NANOKVM_NATIVE_BOOT_STOP", step)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, receive) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.unwrap().contains("native-boot-state-checkpoint-ready") {
                    let _ = send.send(());
                    break;
                }
            }
        });
        let mut paused = Paused {
            child,
            reader: Some(reader),
        };
        receive.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(matches!(acquire(root.path(), false), Err(Error::Busy)));
        paused.child.kill().unwrap();
        paused.child.wait().unwrap();
        drop(paused);
        let permit = acquire(root.path(), true).unwrap();
        let state = load(&permit, nix::unistd::geteuid().as_raw()).unwrap();
        assert!(
            state
                == if matches!(step, "renamed" | "directory-synced") {
                    Some(State::Armed(epoch(BOOT)))
                } else {
                    None
                }
        );
        assert!(matches!(
            activate(&permit, epoch(BOOT), nix::unistd::geteuid().as_raw()),
            Err(Error::Inactive)
        ));
        // A retry re-arms; neither temporary bytes nor lease disappearance is
        // sufficient to promote. Only a later kernel epoch can activate.
        publish(&permit, State::Armed(epoch(BOOT))).unwrap();
        assert!(activate(&permit, epoch(BOOT), nix::unistd::geteuid().as_raw()).is_err());
        activate(&permit, epoch(OTHER), nix::unistd::geteuid().as_raw()).unwrap();
    }
}
