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
fn profile() -> Profile {
    Profile {
        generation: [0x19; 32],
        picoclaw: false,
    }
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
fn independent_boot_vectors_bind_the_full_generation_and_optional_presence() {
    let mut factory = [0; 112];
    factory[..8].copy_from_slice(b"NKBOOT02");
    factory[44] = 1;
    factory[80..].copy_from_slice(&[
        0x67, 0xbf, 0x2e, 0x48, 0x63, 0xf3, 0x7d, 0xdf, 0x08, 0x7c, 0x39, 0x7a, 0x5c, 0xa5, 0x7f,
        0x29, 0x75, 0x21, 0xeb, 0x35, 0x53, 0xa0, 0x21, 0x4e, 0xc8, 0xff, 0x88, 0xa0, 0xe0, 0xfd,
        0xb8, 0x0c,
    ]);
    assert_eq!(record(State::Factory), factory);
    let mut ready = factory;
    ready[8..44].copy_from_slice(BOOT.as_bytes());
    ready[44] = 3;
    ready[45] = 1;
    ready[48..80].fill(0x19);
    ready[80..].copy_from_slice(&[
        0x2a, 0x31, 0x61, 0x8b, 0x7e, 0xc9, 0x3e, 0x04, 0x96, 0xc1, 0xc6, 0x60, 0x2c, 0xb1, 0xba,
        0x3e, 0xe8, 0x19, 0x95, 0xf7, 0x7b, 0xf1, 0xe5, 0x13, 0x3e, 0xb6, 0xc6, 0xec, 0xad, 0x21,
        0x90, 0xc9,
    ]);
    assert_eq!(
        record(State::Ready(
            epoch(BOOT),
            Profile {
                picoclaw: true,
                ..profile()
            }
        )),
        ready
    );
}

#[test]
fn same_boot_generation_or_optional_presence_change_cannot_reuse_ready() {
    let uid = nix::unistd::geteuid().as_raw();
    for changed in [
        Profile {
            picoclaw: true,
            ..profile()
        },
        Profile {
            generation: [0x18; 32],
            ..profile()
        },
    ] {
        let root = tempfile::tempdir().unwrap();
        let permit = acquire(root.path(), true).unwrap();
        publish(&permit, State::Ready(epoch(BOOT), profile())).unwrap();
        let before = fs::read(root.path().join(DIRECTORY).join("state")).unwrap();
        assert!(matches!(
            activate(&permit, epoch(BOOT), uid, changed),
            Err(Error::Inactive)
        ));
        assert_eq!(
            fs::read(root.path().join(DIRECTORY).join("state")).unwrap(),
            before
        );
        activate(&permit, epoch(OTHER), uid, changed).unwrap();
        assert!(load(&permit, uid).unwrap() == Some(State::Ready(epoch(OTHER), changed)));
    }
}

#[test]
fn optional_script_absence_is_explicit_and_present_content_must_be_exact_and_safe() {
    let uid = nix::unistd::geteuid().as_raw();
    for fault in [
        "absent",
        "exact",
        "bytes",
        "empty",
        "size",
        "mode",
        "symlink",
        "hardlink",
        "fifo",
        "directory",
    ] {
        let root = tempfile::tempdir().unwrap();
        let init = root.path().join("etc/init.d");
        fs::create_dir_all(&init).unwrap();
        let mut digests = [0; 160];
        for (index, name) in SCRIPTS.iter().copied().chain([OPTIONAL]).enumerate() {
            digests[index * 32..(index + 1) * 32].copy_from_slice(&Sha256::digest(name.as_bytes()));
            if name != OPTIONAL || fault != "absent" {
                let path = init.join(name);
                fs::write(&path, name).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let path = init.join(OPTIONAL);
        match fault {
            "bytes" => fs::write(&path, b"old unowned launcher").unwrap(),
            "empty" => fs::write(&path, b"").unwrap(),
            "size" => fs::write(&path, vec![0; 1024 * 1024 + 1]).unwrap(),
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap(),
            "symlink" => {
                fs::remove_file(&path).unwrap();
                symlink("S95nanokvm", &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, init.join("alias")).unwrap(),
            "fifo" => {
                fs::remove_file(&path).unwrap();
                nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
            }
            "directory" => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            _ => {}
        }
        let selected = scripts_at(&File::open(root.path()).unwrap(), uid, &digests);
        if matches!(fault, "absent" | "exact") {
            assert_eq!(selected.unwrap().picoclaw, fault == "exact");
        } else {
            assert!(selected.is_err(), "{fault}");
        }
    }
}

#[test]
fn script_scan_child() {
    let Some(root) = std::env::var_os("NANOKVM_NATIVE_BOOT_SCRIPT_ROOT") else {
        return;
    };
    let mut digests = [0; 160];
    for (index, name) in SCRIPTS.iter().copied().chain([OPTIONAL]).enumerate() {
        digests[index * 32..(index + 1) * 32].copy_from_slice(&Sha256::digest(name.as_bytes()));
    }
    assert!(
        scripts_at(
            &File::open(root).unwrap(),
            nix::unistd::geteuid().as_raw(),
            &digests
        )
        .is_err()
    );
    println!("native-boot-script-race-refused");
}

#[test]
fn optional_script_added_during_the_scan_is_never_reported_absent() {
    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    struct Probe(std::process::Child);
    impl Drop for Probe {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let root = tempfile::tempdir().unwrap();
    let init = root.path().join("etc/init.d");
    fs::create_dir_all(&init).unwrap();
    for name in SCRIPTS {
        let path = init.join(name);
        fs::write(&path, name).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut child = Probe(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_owner::broker::journal::boot::tests::script_scan_child",
                "--nocapture",
            ])
            .env_clear()
            .env("NANOKVM_NATIVE_BOOT_SCRIPT_ROOT", root.path())
            .env("NANOKVM_NATIVE_BOOT_STOP", "optional-presence-observed")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let output = child.0.stdout.as_mut().unwrap();
    let flags = rustix::fs::fcntl_getfl(&*output).unwrap();
    rustix::fs::fcntl_setfl(&*output, flags | OFlags::NONBLOCK).unwrap();
    let mut bytes = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut chunk = [0; 1024];
        match output.read(&mut chunk) {
            Ok(0) => panic!("script scan exited before optional presence checkpoint"),
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("script scan read: {error}"),
        }
        if bytes
            .windows(b"native-boot-state-checkpoint-ready".len())
            .any(|part| part == b"native-boot-state-checkpoint-ready")
        {
            break;
        }
        assert!(
            bytes.len() < 16384 && Instant::now() < deadline,
            "script scan checkpoint not reached"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // Deliberately install a foreign old launcher, after the absent observation.
    let script = init.join(OPTIONAL);
    fs::write(&script, b"foreign gateway launcher").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    child.0.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut detail = String::new();
            child
                .0
                .stderr
                .as_mut()
                .unwrap()
                .read_to_string(&mut detail)
                .unwrap();
            assert!(
                status.success(),
                "scan accepted a newly installed unverified script: {status}: {detail}"
            );
            child
                .0
                .stdout
                .as_mut()
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(
                bytes
                    .windows(b"native-boot-script-race-refused".len())
                    .any(|part| part == b"native-boot-script-race-refused")
            );
            break;
        }
        assert!(Instant::now() < deadline, "script scan did not finish");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn factory_and_old_epoch_activate_but_current_armed_or_absent_never_do() {
    for source in [
        None,
        Some(State::Factory),
        Some(State::Armed(epoch(BOOT))),
        Some(State::Armed(epoch(OTHER))),
        Some(State::Ready(epoch(BOOT), profile())),
        Some(State::Ready(epoch(OTHER), profile())),
    ] {
        let root = tempfile::tempdir().unwrap();
        let permit = acquire(root.path(), true).unwrap();
        if let Some(state) = source {
            publish(&permit, state).unwrap();
        }
        let result = activate(
            &permit,
            epoch(BOOT),
            nix::unistd::geteuid().as_raw(),
            profile(),
        );
        let allowed = source.is_some() && source != Some(State::Armed(epoch(BOOT)));
        assert_eq!(result.is_ok(), allowed);
        assert!(
            load(&permit, nix::unistd::geteuid().as_raw()).unwrap()
                == if allowed {
                    Some(State::Ready(epoch(BOOT), profile()))
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
        "factory-profile",
        "old-format",
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
                    "factory-profile" => bytes[48] = 1,
                    "old-format" => {
                        bytes[..8].copy_from_slice(b"NKBOOT01");
                        bytes.truncate(80);
                    }
                    _ => unreachable!(),
                }
                if !matches!(fault, "hash" | "size" | "old-format") {
                    let hash = Sha256::digest(&bytes[..80]);
                    bytes[80..112].copy_from_slice(&hash);
                }
                fs::write(&path, bytes).unwrap();
            }
        }
        let before = fs::symlink_metadata(&path).unwrap();
        assert!(
            activate(
                &permit,
                epoch(BOOT),
                nix::unistd::geteuid().as_raw(),
                profile()
            )
            .is_err(),
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
    fs::write(&orphan, record(State::Ready(epoch(BOOT), profile()))).unwrap();
    assert!(matches!(
        activate(
            &permit,
            epoch(BOOT),
            nix::unistd::geteuid().as_raw(),
            profile()
        ),
        Err(Error::Inactive)
    ));
    publish(&permit, State::Armed(epoch(BOOT))).unwrap();
    assert!(
        activate(
            &permit,
            epoch(BOOT),
            nix::unistd::geteuid().as_raw(),
            profile()
        )
        .is_err()
    );
    assert_eq!(
        fs::read(orphan).unwrap(),
        record(State::Ready(epoch(BOOT), profile()))
    );
    activate(
        &permit,
        epoch(OTHER),
        nix::unistd::geteuid().as_raw(),
        profile(),
    )
    .unwrap();
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
            let mut digests = [0; 160];
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
            activate(
                &permit,
                epoch(BOOT),
                nix::unistd::geteuid().as_raw(),
                profile()
            ),
            Err(Error::Inactive)
        ));
        // A retry re-arms; neither temporary bytes nor lease disappearance is
        // sufficient to promote. Only a later kernel epoch can activate.
        publish(&permit, State::Armed(epoch(BOOT))).unwrap();
        assert!(
            activate(
                &permit,
                epoch(BOOT),
                nix::unistd::geteuid().as_raw(),
                profile()
            )
            .is_err()
        );
        activate(
            &permit,
            epoch(OTHER),
            nix::unistd::geteuid().as_raw(),
            profile(),
        )
        .unwrap();
    }
}
