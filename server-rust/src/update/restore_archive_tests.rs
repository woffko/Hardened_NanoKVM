use super::*;
use crate::update::restore_capsule::{open_capsule, prepare_capsule};
use std::{
    io::Cursor,
    os::unix::fs::{PermissionsExt, symlink},
};
use tempfile::{TempDir, tempdir};

fn put(root: &Path, path: &str, bytes: &[u8]) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn source_fixture() -> TempDir {
    let root = tempdir().unwrap();
    for path in policy::REQUIRED {
        put(root.path(), path, b"synthetic fixture state\n");
    }
    put(
        root.path(),
        "etc/kvm/session_secret",
        b"synthetic-session-state-not-a-credential\n",
    );
    root
}

fn authenticated(bytes: &[u8], staging: &Path) -> VerifiedPayload {
    let mut encrypted = Vec::new();
    let secret = prepare_capsule(
        "0.3.0-raw.13",
        bytes.len() as u64,
        &mut Cursor::new(bytes),
        &mut encrypted,
    )
    .unwrap();
    open_capsule(&secret, &mut Cursor::new(encrypted), staging).unwrap()
}

fn records() -> Vec<(String, Vec<u8>, u32, EntryType)> {
    let mut entries = vec![(
        FORMAT_PATH.to_string(),
        FORMAT.to_vec(),
        0o600,
        EntryType::Regular,
    )];
    for path in policy::REQUIRED.iter().chain([&"etc/kvm/session_secret"]) {
        entries.push((
            format!("files/{path}"),
            b"synthetic state".to_vec(),
            policy::mode(path),
            EntryType::Regular,
        ));
    }
    for path in policy::PRESENCE {
        entries.push((format!("absent/{path}"), vec![], 0o600, EntryType::Regular));
    }
    entries
}

fn encode(entries: Vec<(String, Vec<u8>, u32, EntryType)>) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut bytes);
        for (name, data, mode, kind) in entries {
            let mut header = Header::new_ustar();
            if header.set_path(&name).is_err() {
                // Deliberately malformed/traversal fixtures bypass the builder's
                // friendly pathname validation; production code never does this.
                assert!(name.len() < 100);
                header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            }
            header.set_entry_type(kind);
            header.set_mode(mode);
            header.set_size(data.len() as u64);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
        }
        builder.finish().unwrap();
    }
    bytes
}

fn rejects(bytes: &[u8]) {
    let root = tempdir().unwrap();
    let payload = authenticated(bytes, root.path());
    assert!(validate(payload).is_err());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn capture_seal_validate_and_read_preserves_settings_not_executables() {
    let source = source_fixture();
    let staging = tempdir().unwrap();
    put(
        source.path(),
        "etc/ssh/ssh_host_ed25519_key",
        b"synthetic SSH identity",
    );
    put(
        source.path(),
        "etc/kvm/firewall.json",
        b"{\"enabled\":true}",
    );
    put(
        source.path(),
        "kvmapp/kvm/ap.pass",
        b"synthetic AP configuration",
    );
    put(
        source.path(),
        "etc/kvm/scripts/manual.sh",
        b"echo user data\n",
    );
    fs::set_permissions(
        source.path().join("etc/kvm/scripts/manual.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    put(
        source.path(),
        "root/.picoclaw/workspace/notes/example.md",
        b"user memory",
    );
    put(
        source.path(),
        "root/.picoclaw/workspace/AGENT.md",
        b"old generated agent profile",
    );
    put(
        source.path(),
        "root/.picoclaw/workspace/skills/kvm-control/tool.sh",
        b"old generated control code",
    );
    put(source.path(), "usr/bin/picoclaw", b"do not preserve binary");
    put(
        source.path(),
        "etc/init.d/S96picoclaw",
        b"do not preserve init code",
    );
    put(
        source.path(),
        "etc/default/syslogd",
        b"do not preserve shell-sourced config",
    );
    put(
        source.path(),
        "etc/kvm/update-keys/untrusted.pub.pem",
        b"do not preserve trust material",
    );
    for path in [
        "etc/init.d/S02apprecover",
        "etc/kvm/application-update/stage-forged/extract/kvmapp/server/NanoKVM-Server",
        "usr/libexec/nanokvm-app-recovery",
        "usr/libexec/.nanokvm-app-recovery-next-forged",
        "etc/kvm/application-slot/current/state",
        "etc/kvm/application-slot/current/.state-next-forged",
        "etc/kvm/application-slot/current/old/server/NanoKVM-Server",
        "etc/kvm/application-slot/current/new/server/NanoKVM-Server",
        "etc/kvm/native-runtime-owner/state",
        "etc/kvm/native-runtime-boot/state",
        "etc/kvm/native-runtime-boot/.state-next-forged",
        "etc/kvm/native-runtime-owner/.state.next",
        "etc/kvm/native-runtime-owner/control.sock",
        "etc/kvm/native-runtime-owner/app-install.sock",
        "etc/kvm/native-runtime-owner/recovery/boot-12345678-1234-1234-1234-123456789abc",
        "etc/kvm/native-runtime-owner/recovery/evidence/state",
        "etc/kvm/native-runtime-owner/recovery/quarantined",
        "etc/kvm/native-runtime-owner/recovered-12345678-1234-1234-1234-123456789abc/evidence/state",
    ] {
        put(
            source.path(),
            path,
            b"do not preserve native process ownership authority",
        );
    }
    let mut snapshot = capture(source.path(), staging.path()).unwrap();
    let mut bytes = Vec::new();
    snapshot.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.len() as u64, snapshot.size());
    assert_eq!(snapshot.file.metadata().unwrap().nlink(), 0);
    let mut validated = validate(authenticated(&bytes, staging.path())).unwrap();
    for path in [
        "etc/ssh/ssh_host_ed25519_key",
        "etc/kvm/firewall.json",
        "kvmapp/kvm/ap.pass",
        "etc/kvm/scripts/manual.sh",
        "root/.picoclaw/workspace/notes/example.md",
    ] {
        let index = validated
            .members()
            .iter()
            .position(|entry| entry.path == path)
            .unwrap();
        let mut output = Vec::new();
        validated.copy_file(index, &mut output).unwrap();
        assert_eq!(output, fs::read(source.path().join(path)).unwrap());
        assert_eq!(validated.members()[index].mode, 0o600);
    }
    for forbidden in [
        "etc/init.d/S02apprecover",
        "etc/kvm/application-update/stage-forged/extract/kvmapp/server/NanoKVM-Server",
        "usr/libexec/nanokvm-app-recovery",
        "usr/libexec/.nanokvm-app-recovery-next-forged",
        "etc/kvm/application-slot/current/state",
        "etc/kvm/application-slot/current/.state-next-forged",
        "etc/kvm/application-slot/current/old/server/NanoKVM-Server",
        "etc/kvm/application-slot/current/new/server/NanoKVM-Server",
        "usr/bin/picoclaw",
        "etc/init.d/S96picoclaw",
        "etc/default/syslogd",
        "etc/kvm/update-keys/untrusted.pub.pem",
        "etc/kvm/native-runtime-owner/state",
        "etc/kvm/native-runtime-boot/state",
        "etc/kvm/native-runtime-boot/.state-next-forged",
        "etc/kvm/native-runtime-owner/.state.next",
        "etc/kvm/native-runtime-owner/control.sock",
        "etc/kvm/native-runtime-owner/app-install.sock",
        "etc/kvm/native-runtime-owner/recovery/boot-12345678-1234-1234-1234-123456789abc",
        "etc/kvm/native-runtime-owner/recovery/evidence/state",
        "etc/kvm/native-runtime-owner/recovery/quarantined",
        "etc/kvm/native-runtime-owner/recovered-12345678-1234-1234-1234-123456789abc/evidence/state",
        "root/.picoclaw/workspace/AGENT.md",
        "root/.picoclaw/workspace/skills/kvm-control/tool.sh",
    ] {
        assert!(
            !validated
                .members()
                .iter()
                .any(|entry| entry.path == forbidden)
        );
    }
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
}

#[test]
fn absence_is_explicit_and_legacy_disk_backing_is_normalized_to_empty() {
    let source = source_fixture();
    let staging = tempdir().unwrap();
    put(source.path(), "boot/usb.disk0", b"/dev/mmcblk0p3\n");
    let mut snapshot = capture(source.path(), staging.path()).unwrap();
    let mut bytes = Vec::new();
    snapshot.read_to_end(&mut bytes).unwrap();
    let mut validated = validate(authenticated(&bytes, staging.path())).unwrap();
    let disk = validated
        .members()
        .iter()
        .position(|entry| entry.path == "boot/usb.disk0")
        .unwrap();
    assert_eq!(validated.members()[disk].action, RestoreAction::Write);
    let mut backing = Vec::new();
    validated.copy_file(disk, &mut backing).unwrap();
    assert!(backing.is_empty());
    let network = validated
        .members()
        .iter()
        .position(|entry| entry.path == "boot/usb.rndis0")
        .unwrap();
    assert_eq!(validated.members()[network].action, RestoreAction::Absent);
    assert!(validated.copy_file(network, &mut Vec::new()).is_err());
}

#[test]
fn unchanged_snapshot_is_deterministic_and_preserves_live_source() {
    let source = source_fixture();
    let staging = tempdir().unwrap();
    let mut a = capture(source.path(), staging.path()).unwrap();
    let mut b = capture(source.path(), staging.path()).unwrap();
    let mut first = Vec::new();
    let mut second = Vec::new();
    a.read_to_end(&mut first).unwrap();
    b.read_to_end(&mut second).unwrap();
    assert_eq!(first, second);
    assert!(source.path().join("etc/kvm/pwd").is_file());
}

#[test]
fn missing_or_empty_critical_state_aborts_capture_before_any_spool() {
    for path in policy::REQUIRED.iter().chain([&"etc/kvm/session_secret"]) {
        let source = source_fixture();
        let staging = tempdir().unwrap();
        fs::remove_file(source.path().join(path)).unwrap();
        assert!(matches!(
            capture(source.path(), staging.path()),
            Err(RestoreArchiveError::Incomplete)
        ));
        put(source.path(), path, b"");
        assert!(matches!(
            capture(source.path(), staging.path()),
            Err(RestoreArchiveError::Incomplete)
        ));
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    }
}

#[test]
fn source_symlinks_hardlinks_and_parent_aliases_are_rejected() {
    let source = source_fixture();
    let staging = tempdir().unwrap();
    let pwd = source.path().join("etc/kvm/pwd");
    fs::hard_link(&pwd, source.path().join("alias")).unwrap();
    assert!(matches!(
        capture(source.path(), staging.path()),
        Err(RestoreArchiveError::InvalidSource)
    ));
    fs::remove_file(source.path().join("alias")).unwrap();
    fs::rename(&pwd, source.path().join("original")).unwrap();
    symlink(source.path().join("original"), &pwd).unwrap();
    assert!(matches!(
        capture(source.path(), staging.path()),
        Err(RestoreArchiveError::InvalidSource)
    ));
    fs::remove_file(&pwd).unwrap();
    fs::rename(source.path().join("original"), &pwd).unwrap();
    fs::rename(
        source.path().join("etc/kvm"),
        source.path().join("real-kvm"),
    )
    .unwrap();
    symlink(
        source.path().join("real-kvm"),
        source.path().join("etc/kvm"),
    )
    .unwrap();
    assert!(matches!(
        capture(source.path(), staging.path()),
        Err(RestoreArchiveError::InvalidSource)
    ));
}

#[test]
fn source_inode_replacement_is_detected_before_reading_it() {
    let source = source_fixture();
    let path = "etc/kvm/pwd";
    let root = SourceRoot::open(source.path()).unwrap();
    let metadata = root.metadata(path).unwrap().unwrap();
    fs::rename(source.path().join(path), source.path().join("old-pwd")).unwrap();
    put(source.path(), path, b"replacement");
    assert!(matches!(
        root.open_file(path, &metadata),
        Err(RestoreArchiveError::InvalidSource)
    ));
}

#[test]
fn pinned_source_root_cannot_be_redirected_by_renaming_its_path() {
    let parent = tempdir().unwrap();
    let original = parent.path().join("original");
    let moved = parent.path().join("moved");
    let outside = parent.path().join("outside");
    put(&original, "etc/kvm/pwd", b"original synthetic state");
    put(&outside, "etc/kvm/pwd", b"untrusted replacement state");
    let root = SourceRoot::open(&original).unwrap();
    let expected = root.metadata("etc/kvm/pwd").unwrap().unwrap();
    fs::rename(&original, &moved).unwrap();
    symlink(&outside, &original).unwrap();
    let mut file = root.open_file("etc/kvm/pwd", &expected).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"original synthetic state");
    assert!(SourceRoot::open(&original).is_err());
}

#[test]
fn concurrent_parent_swaps_never_read_outside_the_pinned_source() {
    let source = source_fixture();
    let outside = tempdir().unwrap();
    put(outside.path(), "pwd", b"untrusted replacement state");
    let root = SourceRoot::open(source.path()).unwrap();
    let expected = root.metadata("etc/kvm/pwd").unwrap().unwrap();
    let path = source.path().join("etc/kvm");
    let moved = source.path().join("etc/moved-kvm");
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..128 {
                fs::rename(&path, &moved).unwrap();
                symlink(outside.path(), &path).unwrap();
                std::thread::yield_now();
                fs::remove_file(&path).unwrap();
                fs::rename(&moved, &path).unwrap();
            }
        });
        for _ in 0..256 {
            match root.open_file("etc/kvm/pwd", &expected) {
                Ok(mut file) => {
                    let mut bytes = Vec::new();
                    file.read_to_end(&mut bytes).unwrap();
                    assert_eq!(bytes, b"synthetic fixture state\n");
                }
                Err(RestoreArchiveError::InvalidSource) => {}
                Err(err) => panic!("unexpected synthetic source error: {err}"),
            }
        }
    });
}

#[test]
fn nested_mounts_and_proc_magic_links_are_not_source_aliases() {
    let root = SourceRoot::open(Path::new("/")).unwrap();
    assert!(matches!(
        root.metadata("proc/version"),
        Err(RestoreArchiveError::InvalidSource)
    ));
    assert!(SourceRoot::open(Path::new("/proc/self/fd")).is_err());
}

#[test]
fn unsupported_selected_tree_state_aborts_instead_of_silently_losing_it() {
    for path in [
        "etc/kvm/scripts/custom name.sh",
        "etc/kvm/autostart/nested/custom.sh",
        "etc/ssh/sshd_config.d/custom.disabled",
    ] {
        let source = source_fixture();
        let staging = tempdir().unwrap();
        put(
            source.path(),
            path,
            b"operator state needs an explicit migration",
        );
        assert!(matches!(
            capture(source.path(), staging.path()),
            Err(RestoreArchiveError::InvalidSource)
        ));
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    }
}

#[test]
fn administrative_uploads_and_ssh_client_state_remain_private_inert_data() {
    let source = source_fixture();
    let staging = tempdir().unwrap();
    let paths = [
        "etc/kvm/autostart/manual.sh",
        "root/.picoclaw/workspace/tools/manual.sh",
        "root/.ssh/id_ed25519",
    ];
    for path in paths {
        put(
            source.path(),
            path,
            b"synthetic operator data, not a real key",
        );
        fs::set_permissions(source.path().join(path), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut snapshot = capture(source.path(), staging.path()).unwrap();
    let mut bytes = Vec::new();
    snapshot.read_to_end(&mut bytes).unwrap();
    let validated = validate(authenticated(&bytes, staging.path())).unwrap();
    for path in paths {
        let member = validated.members().iter().find(|m| m.path == path).unwrap();
        assert_eq!(member.action, RestoreAction::Write);
        assert_eq!(member.mode, 0o600);
    }
}

#[test]
fn append_never_consumes_more_than_the_declared_size() {
    let root = tempdir().unwrap();
    let mut file = restore_capsule::create_private_spool(root.path()).unwrap();
    let mut input = Cursor::new(b"abcd");
    {
        let mut builder = Builder::new(&mut file);
        append(&mut builder, "file", 2, 0o600, &mut input).unwrap();
        builder.finish().unwrap();
    }
    assert_eq!(input.position(), 2);
    let mut short = Cursor::new(b"x");
    let mut builder = Builder::new(&mut file);
    assert!(matches!(
        append(&mut builder, "file", 2, 0o600, &mut short),
        Err(RestoreArchiveError::InvalidSource)
    ));
}

#[test]
fn unauthorized_system_code_trust_runtime_and_private_paths_are_rejected() {
    for path in [
        "etc/init.d/S02apprecover",
        "etc/kvm/application-update/stage-forged/extract/kvmapp/server/NanoKVM-Server",
        "usr/libexec/nanokvm-app-recovery",
        "usr/libexec/.nanokvm-app-recovery-next-forged",
        "etc/kvm/application-slot/current/state",
        "etc/kvm/application-slot/current/.state-next-forged",
        "etc/kvm/application-slot/current/old/server/NanoKVM-Server",
        "etc/kvm/application-slot/current/new/server/NanoKVM-Server",
        "usr/bin/picoclaw",
        "etc/init.d/S96picoclaw",
        "etc/default/syslogd",
        "etc/kvm/update-nanokvm.py",
        "etc/kvm/system-version.json",
        "etc/kvm/system-update-pending.json",
        "etc/kvm/native-runtime-owner/state",
        "etc/kvm/native-runtime-boot/state",
        "etc/kvm/native-runtime-boot/.state-next-forged",
        "etc/kvm/native-runtime-owner/.state.next",
        "etc/kvm/native-runtime-owner/control.sock",
        "etc/kvm/native-runtime-owner/app-install.sock",
        "etc/kvm/native-runtime-owner/recovery/boot-12345678-1234-1234-1234-123456789abc",
        "etc/kvm/native-runtime-owner/recovery/evidence/state",
        "etc/kvm/native-runtime-owner/recovery/quarantined",
        "etc/kvm/native-runtime-owner/recovered-12345678-1234-1234-1234-123456789abc/evidence/state",
        "etc/kvm/update-key-policy",
        "etc/kvm/update-keys/key.pub.pem",
        "etc/kvm/.picoclaw_internal_token",
        "data/.hardened-kvmcache/preserve/root.img",
        "boot/usb.disk0.ro",
        "tmp/token",
        "proc/sys/kernel/core_pattern",
        "root/.picoclaw-cache/archive.tar.gz",
    ] {
        let mut items = records();
        items.push((format!("files/{path}"), vec![], 0o600, EntryType::Regular));
        rejects(&encode(items));
    }
}

#[test]
fn absent_records_cannot_delete_identity_or_authorize_unknown_paths() {
    for path in [
        "etc/init.d/S02apprecover",
        "etc/kvm/application-update/stage-forged/extract/kvmapp/server/NanoKVM-Server",
        "usr/libexec/nanokvm-app-recovery",
        "usr/libexec/.nanokvm-app-recovery-next-forged",
        "etc/kvm/application-slot/current/state",
        "etc/kvm/application-slot/current/.state-next-forged",
        "etc/kvm/application-slot/current/old/server/NanoKVM-Server",
        "etc/kvm/application-slot/current/new/server/NanoKVM-Server",
        "etc/passwd",
        "etc/kvm/pwd",
        "etc/kvm/server.yaml",
        "etc/kvm/update-key-policy",
        "usr/bin/picoclaw",
        "etc/kvm/native-runtime-owner/state",
        "etc/kvm/native-runtime-boot/state",
        "etc/kvm/native-runtime-boot/.state-next-forged",
        "etc/kvm/native-runtime-owner/.state.next",
        "etc/kvm/native-runtime-owner/control.sock",
        "etc/kvm/native-runtime-owner/app-install.sock",
        "etc/kvm/native-runtime-owner/recovery/boot-12345678-1234-1234-1234-123456789abc",
        "etc/kvm/native-runtime-owner/recovery/evidence/state",
        "etc/kvm/native-runtime-owner/recovery/quarantined",
        "etc/kvm/native-runtime-owner/recovered-12345678-1234-1234-1234-123456789abc/evidence/state",
    ] {
        let mut items = records();
        items.push((format!("absent/{path}"), vec![], 0o600, EntryType::Regular));
        rejects(&encode(items));
    }
    let mut items = records();
    items.retain(|item| item.0 != "absent/boot/usb.disk0");
    rejects(&encode(items));
}

#[test]
fn all_links_devices_sparse_and_extension_types_are_rejected() {
    for kind in [
        EntryType::Symlink,
        EntryType::Link,
        EntryType::Char,
        EntryType::Block,
        EntryType::Fifo,
        EntryType::Directory,
        EntryType::GNUSparse,
        EntryType::GNULongName,
        EntryType::GNULongLink,
        EntryType::XHeader,
        EntryType::XGlobalHeader,
    ] {
        let mut items = records();
        items.push((
            "files/root/.picoclaw/workspace/item".to_string(),
            vec![],
            0o600,
            kind,
        ));
        rejects(&encode(items));
    }
}

#[test]
fn traversal_absolute_and_noncanonical_alias_paths_are_rejected() {
    for path in [
        "files/../etc/shadow",
        "files//etc/kvm/pwd",
        "files/etc/./kvm/pwd",
        "files/etc/kvm/../pwd",
        "files/etc\\kvm\\pwd",
        "/etc/kvm/pwd",
    ] {
        let mut items = records();
        items.push((path.to_string(), vec![], 0o600, EntryType::Regular));
        rejects(&encode(items));
    }
    assert!(
        check_path(&format!(
            "root/.picoclaw/workspace/{}",
            "a".repeat(MAX_PATH)
        ))
        .is_err()
    );
    assert!(check_path(&"a/".repeat(MAX_DEPTH)).is_err());
    assert!(check_path("root/.picoclaw/workspace/new\nline").is_err());
}

#[test]
fn duplicate_write_absence_and_file_parent_conflicts_are_rejected() {
    let mut items = records();
    items.push(items[1].clone());
    rejects(&encode(items));
    let mut items = records();
    items.push((
        "files/boot/usb.disk0".to_string(),
        vec![],
        0o600,
        EntryType::Regular,
    ));
    rejects(&encode(items));
    let mut items = records();
    for path in [
        "root/.picoclaw/workspace/a",
        "root/.picoclaw/workspace/a-b",
        "root/.picoclaw/workspace/a/b",
    ] {
        items.push((format!("files/{path}"), vec![], 0o600, EntryType::Regular));
    }
    rejects(&encode(items));
}

#[test]
fn executable_modes_nonempty_disk_backing_and_empty_account_are_rejected() {
    for mode in [0o755, 0o4755, 0o777, 0o644] {
        let mut items = records();
        items.push((
            "files/etc/kvm/scripts/test.sh".to_string(),
            b"script data".to_vec(),
            mode,
            EntryType::Regular,
        ));
        rejects(&encode(items));
    }
    let mut items = records();
    items.retain(|item| item.0 != "absent/boot/usb.disk0");
    items.push((
        "files/boot/usb.disk0".to_string(),
        b"/dev/mmcblk0p3".to_vec(),
        0o600,
        EntryType::Regular,
    ));
    rejects(&encode(items));
    let mut items = records();
    items
        .iter_mut()
        .find(|item| item.0 == "files/etc/kvm/pwd")
        .unwrap()
        .1
        .clear();
    rejects(&encode(items));
}

#[test]
fn format_required_identity_and_trailer_are_mandatory() {
    let mut items = records();
    items.remove(0);
    rejects(&encode(items));
    let mut items = records();
    items[0].1 = b"unknown format\n".to_vec();
    rejects(&encode(items));
    let mut items = records();
    items.retain(|item| item.0 != "files/etc/kvm/pwd");
    rejects(&encode(items));
    let bytes = encode(records());
    rejects(&bytes[..bytes.len() - 512]);
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(&encode(records()));
    rejects(&trailing);
    let mut hidden = bytes;
    let end = hidden.len() - 1;
    hidden[end] = 1;
    rejects(&hidden);
}

#[test]
fn header_checksum_padding_uid_and_oversized_entries_are_rejected() {
    let bytes = encode(records());
    let mut corrupt = bytes.clone();
    corrupt[0] ^= 1;
    rejects(&corrupt);
    let mut pad = bytes.clone();
    pad[512 + FORMAT.len()] = 1;
    rejects(&pad);
    for (size, uid) in [(MAX_FILE_BYTES + 1, 0), (u64::MAX, 0), (10, 1000)] {
        let mut corrupt = bytes.clone();
        let header = Header::from_byte_slice(&corrupt[1024..1536]).clone();
        let mut changed = header;
        changed.set_size(size);
        changed.set_uid(uid);
        changed.set_cksum();
        corrupt[1024..1536].copy_from_slice(changed.as_bytes());
        rejects(&corrupt);
    }
}

#[test]
fn file_and_depth_budgets_fail_before_capture_allocates_output() {
    let source = source_fixture();
    let staging = tempdir().unwrap();
    let huge = source.path().join("root/.picoclaw/workspace/large");
    fs::create_dir_all(huge.parent().unwrap()).unwrap();
    let file = File::create(&huge).unwrap();
    file.set_len(MAX_FILE_BYTES + 1).unwrap();
    assert!(matches!(
        capture(source.path(), staging.path()),
        Err(RestoreArchiveError::Limit)
    ));
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    assert!(rounded(u64::MAX).is_err());
}

#[test]
fn too_many_archive_members_are_rejected_with_bounded_index() {
    let mut items = records();
    for index in 0..MAX_FILES {
        items.push((
            format!("files/root/.picoclaw/workspace/file-{index}"),
            vec![],
            0o600,
            EntryType::Regular,
        ));
    }
    rejects(&encode(items));
}

#[test]
fn root_ssh_admits_flat_safe_names_but_never_what_sshd_runs_or_imports() {
    assert!(policy::allowed("root/.ssh/id_work"));
    assert!(policy::allowed("root/.ssh/known_hosts.old"));
    for path in [
        "root/.ssh/rc",
        "root/.ssh/environment",
        "root/.ssh/nested/key",
        "root/.ssh/.hidden",
        "root/.ssh/a name",
    ] {
        assert!(!policy::allowed(path), "{path}");
    }
}
