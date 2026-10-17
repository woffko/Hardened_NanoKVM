use super::*;
use crate::update::restore_capsule::prepare_capsule;
use std::{
    io::Cursor,
    os::unix::fs::{PermissionsExt, symlink},
};
use tempfile::{TempDir, tempdir};

const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
const BOOT: &str = "22222222-2222-4222-8222-222222222222";
const REBOOT: &str = "33333333-3333-4333-8333-333333333333";
const VERSION: &str = "0.3.0-raw.13";
const APP: &str = "2.0.43";
const TARGET: &str = "sg2002-licheervnano-sd";

fn fixture() -> (RestoreTicket, Vec<u8>, Vec<u8>) {
    let plaintext = b"synthetic private settings fixture\n".repeat(4096);
    let mut encrypted = Vec::new();
    let secret = prepare_capsule(
        VERSION,
        plaintext.len() as u64,
        &mut Cursor::new(&plaintext),
        &mut encrypted,
    )
    .unwrap();
    let mut capsule = [0; 32];
    capsule.copy_from_slice(&Sha256::digest(&encrypted));
    let binding = Binding {
        source_boot: BootId::parse(SOURCE).unwrap(),
        device_id: [1; 32],
        capsule_sha256: capsule,
        boot_image_sha256: [2; 32],
        rootfs_image_sha256: [3; 32],
        target_app_version: APP.to_string(),
        target: TARGET.to_string(),
    };
    (
        RestoreTicket::prepared(secret, binding).unwrap(),
        encrypted,
        plaintext,
    )
}
fn observed(boot: &str) -> BootObservation<'static> {
    BootObservation {
        boot_id: BootId::parse(boot).unwrap(),
        device_id: [1; 32],
        system_version: VERSION,
        app_version: APP,
        target: TARGET,
    }
}
fn open_fixture(root: &Path) -> Result<Store> {
    let file = restore_fs::open_root(root, false)?;
    let metadata = file.metadata()?;
    Store::from_boot(file, nix::unistd::geteuid().as_raw(), metadata.dev())
}
fn record_path(root: &Path, name: &str) -> std::path::PathBuf {
    root.join(DIRECTORY).join(name)
}
fn private_write(path: &Path, data: &[u8]) {
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn reseal(bytes: &mut [u8; RECORD_BYTES]) {
    let hash = Sha256::digest(&bytes[..HASH_OFFSET]);
    bytes[HASH_OFFSET..].copy_from_slice(&hash);
}
fn applying(root: &Path) -> (Store, RestoreTicket, Vec<u8>, Vec<u8>) {
    let mut store = open_fixture(root).unwrap();
    let (mut ticket, encrypted, plain) = fixture();
    store.publish_prepared(&ticket).unwrap();
    store.begin_apply(&mut ticket, &observed(BOOT)).unwrap();
    (store, ticket, encrypted, plain)
}

#[test]
fn boot_ids_are_bounded_canonical_values_not_arbitrary_marker_strings() {
    assert!(BootId::parse(SOURCE).unwrap() == BootId::parse(&SOURCE.to_uppercase()).unwrap());
    for invalid in [
        "",
        "00000000-0000-0000-0000-000000000000",
        "11111111111141118111111111111111",
        "g1111111-1111-4111-8111-111111111111",
        "11111111_1111-4111-8111-111111111111",
    ] {
        assert!(BootId::parse(invalid).is_err());
    }
}

#[test]
fn fixed_record_roundtrip_keeps_private_key_only_in_active_state() {
    let (ticket, encrypted, plain) = fixture();
    let bytes = encode(&ticket, ticket.phase, ticket.last_boot).unwrap();
    assert_eq!(bytes.len(), 512);
    let restored = decode(&bytes).unwrap();
    assert!(
        encode(&restored, restored.phase, restored.last_boot)
            .unwrap()
            .as_slice()
            == bytes.as_slice()
    );
    let staging = tempdir().unwrap();
    let mut payload = restored
        .decrypt(&observed(BOOT), &mut Cursor::new(encrypted), staging.path())
        .unwrap();
    let mut result = Vec::new();
    payload.read_to_end(&mut result).unwrap();
    assert!(result == plain);
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
}

#[test]
fn lifecycle_is_durable_and_committed_receipt_cannot_decrypt_or_replay() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("sentinel"), b"unrelated recovery data").unwrap();
    let mut store = open_fixture(root.path()).unwrap();
    let (mut ticket, encrypted, plain) = fixture();
    store.publish_prepared(&ticket).unwrap();
    let stale = store.load().unwrap().unwrap();
    let staging = tempdir().unwrap();
    let mut payload = store
        .decrypt(
            &ticket,
            &observed(BOOT),
            &mut Cursor::new(&encrypted),
            staging.path(),
        )
        .unwrap();
    let mut restored = Vec::new();
    payload.read_to_end(&mut restored).unwrap();
    assert!(restored == plain);
    store.begin_apply(&mut ticket, &observed(BOOT)).unwrap();
    assert!(
        store
            .decrypt(
                &stale,
                &observed(BOOT),
                &mut Cursor::new(&encrypted),
                staging.path()
            )
            .is_err()
    );
    store.mark_restored(&mut ticket, &observed(BOOT)).unwrap();
    store.commit(&mut ticket, &observed(BOOT)).unwrap();
    assert_eq!(ticket.phase(), Phase::Committed);
    assert!(ticket.secret.is_none());
    let bytes = fs::read(record_path(root.path(), STATE)).unwrap();
    assert!(bytes[105..137].iter().all(|b| *b == 0));
    assert!(!record_path(root.path(), NEXT).exists());
    assert!(
        store
            .decrypt(
                &stale,
                &observed(BOOT),
                &mut Cursor::new(&encrypted),
                staging.path()
            )
            .is_err()
    );
    assert!(
        store
            .decrypt(
                &ticket,
                &observed(BOOT),
                &mut Cursor::new(&encrypted),
                staging.path()
            )
            .is_err()
    );
    assert!(matches!(
        store.publish_prepared(&stale),
        Err(TicketError::Replay)
    ));
    drop(store);
    let mut store = open_fixture(root.path()).unwrap();
    let receipt = store.load().unwrap().unwrap();
    assert_eq!(receipt.phase(), Phase::Committed);
    assert!(receipt.secret.is_none());
    assert_eq!(
        fs::read(root.path().join("sentinel")).unwrap(),
        b"unrelated recovery data"
    );
}

struct NeverRead;
impl Read for NeverRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("untrusted ciphertext must not be read");
    }
}

#[test]
fn wrong_boot_device_versions_and_target_fail_before_reading_capsule() {
    let root = tempdir().unwrap();
    let mut store = open_fixture(root.path()).unwrap();
    let (ticket, _, _) = fixture();
    store.publish_prepared(&ticket).unwrap();
    let staging = tempdir().unwrap();
    for kind in 0..5 {
        let mut observation = observed(BOOT);
        match kind {
            0 => observation.boot_id = BootId::parse(SOURCE).unwrap(),
            1 => observation.device_id = [9; 32],
            2 => observation.system_version = "wrong-version",
            3 => observation.app_version = "wrong-app",
            _ => observation.target = "wrong-target",
        }
        assert!(matches!(
            store.decrypt(&ticket, &observation, &mut NeverRead, staging.path()),
            Err(TicketError::WrongBoot)
        ));
    }
    assert_eq!(store.load().unwrap().unwrap().phase(), Phase::Prepared);
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
}

#[test]
fn unregistered_or_stale_in_memory_tickets_never_authorize_decryption() {
    let root = tempdir().unwrap();
    let mut store = open_fixture(root.path()).unwrap();
    let (ticket, _, _) = fixture();
    let staging = tempdir().unwrap();
    assert!(
        store
            .decrypt(&ticket, &observed(BOOT), &mut NeverRead, staging.path())
            .is_err()
    );
    store.publish_prepared(&ticket).unwrap();
    let (other, _, _) = fixture();
    assert!(
        store
            .decrypt(&other, &observed(BOOT), &mut NeverRead, staging.path())
            .is_err()
    );
    assert!(matches!(
        store.publish_prepared(&other),
        Err(TicketError::Busy)
    ));
}

#[test]
fn state_order_and_current_restore_boot_are_enforced_across_restarts() {
    let root = tempdir().unwrap();
    let mut store = open_fixture(root.path()).unwrap();
    let (mut ticket, _, _) = fixture();
    store.publish_prepared(&ticket).unwrap();
    assert!(store.commit(&mut ticket, &observed(BOOT)).is_err());
    assert!(store.mark_restored(&mut ticket, &observed(BOOT)).is_err());
    assert!(store.begin_apply(&mut ticket, &observed(SOURCE)).is_err());
    store.begin_apply(&mut ticket, &observed(BOOT)).unwrap();
    assert!(store.commit(&mut ticket, &observed(BOOT)).is_err());
    drop(store);
    let mut store = open_fixture(root.path()).unwrap();
    let mut ticket = store.load().unwrap().unwrap();
    assert!(store.mark_restored(&mut ticket, &observed(REBOOT)).is_err());
    store.begin_apply(&mut ticket, &observed(REBOOT)).unwrap();
    store.mark_restored(&mut ticket, &observed(REBOOT)).unwrap();
    assert!(store.begin_apply(&mut ticket, &observed(REBOOT)).is_err());
    store.commit(&mut ticket, &observed(BOOT)).unwrap();
    assert_eq!(ticket.phase(), Phase::Committed);
}

#[test]
fn every_changed_record_byte_and_bad_inner_fields_are_rejected() {
    let (ticket, _, _) = fixture();
    let bytes = encode(&ticket, Phase::Prepared, None).unwrap();
    for index in 0..RECORD_BYTES {
        let mut changed = Zeroizing::new(*bytes);
        changed[index] ^= 1;
        assert!(
            decode(&changed).is_err(),
            "changed record byte {index} must fail"
        );
    }
    for index in [8, 9, 16, 40, 104, 137, 169, 201, 233, 265, 297, 362, 427] {
        let mut changed = Zeroizing::new(*bytes);
        match index {
            8 => changed[index] = 0,
            16 => changed[16..32].fill(0),
            137 => changed[137..153].fill(0),
            169 | 201 | 233 | 265 => changed[index..index + 32].fill(0),
            40 | 297 | 362 => changed[index] = 65,
            _ => changed[index] = 255,
        }
        reseal(&mut changed);
        assert!(decode(&changed).is_err(), "invalid protected field {index}");
    }
    let mut committed = encode(
        &ticket,
        Phase::Committed,
        Some(BootId::parse(BOOT).unwrap()),
    )
    .unwrap();
    committed[105] = 1;
    reseal(&mut committed);
    assert!(decode(&committed).is_err());
}

#[test]
fn ciphertext_hash_is_checked_even_after_successful_aead() {
    let root = tempdir().unwrap();
    let staging = tempdir().unwrap();
    let mut store = open_fixture(root.path()).unwrap();
    let (mut ticket, encrypted, _) = fixture();
    ticket.binding.capsule_sha256 = [99; 32];
    store.publish_prepared(&ticket).unwrap();
    assert!(matches!(
        store.decrypt(
            &ticket,
            &observed(BOOT),
            &mut Cursor::new(encrypted),
            staging.path()
        ),
        Err(TicketError::Invalid)
    ));
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    assert_eq!(store.load().unwrap().unwrap().phase(), Phase::Prepared);
}

#[test]
fn store_is_private_pinned_and_exclusively_owned() {
    let root = tempdir().unwrap();
    let mut store = open_fixture(root.path()).unwrap();
    assert!(matches!(open_fixture(root.path()), Err(TicketError::Busy)));
    let metadata = fs::metadata(root.path()).unwrap();
    let file = restore_fs::open_root(root.path(), false).unwrap();
    assert!(matches!(
        Store::from_boot(file, metadata.uid() + 1, metadata.dev()),
        Err(TicketError::UnsafeStore)
    ));
    let file = restore_fs::open_root(root.path(), false).unwrap();
    assert!(matches!(
        Store::from_boot(file, metadata.uid(), metadata.dev() + 1),
        Err(TicketError::UnsafeStore)
    ));
    let (ticket, _, _) = fixture();
    store.publish_prepared(&ticket).unwrap();
    drop(store);
    let store = open_fixture(root.path()).unwrap();
    drop(store);
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        open_fixture(root.path()),
        Err(TicketError::UnsafeStore)
    ));
}

#[test]
fn aliases_hardlinks_nonfiles_and_shared_state_are_rejected() {
    for kind in 0..4 {
        let root = tempdir().unwrap();
        let mut store = open_fixture(root.path()).unwrap();
        let (ticket, _, _) = fixture();
        store.publish_prepared(&ticket).unwrap();
        drop(store);
        let path = record_path(root.path(), STATE);
        match kind {
            0 => {
                let moved = root.path().join("moved");
                fs::rename(&path, &moved).unwrap();
                symlink(moved, &path).unwrap();
            }
            1 => fs::hard_link(&path, root.path().join("alias")).unwrap(),
            2 => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
        }
        assert!(open_fixture(root.path()).is_err());
    }
}

#[test]
fn renamed_boot_path_cannot_redirect_the_open_store() {
    let parent = tempdir().unwrap();
    let boot = parent.path().join("boot");
    let moved = parent.path().join("moved");
    let outside = parent.path().join("outside");
    fs::create_dir(&boot).unwrap();
    fs::set_permissions(&boot, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&outside).unwrap();
    let mut store = open_fixture(&boot).unwrap();
    fs::rename(&boot, &moved).unwrap();
    symlink(&outside, &boot).unwrap();
    let (ticket, _, _) = fixture();
    store.publish_prepared(&ticket).unwrap();
    assert!(record_path(&moved, STATE).is_file());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn interrupted_initial_publication_is_not_promoted_or_deleted() {
    let root = tempdir().unwrap();
    let store = open_fixture(root.path()).unwrap();
    drop(store);
    private_write(
        &record_path(root.path(), NEXT),
        b"partial private initial record",
    );
    assert!(matches!(
        open_fixture(root.path()),
        Err(TicketError::Ambiguous)
    ));
    assert!(record_path(root.path(), NEXT).exists());
    assert!(!record_path(root.path(), STATE).exists());
}

#[test]
fn canonical_valid_record_wins_over_partial_next_but_corruption_preserves_evidence() {
    let root = tempdir().unwrap();
    let mut store = open_fixture(root.path()).unwrap();
    let (ticket, _, _) = fixture();
    store.publish_prepared(&ticket).unwrap();
    drop(store);
    private_write(&record_path(root.path(), NEXT), b"partial replacement");
    let mut store = open_fixture(root.path()).unwrap();
    assert_eq!(store.load().unwrap().unwrap().phase(), Phase::Prepared);
    assert!(!record_path(root.path(), NEXT).exists());
    drop(store);
    private_write(
        &record_path(root.path(), STATE),
        b"corrupt canonical record",
    );
    private_write(&record_path(root.path(), NEXT), b"unique recovery material");
    assert!(open_fixture(root.path()).is_err());
    assert_eq!(
        fs::read(record_path(root.path(), NEXT)).unwrap(),
        b"unique recovery material"
    );
}

#[test]
fn dropping_store_releases_lock_even_while_an_incidental_fd_alias_is_alive() {
    let root = tempdir().unwrap();
    let store = open_fixture(root.path()).unwrap();
    // dup and a pre-exec fork share exactly the same open file description.
    // CLOEXEC does not prevent that temporary child/alias from retaining flock.
    let incidental_alias = store.directory.try_clone().unwrap();
    assert!(matches!(open_fixture(root.path()), Err(TicketError::Busy)));
    drop(store);
    let successor = open_fixture(root.path())
        .expect("an incidental inherited descriptor must not extend Store ownership");
    assert!(matches!(open_fixture(root.path()), Err(TicketError::Busy)));
    drop(incidental_alias);
    assert!(matches!(open_fixture(root.path()), Err(TicketError::Busy)));
    drop(successor);
    assert!(open_fixture(root.path()).is_ok());
}

#[test]
fn publication_faults_poison_handle_and_reopen_observes_actual_old_or_new_state() {
    for step in [
        PublishStep::BeforeCreate,
        PublishStep::AfterCreate,
        PublishStep::AfterWrite,
        PublishStep::AfterFileSync,
        PublishStep::AfterRename,
        PublishStep::AfterDirectorySync,
    ] {
        let root = tempdir().unwrap();
        let mut store = open_fixture(root.path()).unwrap();
        let (mut ticket, _, _) = fixture();
        store.publish_prepared(&ticket).unwrap();
        store.fail_at = Some(step);
        assert!(matches!(
            store.begin_apply(&mut ticket, &observed(BOOT)),
            Err(TicketError::Ambiguous)
        ));
        assert_eq!(ticket.phase(), Phase::Prepared);
        assert!(matches!(store.load(), Err(TicketError::Ambiguous)));
        drop(store);
        let mut store = open_fixture(root.path()).unwrap();
        let actual = store.load().unwrap().unwrap();
        let advanced = matches!(
            step,
            PublishStep::AfterRename | PublishStep::AfterDirectorySync
        );
        assert_eq!(
            actual.phase(),
            if advanced {
                Phase::Applying
            } else {
                Phase::Prepared
            }
        );
        assert!(!record_path(root.path(), NEXT).exists());
        if advanced {
            assert!(store.begin_apply(&mut ticket, &observed(BOOT)).is_err());
        }
    }
}

#[test]
fn commit_faults_never_retain_a_decryptable_committed_record() {
    for step in [
        PublishStep::AfterFileSync,
        PublishStep::AfterRename,
        PublishStep::AfterDirectorySync,
    ] {
        let root = tempdir().unwrap();
        let (mut store, mut ticket, encrypted, _) = applying(root.path());
        store.mark_restored(&mut ticket, &observed(BOOT)).unwrap();
        store.fail_at = Some(step);
        assert!(matches!(
            store.commit(&mut ticket, &observed(BOOT)),
            Err(TicketError::Ambiguous)
        ));
        drop(store);
        let mut store = open_fixture(root.path()).unwrap();
        let actual = store.load().unwrap().unwrap();
        let staging = tempdir().unwrap();
        if step == PublishStep::AfterFileSync {
            assert_eq!(actual.phase(), Phase::Restored);
            // Restored may be re-authenticated for verification after reboot,
            // but begin_apply refuses to authorize applying it a second time.
            assert!(
                store
                    .decrypt(
                        &actual,
                        &observed(BOOT),
                        &mut Cursor::new(&encrypted),
                        staging.path()
                    )
                    .is_ok()
            );
        } else {
            assert_eq!(actual.phase(), Phase::Committed);
            assert!(actual.secret.is_none());
            assert!(
                store
                    .decrypt(
                        &ticket,
                        &observed(BOOT),
                        &mut Cursor::new(&encrypted),
                        staging.path()
                    )
                    .is_err()
            );
        }
        if actual.phase() == Phase::Committed {
            assert!(
                store
                    .decrypt(
                        &actual,
                        &observed(BOOT),
                        &mut Cursor::new(&encrypted),
                        staging.path()
                    )
                    .is_err()
            );
        }
    }
}

#[test]
fn new_fresh_transaction_can_replace_only_a_committed_receipt() {
    let root = tempdir().unwrap();
    let (mut store, mut ticket, _, _) = applying(root.path());
    store.mark_restored(&mut ticket, &observed(BOOT)).unwrap();
    store.commit(&mut ticket, &observed(BOOT)).unwrap();
    let (mut next, _, _) = fixture();
    next.binding.source_boot = BootId::parse(BOOT).unwrap();
    store.publish_prepared(&next).unwrap();
    assert_eq!(
        store.load().unwrap().unwrap().transaction_id(),
        next.transaction_id()
    );
}

#[test]
fn boot_mount_must_be_unique_whole_expected_partition_not_a_bind_subtree() {
    let root: TempDir = tempdir().unwrap();
    let device = fs::metadata(root.path()).unwrap().dev();
    let number = format!(
        "{}:{}",
        rustix::fs::major(device),
        rustix::fs::minor(device)
    );
    let line = format!(
        "21 1 {number} / /boot rw,nosuid,nodev,noexec - vfat /dev/mmcblk0p1 rw,fmask=0177,dmask=0077\n"
    );
    assert!(boot_mount_is_root(&line, device));
    assert!(!boot_mount_is_root(&(line.clone() + &line), device));
    assert!(!boot_mount_is_root(
        &line.replace(" / /boot ", " /alias /boot "),
        device
    ));
    assert!(!boot_mount_is_root(
        &line.replace("mmcblk0p1", "mmcblk0p3"),
        device
    ));
    assert!(!boot_mount_is_root(&line.replace("vfat", "exfat"), device));
    assert!(!boot_mount_is_root(
        &line.replace(&number, "999:999"),
        device
    ));
}

#[test]
fn ticket_process_crash_child() {
    let Some(root) = std::env::var_os("NANOKVM_TICKET_CRASH_FIXTURE_ROOT") else {
        return;
    };
    let step = match std::env::var("NANOKVM_TICKET_CRASH_FIXTURE_STEP")
        .unwrap()
        .as_str()
    {
        "before-rename" => PublishStep::AfterFileSync,
        "after-rename" => PublishStep::AfterRename,
        _ => panic!("invalid synthetic crash step"),
    };
    let mut store = open_fixture(Path::new(&root)).unwrap();
    let (mut ticket, _, _) = fixture();
    store.publish_prepared(&ticket).unwrap();
    store.pause_at = Some(step);
    store.begin_apply(&mut ticket, &observed(BOOT)).unwrap();
}

#[test]
fn actual_process_kill_releases_lock_and_recovers_before_and_after_rename() {
    use std::{
        io::{BufRead, BufReader},
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::Duration,
    };
    for (step, expected) in [
        ("before-rename", Phase::Prepared),
        ("after-rename", Phase::Applying),
    ] {
        let root = tempdir().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::restore_capsule::ticket::tests::ticket_process_crash_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NANOKVM_TICKET_CRASH_FIXTURE_ROOT", root.path())
            .env("NANOKVM_TICKET_CRASH_FIXTURE_STEP", step)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            let mut line = String::new();
            while stdout.read_line(&mut line).unwrap_or(0) > 0 {
                if line.trim_end().ends_with("TICKET_FIXTURE_READY") {
                    // Report framing as a boolean, never dump private child I/O.
                    let _ = tx.send(line.trim() == "TICKET_FIXTURE_READY");
                    break;
                }
                line.clear();
            }
        });
        let ready = rx.recv_timeout(Duration::from_secs(5));
        let early_exit = child.try_wait().unwrap();
        if early_exit.is_none() {
            let _ = child.kill();
        }
        let terminal = child.wait().unwrap();
        reader.join().unwrap();
        assert!(
            matches!(ready, Ok(true)),
            "child did not reach standalone synthetic checkpoint {step}; frame={ready:?}, early={early_exit:?}, terminal={terminal}"
        );
        let mut store = open_fixture(root.path()).unwrap();
        assert_eq!(store.load().unwrap().unwrap().phase(), expected);
        assert!(!record_path(root.path(), NEXT).exists());
    }
}
