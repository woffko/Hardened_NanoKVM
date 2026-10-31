use super::*;
use crate::update::{
    operation::{Kind, UpdateCoordinator},
    operation_lock::{LockError, ProcessLock},
    state_writers::StateWriters,
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    sync::Arc,
};

const ID: [u8; 16] = [7; 16];

struct Fixture {
    root: tempfile::TempDir,
    owner: UpdateOwner,
    handoff: Handoff,
}
async fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let parent = File::open(root.path()).unwrap();
    let coordinator = Arc::new(UpdateCoordinator::with_test_parent(
        parent.try_clone().unwrap(),
    ));
    let owner = coordinator.acquire(Kind::ApplicationOffline).unwrap();
    let writers = StateWriters::for_test_parent(parent);
    let writers = writers.drain(Duration::from_secs(1)).await.unwrap();
    let handoff = owner.prepare_install_handoff(writers).unwrap();
    Fixture {
        root,
        owner,
        handoff,
    }
}

fn check_busy(parent: &File, domains: &[Domain]) {
    for domain in domains {
        assert!(matches!(
            ProcessLock::at_parent(parent, nix::unistd::geteuid().as_raw(), *domain, false),
            Err(LockError::Busy)
        ));
    }
}

fn check_free(parent: &File) {
    for domain in [
        Domain::WriterActivity,
        Domain::WriterAdmission,
        Domain::Update,
    ] {
        check_released(parent, domain);
    }
}

fn check_released(parent: &File, domain: Domain) {
    // A parallel fixture can fork with a temporary CLOEXEC alias. Exported
    // descriptions intentionally cannot be explicitly unlocked on Drop.
    // Observe actual release; never force-unlock or hide non-Busy errors.
    let start = std::time::Instant::now();
    loop {
        match ProcessLock::at_parent(parent, nix::unistd::geteuid().as_raw(), domain, false) {
            Ok(lease) => {
                drop(lease);
                break;
            }
            Err(LockError::Busy) if start.elapsed() < Duration::from_secs(3) => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(error) => panic!("lease release failed: {error}"),
        }
    }
}

#[tokio::test]
async fn queued_three_leases_survive_all_sender_owners_until_receiver_releases() {
    let Fixture {
        root,
        owner,
        handoff,
    } = fixture().await;
    let id = handoff.transaction();
    let parent = File::open(root.path()).unwrap();
    let (sender, receiver) = pair().unwrap();
    sender.send(handoff).unwrap();
    drop(owner);
    check_busy(
        &parent,
        &[
            Domain::Update,
            Domain::WriterAdmission,
            Domain::WriterActivity,
        ],
    );
    let accepted = receive(
        &receiver.socket,
        id,
        &parent,
        nix::unistd::geteuid().as_raw(),
    )
    .unwrap();
    drop(receiver);
    assert_eq!(accepted.transaction(), id);
    for file in accepted._files.wire() {
        assert!(fcntl_getfd(file).unwrap().contains(FdFlags::CLOEXEC));
    }
    check_busy(
        &parent,
        &[
            Domain::Update,
            Domain::WriterAdmission,
            Domain::WriterActivity,
        ],
    );
    drop(accepted);
    check_free(&parent);
}

#[tokio::test]
async fn receiver_drop_cannot_explicitly_unlock_still_live_frontend_description() {
    let Fixture {
        root,
        owner,
        handoff,
    } = fixture().await;
    let id = handoff.transaction();
    let parent = File::open(root.path()).unwrap();
    let (sender, receiver) = pair().unwrap();
    sender.send(handoff).unwrap();
    let accepted = receive(
        &receiver.socket,
        id,
        &parent,
        nix::unistd::geteuid().as_raw(),
    )
    .unwrap();
    drop(receiver);
    drop(accepted);
    check_busy(&parent, &[Domain::Update]);
    drop(owner);
    check_free(&parent);
}

#[tokio::test]
async fn retained_preexec_alias_conservatively_extends_exclusion_until_close() {
    let Fixture {
        root,
        owner,
        handoff,
    } = fixture().await;
    let parent = File::open(root.path()).unwrap();
    let id = handoff.transaction();
    let preexec = handoff.files.activity.try_clone().unwrap();
    assert!(fcntl_getfd(&preexec).unwrap().contains(FdFlags::CLOEXEC));
    let (sender, receiver) = pair().unwrap();
    sender.send(handoff).unwrap();
    let accepted = receive(
        &receiver.socket,
        id,
        &parent,
        nix::unistd::geteuid().as_raw(),
    )
    .unwrap();
    drop(receiver);
    drop(owner);
    drop(accepted);
    check_busy(&parent, &[Domain::WriterActivity]);
    drop(preexec);
    check_free(&parent);
}

#[tokio::test]
async fn abandoned_receiver_closes_queued_rights_without_releasing_live_frontend() {
    let Fixture {
        root,
        owner,
        handoff,
    } = fixture().await;
    let parent = File::open(root.path()).unwrap();
    let (sender, receiver) = pair().unwrap();
    sender.send(handoff).unwrap();
    drop(receiver);
    check_busy(&parent, &[Domain::Update]);
    drop(owner);
    check_free(&parent);
}

#[tokio::test]
async fn broken_send_is_not_retried_or_allowed_to_unlock_frontend() {
    let Fixture {
        root,
        owner,
        handoff,
    } = fixture().await;
    let parent = File::open(root.path()).unwrap();
    let (sender, receiver) = pair().unwrap();
    // A concurrent fork can retain a CLOEXEC receiver alias before exec. A
    // close alone then does not inject a broken peer; shutdown does, including
    // through that alias. Keep one explicitly so this case is deterministic.
    let preexec = receiver.socket.try_clone().unwrap();
    rustix::net::shutdown(&receiver.socket, rustix::net::Shutdown::Both).unwrap();
    drop(receiver);
    assert!(sender.send(handoff).is_err());
    check_busy(&parent, &[Domain::Update]);
    // Sending failed and closed the writer owners. The still-live frontend
    // must retain UpdateEX, not WriterEX; wait for any pre-exec aliases before
    // testing that the one-shot export cannot be repeated.
    check_released(&parent, Domain::WriterActivity);
    check_released(&parent, Domain::WriterAdmission);
    let writers = StateWriters::for_test_parent(parent.try_clone().unwrap())
        .drain(Duration::from_secs(1))
        .await
        .unwrap();
    assert!(owner.prepare_install_handoff(writers).is_err());
    check_busy(&parent, &[Domain::Update]);
    drop(preexec);
    drop(owner);
    check_free(&parent);
}

#[tokio::test]
async fn wrong_transaction_swapped_domains_and_foreign_names_never_grant_acceptance() {
    for fault in [
        "transaction",
        "swapped",
        "foreign",
        "mode",
        "symlink",
        "separate-ofd",
    ] {
        let Fixture {
            root,
            owner,
            mut handoff,
        } = fixture().await;
        let parent = File::open(root.path()).unwrap();
        let mut expected = handoff.transaction();
        match fault {
            "separate-ofd" => {
                handoff.files.update =
                    File::open(root.path().join(Domain::Update.directory())).unwrap()
            }
            "transaction" => expected[0] ^= 1,
            "swapped" => std::mem::swap(&mut handoff.files.admission, &mut handoff.files.activity),
            "foreign" => {
                let foreign = tempfile::tempdir().unwrap();
                let mut lock = ProcessLock::at_parent(
                    &File::open(foreign.path()).unwrap(),
                    nix::unistd::geteuid().as_raw(),
                    Domain::WriterActivity,
                    false,
                )
                .unwrap();
                handoff.files.activity = lock.transfer_alias().unwrap();
                // Retain that directory inode after the disposable name disappears.
            }
            "mode" => fs::set_permissions(
                root.path().join(Domain::WriterActivity.directory()),
                fs::Permissions::from_mode(0o777),
            )
            .unwrap(),
            "symlink" => {
                fs::rename(
                    root.path().join(Domain::WriterActivity.directory()),
                    root.path().join("original"),
                )
                .unwrap();
                symlink(
                    "original",
                    root.path().join(Domain::WriterActivity.directory()),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let (sender, receiver) = pair().unwrap();
        sender.send(handoff).unwrap();
        assert!(
            receive(
                &receiver.socket,
                expected,
                &parent,
                nix::unistd::geteuid().as_raw()
            )
            .is_err(),
            "{fault}"
        );
        drop(receiver);
        check_busy(&parent, &[Domain::Update]);
        drop(owner);
    }
}

#[tokio::test]
async fn ancillary_missing_extra_and_duplicate_domains_close_without_unlocking_sender() {
    for count in [0, 1, 2, 3, 4] {
        let Fixture {
            root,
            owner,
            handoff,
        } = fixture().await;
        let parent = File::open(root.path()).unwrap();
        let (sender, receiver) = pair().unwrap();
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&handoff.transaction);
        let m = handoff.files.update.metadata().unwrap();
        for encoded in bytes[24..].as_chunks_mut::<16>().0 {
            encoded[..8].copy_from_slice(&m.dev().to_be_bytes());
            encoded[8..].copy_from_slice(&m.ino().to_be_bytes());
        }
        let descriptors = [handoff.files.update.as_fd(); 4];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if count != 0 {
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors[..count])));
        }
        sendmsg(
            &sender.socket,
            &[IoSlice::new(&bytes)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert!(
            receive(
                &receiver.socket,
                handoff.transaction,
                &parent,
                nix::unistd::geteuid().as_raw()
            )
            .is_err(),
            "count={count}"
        );
        drop(receiver);
        drop(sender);
        drop(handoff);
        check_busy(&parent, &[Domain::Update]);
        drop(owner);
        check_free(&parent);
    }
}

#[tokio::test]
async fn system_jobs_and_inprocess_only_fixture_cannot_issue_install_handoff() {
    for real_admission in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let parent = File::open(root.path()).unwrap();
        let coordinator = Arc::new(if real_admission {
            UpdateCoordinator::with_test_parent(parent.try_clone().unwrap())
        } else {
            UpdateCoordinator::in_process_fixture()
        });
        let owner = coordinator
            .acquire(if real_admission {
                Kind::SystemInstall
            } else {
                Kind::ApplicationOffline
            })
            .unwrap();
        let writers = StateWriters::for_test_parent(parent.try_clone().unwrap())
            .drain(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(owner.prepare_install_handoff(writers).is_err());
        if real_admission {
            check_busy(&parent, &[Domain::Update]);
        }
        drop(owner);
        check_free(&parent);
    }
}

#[test]
fn record_shape_and_peer_validation_are_closed_and_receive_has_finite_deadline() {
    let root = tempfile::tempdir().unwrap();
    let parent = File::open(root.path()).unwrap();
    for length in [0, 8, BYTES - 1, BYTES, BYTES + 1] {
        let (sender, receiver) = pair().unwrap();
        let mut bytes = vec![0; length];
        if length >= 24 {
            bytes[..8].copy_from_slice(MAGIC);
            bytes[8..24].copy_from_slice(&ID);
        }
        let mut space = [];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        sendmsg(
            &sender.socket,
            &[IoSlice::new(&bytes)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert!(matches!(
            receive(
                &receiver.socket,
                ID,
                &parent,
                nix::unistd::geteuid().as_raw()
            ),
            Err(Error::Record)
        ));
    }
    let (_sender, receiver) = pair().unwrap();
    let started = std::time::Instant::now();
    assert!(
        receive(
            &receiver.socket,
            ID,
            &parent,
            nix::unistd::geteuid().as_raw()
        )
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(prepare(&receiver.socket, 0, nix::unistd::geteuid().as_raw()).is_err());
    assert!(
        prepare(
            &receiver.socket,
            nix::unistd::getpid().as_raw() as u32 + 1,
            nix::unistd::geteuid().as_raw()
        )
        .is_err()
    );
    let (stream, _peer) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    assert!(
        prepare(
            &stream,
            nix::unistd::getpid().as_raw() as u32,
            nix::unistd::geteuid().as_raw()
        )
        .is_err()
    );
    if !nix::unistd::geteuid().is_root() {
        assert!(matches!(channel(), Err(Error::Channel)));
    }
    assert!(
        prepare(
            &receiver.socket,
            nix::unistd::getpid().as_raw() as u32,
            nix::unistd::geteuid().as_raw().wrapping_add(1)
        )
        .is_err()
    );
}

#[cfg(feature = "sandbox-test-fixture")]
struct Worker(std::process::Child);
#[cfg(feature = "sandbox-test-fixture")]
impl Worker {
    fn finish(&mut self) {
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "lease worker failed: {status}");
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(12),
                "lease worker deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
#[cfg(feature = "sandbox-test-fixture")]
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn root_exchange_child() {
    let Some(root) = std::env::var_os("NANOKVM_APP_LEASE_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    if std::env::var("NANOKVM_APP_LEASE_ROLE").unwrap() == "receiver" {
        let socket = rustix::io::dup(std::io::stdin()).unwrap();
        let null = File::open("/dev/null").unwrap();
        use std::os::fd::AsRawFd;
        nix::unistd::dup2(null.as_raw_fd(), 0).unwrap();
        drop(null);
        let receiver = Receiver::adopt(socket, nix::unistd::getppid().as_raw() as u32).unwrap();
        nix::unistd::chroot(root).unwrap();
        std::env::set_current_dir("/").unwrap();
        let start = std::time::Instant::now();
        while !Path::new("/expected-id").exists() {
            assert!(start.elapsed() < Duration::from_secs(8));
            std::thread::sleep(Duration::from_millis(5));
        }
        // Fixture-only expected context, not an installation receipt.
        let expected = u128::from_str_radix(&fs::read_to_string("/expected-id").unwrap(), 16)
            .unwrap()
            .to_be_bytes();
        // Actual production receiver; no fixture parent/path override.
        let accepted = receiver.receive(expected).unwrap();
        assert_eq!(accepted.transaction(), expected);
        fs::write("/accepted", b"accepted").unwrap();
        let start = std::time::Instant::now();
        while !Path::new("/release").exists() {
            assert!(start.elapsed() < Duration::from_secs(8));
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(accepted);
        return;
    }
    assert!(nix::unistd::geteuid().is_root());
    fs::create_dir_all(root.join("etc/kvm")).unwrap();
    let (sender, receiver) = channel().unwrap();
    let mut child = Worker(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::app_install_lease::tests::root_exchange_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_APP_LEASE_ROOT", root)
            .env("NANOKVM_APP_LEASE_ROLE", "receiver")
            .stdin(receiver.into_stdio())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    nix::unistd::chroot(root).unwrap();
    std::env::set_current_dir("/").unwrap();
    let root = Path::new("/");
    let parent = File::open("/etc/kvm").unwrap();
    // Actual production sender admission and writer drain, not private-parent
    // constructors. The receiver was exec'd before this private chroot.
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::ApplicationOffline).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let writers = runtime
        .block_on(StateWriters::default().drain(Duration::from_secs(1)))
        .unwrap();
    let handoff = owner.prepare_install_handoff(writers).unwrap();
    fs::write(
        "/expected-id.next",
        format!("{:032x}", u128::from_be_bytes(handoff.transaction())),
    )
    .unwrap();
    fs::rename("/expected-id.next", "/expected-id").unwrap();
    sender.send(handoff).unwrap();
    drop(owner);
    let start = std::time::Instant::now();
    while !root.join("accepted").exists() {
        assert!(start.elapsed() < Duration::from_secs(8));
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "receiver exited before acceptance"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    check_busy(
        &parent,
        &[
            Domain::Update,
            Domain::WriterAdmission,
            Domain::WriterActivity,
        ],
    );
    fs::write(root.join("release"), b"release").unwrap();
    child.finish();
    check_free(&parent);
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn actual_exec_receiver_retains_three_fixed_root_leases_after_frontend_drop() {
    let root = tempfile::tempdir().unwrap();
    let mut child = Worker(
        std::process::Command::new("/usr/bin/unshare")
            .args(["--user", "--map-root-user", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::app_install_lease::tests::root_exchange_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_APP_LEASE_ROOT", root.path())
            .env("NANOKVM_APP_LEASE_ROLE", "sender")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    child.finish();
    assert!(root.path().join("accepted").exists());
}

#[tokio::test]
async fn an_offer_hears_taken_refused_or_nothing_from_an_older_installer() {
    for reply in [Some(true), Some(false), None] {
        let Fixture {
            root,
            owner,
            handoff,
        } = fixture().await;
        let (sender, receiver) = pair().unwrap();
        let parent = File::open(root.path()).unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        let mut incoming = Incoming::fixture(receiver.socket, parent, uid).unwrap();
        let installer = std::thread::spawn(move || {
            let accepted = loop {
                if let Some(accepted) = incoming.poll().unwrap() {
                    break accepted;
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            drop(accepted);
            if let Some(taken) = reply {
                incoming.answer(taken);
            }
        });
        let answer = sender.offer(handoff).unwrap();
        installer.join().unwrap();
        assert!(matches!(
            (reply, answer),
            (Some(true), Answer::Taken)
                | (Some(false), Answer::Refused(_))
                | (None, Answer::Unknown)
        ));
        drop(owner);
    }
}
