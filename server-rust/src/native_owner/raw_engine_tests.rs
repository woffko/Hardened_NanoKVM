use super::*;
use crate::update::{
    operation::{Kind, UpdateCoordinator},
    operation_lock::{Domain, LockError, ProcessLock},
    raw_install_lease::{self, RawImages, RawSender},
    restore_capsule::{
        prepare_capsule,
        ticket::{Binding, BootId, RestoreTicket, Store},
    },
    state_writers::StateWriters,
};
use sha2::{Digest, Sha256};
use std::{
    io::{Cursor, Write},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    sync::Arc,
};

const VERSION: &str = "0.3.0-raw.13";
const IMAGES: [&[u8]; 2] = [b"synthetic boot image", b"synthetic root filesystem image"];
const DOMAINS: [Domain; 3] = [
    Domain::Update,
    Domain::WriterAdmission,
    Domain::WriterActivity,
];

fn digests() -> [[u8; 32]; 2] {
    IMAGES.map(|image| Sha256::digest(image).into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ticket(sha256: [[u8; 32]; 2]) -> RestoreTicket {
    let plaintext = b"synthetic restore archive";
    let mut encrypted = Vec::new();
    let secret = prepare_capsule(
        VERSION,
        plaintext.len() as u64,
        &mut Cursor::new(&plaintext[..]),
        &mut encrypted,
    )
    .unwrap();
    RestoreTicket::prepared(
        secret,
        Binding {
            source_boot: BootId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            device_id: [1; 32],
            capsule_sha256: Sha256::digest(&encrypted).into(),
            boot_image_sha256: sha256[0],
            rootfs_image_sha256: sha256[1],
            target_app_version: "2.0.43".into(),
            target: "sg2002-licheervnano-sd".into(),
        },
    )
    .unwrap()
}

// The fixture's boot partition, as the engine reads it.
fn publish(root: &Path, ticket: &RestoreTicket) {
    let boot = root.join("boot");
    fs::create_dir(&boot).unwrap();
    fs::set_permissions(&boot, fs::Permissions::from_mode(0o700)).unwrap();
    Store::open_fixture(&boot)
        .unwrap()
        .publish_prepared(ticket)
        .unwrap();
}

fn snapshot(bytes: &[u8]) -> File {
    let mut writable = tempfile::tempfile().unwrap();
    writable.write_all(bytes).unwrap();
    File::open(format!("/proc/self/fd/{}", writable.as_raw_fd())).unwrap()
}

fn images() -> RawImages {
    RawImages {
        files: IMAGES.map(snapshot),
        sizes: IMAGES.map(|image| image.len() as u64),
        sha256: digests(),
    }
}

// The backend's handoff with the leases under the fixture root.
async fn handoff(root: &Path, transaction: [u8; 16]) -> raw_install_lease::RawHandoff {
    let coordinator = Arc::new(UpdateCoordinator::with_test_parent(
        File::open(root).unwrap(),
    ));
    let owner = coordinator.acquire(Kind::SystemInstall).unwrap();
    let writers = StateWriters::for_test_parent(File::open(root).unwrap())
        .drain(Duration::from_secs(1))
        .await
        .unwrap();
    owner
        .prepare_raw_handoff(transaction, images(), writers)
        .unwrap()
}

async fn offer(root: &Path, transaction: [u8; 16]) -> RawAccepted {
    raw_install_lease::exchange_fixture(handoff(root, transaction).await, File::open(root).unwrap())
        .unwrap()
}

fn start_all(engine: &mut Engine) {
    for operation in [
        Operation::EnsureKvm,
        Operation::EnsureHwmon,
        Operation::EnsureBackend,
    ] {
        assert_eq!(engine.request(1, operation).code, Code::Ok);
    }
    until(|| {
        engine.tick();
        engine.roles == [2; 2] && engine.backend_status == Some(Status::Running)
    });
}

fn running(engine: &Engine) -> bool {
    engine.mode == Mode::Running
        && engine.roles == [2; 2]
        && engine.backend_status == Some(Status::Running)
        && engine.raw.is_none()
}

fn busy(root: &Path) -> bool {
    let parent = File::open(root).unwrap();
    DOMAINS.into_iter().all(|domain| {
        matches!(
            ProcessLock::at_parent(&parent, nix::unistd::geteuid().as_raw(), domain, false),
            Err(LockError::Busy)
        )
    })
}

// Observe the actual release, tolerating a parallel fork that still holds a
// close-on-exec alias for a moment.
fn released(root: &Path) {
    let parent = File::open(root).unwrap();
    for domain in DOMAINS {
        until(|| {
            match ProcessLock::at_parent(&parent, nix::unistd::geteuid().as_raw(), domain, false) {
                Ok(_) => true,
                Err(LockError::Busy) => false,
                Err(error) => panic!("lease release failed: {error}"),
            }
        });
    }
}

#[tokio::test]
async fn a_ticketed_offer_stops_every_scope_before_the_writer_exec() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path();
    let ticket = ticket(digests());
    publish(path, &ticket);
    let mut engine = engine(path);
    start_all(&mut engine);
    let accepted = offer(path, ticket.transaction_id()).await;
    assert_eq!(engine.accept_raw(accepted), Code::Ok);
    assert_eq!(engine.mode, Mode::Installing);
    assert_eq!(
        fs::read(path.join("native-runtime-owner/state")).unwrap()[44],
        4,
        "Stopping is durable before any scope stops"
    );
    let record = path.join("raw-writer-exec");
    until(|| {
        engine.tick();
        if record.exists() {
            // The exec only ever follows the joined drain.
            assert_eq!(engine.roles, [4; 2]);
            assert_eq!(
                engine.backend_status,
                Some(Status::Closed(Completion::Stopped))
            );
        }
        record.exists()
    });
    let [boot, rootfs] = digests();
    let expected = [
        "--transaction",
        &hex(&ticket.transaction_id()),
        "--version",
        VERSION,
        "--boot-size",
        &IMAGES[0].len().to_string(),
        "--rootfs-size",
        &IMAGES[1].len().to_string(),
        "--boot-sha256",
        &hex(&boot),
        "--rootfs-sha256",
        &hex(&rootfs),
        &hex(&boot),
        &hex(&rootfs),
    ]
    .join("\n");
    assert_eq!(fs::read_to_string(&record).unwrap(), expected);
    // The fixture's exec "failed": nothing resumes and the exclusions stay.
    engine.tick();
    assert_eq!(engine.mode, Mode::Uncertain);
    assert!(busy(path));
    for operation in [
        Operation::EnsureKvm,
        Operation::EnsureHwmon,
        Operation::EnsureBackend,
        Operation::RestartBackend,
        Operation::Pause,
        Operation::Shutdown,
    ] {
        assert_eq!(
            engine.request(1, operation).code,
            Code::Busy,
            "{operation:?}"
        );
    }
    assert_eq!(
        engine.request(1, Operation::BackendRunning).code,
        Code::Unavailable
    );
    assert_eq!(engine.roles, [4; 2]);
}

#[tokio::test]
async fn an_offer_its_ticket_does_not_name_stops_nothing() {
    let missing = ("no ticket", None, [0; 16]);
    let other = ticket(digests());
    let elsewhere = (
        "another transaction",
        Some(ticket(digests())),
        other.transaction_id(),
    );
    let wrong = ticket([[9; 32], digests()[1]]);
    let wrong_id = wrong.transaction_id();
    let digest = ("other image digests", Some(wrong), wrong_id);
    for (name, ticket, transaction) in [missing, elsewhere, digest] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path();
        let transaction = match &ticket {
            Some(ticket) => {
                publish(path, ticket);
                if transaction == ticket.transaction_id() {
                    transaction
                } else {
                    // A transaction the published ticket does not carry.
                    other.transaction_id()
                }
            }
            None => [7; 16],
        };
        let mut engine = engine(path);
        start_all(&mut engine);
        let accepted = offer(path, transaction).await;
        assert_eq!(engine.accept_raw(accepted), Code::Invalid, "{name}");
        engine.tick();
        assert!(running(&engine), "{name}");
        assert!(!path.join("raw-writer-exec").exists(), "{name}");
        released(path);
    }
}

#[tokio::test]
async fn maintenance_or_a_second_offer_cannot_take_over_the_broker() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path();
    let ticket = ticket(digests());
    publish(path, &ticket);
    let mut engine = engine(path);
    start_all(&mut engine);
    // A maintenance lease owns the broker: the offer is refused.
    assert_eq!(engine.request(9, Operation::Pause).code, Code::Ok);
    let accepted = offer(path, ticket.transaction_id()).await;
    assert_eq!(engine.accept_raw(accepted), Code::Busy);
    assert!(engine.raw.is_none());
    assert_eq!(engine.request(9, Operation::Resume).code, Code::Ok);
    start_all(&mut engine);
    released(path);
    // While one raw write drains, a second offer is refused.
    assert_eq!(
        engine.accept_raw(offer(path, ticket.transaction_id()).await),
        Code::Ok
    );
    let second = tempfile::tempdir().unwrap();
    let late = offer(second.path(), ticket.transaction_id()).await;
    assert_eq!(engine.accept_raw(late), Code::Busy);
    until(|| {
        engine.tick();
        path.join("raw-writer-exec").exists()
    });
}

#[test]
fn the_server_takes_a_raw_offer_from_its_fixed_endpoint() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path();
    let ticket = ticket(digests());
    publish(path, &ticket);
    let uid = nix::unistd::geteuid().as_raw();
    serve(path, uid, || {
        let mut control = connect(path);
        for op in [
            Operation::EnsureKvm,
            Operation::EnsureHwmon,
            Operation::EnsureBackend,
        ] {
            assert_eq!(exchange(&mut control, op).code, Code::Ok);
        }
        until(|| exchange(&mut control, Operation::Observe).roles == [2; 2]);
        until(|| exchange(&mut control, Operation::BackendRunning).code == Code::Ok);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let handoff = runtime.block_on(handoff(path, ticket.transaction_id()));
        let directory = File::open(path.join("native-runtime-owner")).unwrap();
        let socket = journal::socket::connect_raw_install(&directory, uid).unwrap();
        RawSender::fixture(socket, uid)
            .unwrap()
            .send(handoff)
            .unwrap();
        // The fixture's idle limit is shorter than this wait under load: leave
        // at a complete reply boundary and come back, as a real observer does.
        drop(control);
        until(|| path.join("raw-writer-exec").exists());
        let mut control = connect(path);
        observed(&mut control, Mode::Uncertain);
        assert!(busy(path));
    });
}
