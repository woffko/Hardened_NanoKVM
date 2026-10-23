use super::*;
use crate::update::{
    operation::{Kind, UpdateCoordinator},
    operation_lock::{LockError, ProcessLock},
    state_writers::StateWriters,
};
use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
use std::{io::Write, os::fd::AsRawFd, sync::Arc, time::Duration};

const ID: [u8; 16] = [9; 16];
const BOOT: &[u8] = b"synthetic boot image";
const ROOTFS: &[u8] = b"synthetic root filesystem image, a bit longer";
const DOMAINS: [Domain; 3] = [
    Domain::Update,
    Domain::WriterAdmission,
    Domain::WriterActivity,
];

// An anonymous file reopened read-only: the shape of an authenticated snapshot.
fn snapshot(bytes: &[u8]) -> File {
    let mut writable = tempfile::tempfile().unwrap();
    writable.write_all(bytes).unwrap();
    File::open(format!("/proc/self/fd/{}", writable.as_raw_fd())).unwrap()
}

fn images() -> RawImages {
    RawImages {
        files: [snapshot(BOOT), snapshot(ROOTFS)],
        sizes: [BOOT.len() as u64, ROOTFS.len() as u64],
        sha256: [[1; 32], [2; 32]],
    }
}

// Every handoff gets its own lock directories: a parallel test's fork can
// briefly retain a closed lease, so reusing them could report a false Busy.
struct Fixture {
    _root: tempfile::TempDir,
    parent: File,
    coordinator: Arc<UpdateCoordinator>,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let parent = File::open(root.path()).unwrap();
    let coordinator = Arc::new(UpdateCoordinator::with_test_parent(
        parent.try_clone().unwrap(),
    ));
    Fixture {
        _root: root,
        parent,
        coordinator,
    }
}

async fn writers(fixture: &Fixture) -> crate::update::state_writers::WriterDrain {
    StateWriters::for_test_parent(fixture.parent.try_clone().unwrap())
        .drain(Duration::from_secs(1))
        .await
        .unwrap()
}

async fn handoff_with(fixture: &Fixture, transaction: [u8; 16], images: RawImages) -> RawHandoff {
    let owner = fixture.coordinator.acquire(Kind::SystemInstall).unwrap();
    owner
        .prepare_raw_handoff(transaction, images, writers(fixture).await)
        .unwrap()
}

async fn handoff(fixture: &Fixture, images: RawImages) -> RawHandoff {
    handoff_with(fixture, ID, images).await
}

fn pair() -> (OwnedFd, OwnedFd) {
    let (sender, receiver) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let pid = std::process::id();
    let uid = nix::unistd::geteuid().as_raw();
    prepare(&sender, pid, uid).unwrap();
    prepare(&receiver, pid, uid).unwrap();
    (sender, receiver)
}

fn incoming(fixture: &Fixture, receiver: OwnedFd) -> RawIncoming {
    let uid = nix::unistd::geteuid().as_raw();
    RawIncoming::fixture(receiver, fixture.parent.try_clone().unwrap(), uid).unwrap()
}

fn exchange(fixture: &Fixture, handoff: RawHandoff) -> Result<RawAccepted, Error> {
    let (sender, receiver) = pair();
    send(&sender, &handoff)?;
    drop(handoff);
    incoming(fixture, receiver)
        .poll()
        .map(|accepted| accepted.unwrap())
}

fn busy(parent: &File) -> bool {
    DOMAINS.into_iter().all(|domain| {
        matches!(
            ProcessLock::at_parent(parent, nix::unistd::geteuid().as_raw(), domain, false),
            Err(LockError::Busy)
        )
    })
}

// As in the app lease tests: observe the actual release, tolerating a
// parallel fork that still holds a close-on-exec alias for a moment.
fn released(parent: &File) {
    for domain in DOMAINS {
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
}

#[tokio::test]
async fn the_broker_receives_both_images_their_digests_and_the_exclusions() {
    let fixture = fixture();
    let accepted = exchange(&fixture, handoff(&fixture, images()).await).unwrap();
    assert_eq!(accepted.transaction(), ID);
    assert_eq!(accepted.sizes(), [BOOT.len() as u64, ROOTFS.len() as u64]);
    assert_eq!(accepted.sha256(), [[1; 32], [2; 32]]);
    // The sender and its owner are gone; the broker's offer keeps all three.
    assert!(busy(&fixture.parent));
    let (exclusions, [boot, rootfs]) = accepted.into_parts();
    for image in [&boot, &rootfs] {
        assert!(fcntl_getfd(image).unwrap().contains(FdFlags::CLOEXEC));
    }
    let mut bytes = vec![0; ROOTFS.len()];
    std::os::unix::fs::FileExt::read_exact_at(&rootfs, &mut bytes, 0).unwrap();
    assert_eq!(bytes, ROOTFS);
    assert_eq!(boot.metadata().unwrap().len(), BOOT.len() as u64);
    // Handing the images on keeps the exclusions until they are dropped.
    drop((boot, rootfs));
    assert!(busy(&fixture.parent));
    drop(exclusions);
    released(&fixture.parent);
}

#[tokio::test]
async fn only_system_installs_may_hand_over_a_raw_write() {
    let fixture = fixture();
    let owner = fixture
        .coordinator
        .acquire(Kind::ApplicationOffline)
        .unwrap();
    assert!(
        owner
            .prepare_raw_handoff(ID, images(), writers(&fixture).await)
            .is_err()
    );
}

#[tokio::test]
async fn a_linked_writable_or_mis_sized_image_is_refused() {
    // A named file.
    let dir = tempfile::tempdir().unwrap();
    let named = dir.path().join("boot.img");
    std::fs::write(&named, BOOT).unwrap();
    let mut linked = images();
    linked.files[0] = File::open(&named).unwrap();
    // An anonymous file still open for writing.
    let mut writable = images();
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(BOOT).unwrap();
    writable.files[0] = file;
    // A size that differs from the snapshot.
    let mut sized = images();
    sized.sizes[1] += 1;
    for case in [linked, writable, sized] {
        let fixture = fixture();
        assert!(matches!(
            exchange(&fixture, handoff(&fixture, case).await),
            Err(Error::Admission)
        ));
    }
}

#[tokio::test]
async fn invalid_records_are_refused_before_sending() {
    let mut zero_digest = images();
    zero_digest.sha256[1] = [0; 32];
    let mut empty = images();
    empty.sizes[0] = 0;
    let mut oversized = images();
    oversized.sizes = [MAX_IMAGE_BYTES, 1];
    for (transaction, case) in [
        (ID, zero_digest),
        (ID, empty),
        (ID, oversized),
        ([0; 16], images()),
    ] {
        let fixture = fixture();
        let handoff = handoff_with(&fixture, transaction, case).await;
        let (sender, _receiver) = pair();
        assert!(matches!(send(&sender, &handoff), Err(Error::Record)));
    }
}

#[test]
fn a_forged_offer_is_refused_and_the_endpoint_consumed() {
    // The app magic, no descriptors.
    let fixture = fixture();
    let (sender, receiver) = pair();
    let mut bytes = [0; BYTES];
    bytes[..8].copy_from_slice(b"NKAPPL01");
    bytes[8..24].copy_from_slice(&ID);
    rustix::net::send(&sender, &bytes, SendFlags::NOSIGNAL).unwrap();
    let mut offer = incoming(&fixture, receiver);
    assert!(matches!(offer.poll(), Err(Error::Record)));
    assert!(
        matches!(offer.poll(), Err(Error::Record)),
        "one packet only"
    );
}

#[tokio::test]
async fn an_offer_without_the_images_is_refused() {
    // A valid record with the three leases but without the images.
    let fixture = fixture();
    let handoff = handoff(&fixture, images()).await;
    let (bytes, wire) = encode(&handoff).unwrap();
    let (sender, receiver) = pair();
    transmit(&sender, &bytes, &wire.map(File::as_fd)[..3]).unwrap();
    drop(handoff);
    assert!(matches!(
        incoming(&fixture, receiver).poll(),
        Err(Error::Record)
    ));
}

#[tokio::test]
async fn a_complete_offer_with_one_field_altered_is_refused() {
    type Alter = fn(&mut [u8; BYTES]);
    let record: [(&str, Alter); 5] = [
        ("magic", |bytes| bytes[..8].copy_from_slice(b"NKAPPL01")),
        ("transaction", |bytes| bytes[8..24].fill(0)),
        ("boot size", |bytes| bytes[24..32].fill(0)),
        ("total size", |bytes| {
            bytes[32..40].copy_from_slice(&MAX_IMAGE_BYTES.to_be_bytes())
        }),
        ("rootfs digest", |bytes| bytes[72..104].fill(0)),
    ];
    let admission: [(&str, Alter); 2] = [
        ("rootfs identity", |bytes| {
            bytes[IDENTITIES + 4 * 16 + 15] ^= 1
        }),
        ("update identity", |bytes| bytes[IDENTITIES + 15] ^= 1),
    ];
    for (cases, malformed) in [(&record[..], true), (&admission[..], false)] {
        for (name, alter) in cases {
            let fixture = fixture();
            let handoff = handoff(&fixture, images()).await;
            let (mut bytes, wire) = encode(&handoff).unwrap();
            alter(&mut bytes);
            let (sender, receiver) = pair();
            transmit(&sender, &bytes, &wire.map(File::as_fd)).unwrap();
            drop(handoff);
            let result = incoming(&fixture, receiver).poll();
            let refused = if malformed {
                matches!(result, Err(Error::Record))
            } else {
                matches!(result, Err(Error::Admission))
            };
            assert!(refused, "{name}");
        }
    }
}

#[tokio::test]
async fn swapped_exclusions_are_refused() {
    let fixture = fixture();
    let mut handoff = handoff(&fixture, images()).await;
    let files = &mut handoff.files;
    std::mem::swap(&mut files.admission, &mut files.activity);
    assert!(matches!(exchange(&fixture, handoff), Err(Error::Admission)));
}
