use super::*;
use std::io::Write;
use tempfile::tempfile;

fn image(bytes: &[u8]) -> File {
    let mut file = tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn contents(file: &File, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    file.read_exact_at(&mut bytes, 0).unwrap();
    bytes
}

#[test]
fn the_image_is_written_from_the_start_and_reads_back_whole() {
    // Larger than one chunk and not a multiple of it.
    let bytes: Vec<u8> = (0..CHUNK * 2 + 4097).map(|i| (i * 7 % 251) as u8).collect();
    let device = image(&vec![0xee; bytes.len() + 8192]);
    write_image(&image(&bytes), &device, bytes.len() as u64, &digest(&bytes)).unwrap();
    assert_eq!(contents(&device, bytes.len()), bytes);
    // The rest of the partition is left as it was.
    let mut tail = vec![0; 8192];
    device.read_exact_at(&mut tail, bytes.len() as u64).unwrap();
    assert!(tail.iter().all(|byte| *byte == 0xee));
}

#[test]
fn a_partition_smaller_than_the_image_is_never_written() {
    let bytes = vec![7; 4096];
    let device = image(&vec![0xee; 4095]);
    assert!(matches!(
        write_image(&image(&bytes), &device, 4096, &digest(&bytes)),
        Err(WriteError::TooSmall)
    ));
    assert_eq!(contents(&device, 4095), vec![0xee; 4095]);
}

#[test]
fn a_root_can_mount_only_once_all_of_it_is_on_the_medium() {
    let bytes: Vec<u8> = (0..CHUNK + 8192).map(|i| (i * 7 % 251) as u8).collect();
    let device = image(&vec![0xee; bytes.len()]);
    let alias = device.try_clone().unwrap();
    let expected = bytes.clone();
    BEFORE_HEADER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let held = contents(&alias, expected.len());
            assert_eq!(held[..ROOT_HEADER], [0; ROOT_HEADER]);
            assert_eq!(held[ROOT_HEADER..], expected[ROOT_HEADER..]);
        }))
    });
    let result = write_root(&image(&bytes), &device, bytes.len() as u64, &digest(&bytes));
    BEFORE_HEADER.with(|hook| *hook.borrow_mut() = None);
    result.unwrap();
    assert_eq!(contents(&device, bytes.len()), bytes);
}

#[test]
fn a_root_cut_short_keeps_a_zero_header() {
    let bytes = vec![7; 8192];
    let device = image(&vec![0xee; 16384]);
    assert!(matches!(
        write_root(&image(&bytes), &device, 16384, &digest(&[7; 16384])),
        Err(WriteError::Io(_))
    ));
    assert_eq!(contents(&device, ROOT_HEADER), [0; ROOT_HEADER]);
}

#[test]
fn a_root_too_small_for_its_image_is_not_touched() {
    let bytes = vec![7; 8192];
    let device = image(&vec![0xee; 8191]);
    assert!(matches!(
        write_root(&image(&bytes), &device, 8192, &digest(&bytes)),
        Err(WriteError::TooSmall)
    ));
    assert_eq!(contents(&device, 8191), [0xee; 8191]);
}

#[test]
fn a_read_back_that_differs_from_the_authenticated_digest_fails() {
    let bytes = vec![7; 4096];
    let device = image(&vec![0; 4096]);
    let mut other = digest(&bytes);
    other[0] ^= 1;
    assert!(matches!(
        write_image(&image(&bytes), &device, 4096, &other),
        Err(WriteError::Mismatch)
    ));
    // A short source is an I/O error, not a partial success.
    let device = image(&vec![0; 8192]);
    assert!(matches!(
        write_image(&image(&bytes), &device, 8192, &digest(&[7; 8192])),
        Err(WriteError::Io(_))
    ));
}

#[test]
fn an_empty_image_reads_back_as_the_empty_digest() {
    let device = image(b"unchanged");
    write_image(&image(b""), &device, 0, &digest(b"")).unwrap();
    assert_eq!(contents(&device, 9), b"unchanged");
}

#[test]
fn the_read_back_comes_from_the_partition_not_from_the_image() {
    let bytes = vec![7; 8192];
    let device = image(&vec![0; 8192]);
    let alias = device.try_clone().unwrap();
    AFTER_SYNC.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || alias.write_all_at(&[8], 4096).unwrap()))
    });
    let result = write_image(&image(&bytes), &device, 8192, &digest(&bytes));
    AFTER_SYNC.with(|hook| *hook.borrow_mut() = None);
    assert!(matches!(result, Err(WriteError::Mismatch)));
}

#[test]
fn missing_advice_syscall_still_writes_and_verifies_the_whole_partition_range() {
    let bytes = vec![0x37; CHUNK + 17];
    let device = image(&vec![0xee; bytes.len() + 32]);
    write_image_with_advice(
        &image(&bytes),
        &device,
        bytes.len() as u64,
        &digest(&bytes),
        0,
        |_, length| {
            assert_eq!(length.get(), bytes.len() as u64);
            Err(rustix::io::Errno::NOSYS)
        },
    )
    .unwrap();
    assert_eq!(contents(&device, bytes.len()), bytes);
    let mut tail = [0; 32];
    device.read_exact_at(&mut tail, bytes.len() as u64).unwrap();
    assert_eq!(tail, [0xee; 32]);
}

#[test]
fn missing_advice_syscall_does_not_skip_readback_or_digest_validation() {
    let bytes = vec![7; CHUNK + 17];
    let device = image(&vec![0; bytes.len()]);
    let result = write_image_with_advice(
        &image(&bytes),
        &device,
        bytes.len() as u64,
        &digest(&bytes),
        0,
        |device, _| {
            // Corrupt the last chunk after sync; the source remains intact.
            device.write_all_at(&[8], CHUNK as u64).unwrap();
            Err(rustix::io::Errno::NOSYS)
        },
    );
    assert!(matches!(result, Err(WriteError::Mismatch)));
}

#[test]
fn the_write_reports_the_eviction_that_ran() {
    let bytes = vec![0x37; 4096];
    for eviction in [Eviction::Advised, Eviction::DropCaches, Eviction::Nothing] {
        let reported = write_image_with_advice(
            &image(&bytes),
            &image(&vec![0; bytes.len()]),
            bytes.len() as u64,
            &digest(&bytes),
            0,
            |_, _| Ok(eviction),
        );
        assert_eq!(reported.unwrap(), eviction);
    }
    let reported = write_image_with_advice(
        &image(&bytes),
        &image(&vec![0; bytes.len()]),
        bytes.len() as u64,
        &digest(&bytes),
        0,
        |_, _| Err(rustix::io::Errno::NOSYS),
    );
    assert_eq!(reported.unwrap(), Eviction::Nothing);
}

#[test]
fn drop_caches_says_when_the_knob_refused() {
    let root = tempfile::tempdir().unwrap();
    let knob = root.path().join("drop_caches");
    assert_eq!(drop_caches(&knob), Eviction::DropCaches);
    assert_eq!(fs::read(&knob).unwrap(), b"1\n");
    assert_eq!(
        drop_caches(&root.path().join("missing/drop_caches")),
        Eviction::Nothing
    );
}

#[test]
fn other_advice_errors_are_not_hidden() {
    for errno in [
        rustix::io::Errno::IO,
        rustix::io::Errno::PERM,
        rustix::io::Errno::INVAL,
    ] {
        let result = write_image_with_advice(
            &image(b"data"),
            &image(b"zero"),
            4,
            &digest(b"data"),
            0,
            |_, _| Err(errno),
        );
        assert!(
            matches!(result, Err(WriteError::Io(error)) if error.raw_os_error() == Some(errno.raw_os_error()))
        );
    }
}

mod sequence {
    use super::*;
    use crate::update::restore_capsule::{
        prepare_capsule,
        ticket::{Binding, BootId},
    };
    use std::io::Cursor;

    fn ticket() -> RestoreTicket {
        let mut encrypted = Vec::new();
        let plaintext = b"synthetic restore archive";
        let secret = prepare_capsule(
            "0.3.0-raw.13",
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
                boot_image_sha256: [2; 32],
                rootfs_image_sha256: [3; 32],
                target_app_version: "2.0.43".into(),
                target: "sg2002-licheervnano-sd".into(),
            },
        )
        .unwrap()
    }

    #[derive(Default)]
    struct Fake {
        calls: Vec<String>,
        fail: Option<&'static str>,
        partitions: Vec<(Partition, File)>,
        log: Vec<String>,
    }
    impl Fake {
        fn step(&mut self, name: &'static str) -> io::Result<()> {
            self.calls.push(name.into());
            if self.fail == Some(name) {
                return Err(io::Error::other("injected"));
            }
            Ok(())
        }
        fn partition(&self, partition: Partition) -> Vec<u8> {
            let file = &self
                .partitions
                .iter()
                .find(|(p, _)| *p == partition)
                .unwrap()
                .1;
            let mut bytes = vec![0; 4096];
            file.read_exact_at(&mut bytes, 0).unwrap();
            bytes
        }
    }
    impl WriterSystem for Fake {
        fn stop_others(&mut self) -> io::Result<()> {
            self.step("stop")
        }
        fn freeze_root(&mut self) -> io::Result<()> {
            self.step("freeze")
        }
        fn release_boot(&mut self) -> io::Result<()> {
            self.step("release")
        }
        fn open_partition(&mut self, partition: Partition) -> io::Result<File> {
            self.step(match partition {
                Partition::Boot => "open-boot",
                Partition::Rootfs => "open-rootfs",
            })?;
            let device = self
                .partitions
                .iter()
                .find(|(p, _)| *p == partition)
                .unwrap()
                .1
                .try_clone()?;
            Ok(device)
        }
        fn publish_ticket(&mut self, _: &RestoreTicket) -> std::result::Result<(), TicketError> {
            self.step("publish").map_err(TicketError::Io)
        }
        fn log(&mut self, line: &str) {
            self.log.push(line.into());
        }
    }

    fn device(fill: u8) -> File {
        let file = tempfile::tempfile().unwrap();
        file.write_all_at(&[fill; 4096], 0).unwrap();
        file
    }

    struct Images {
        files: [File; 2],
        sha256: [[u8; 32]; 2],
    }
    fn images() -> Images {
        let boot = device(0xb0);
        let rootfs = device(0x5f);
        Images {
            files: [boot, rootfs],
            sha256: [
                Sha256::digest([0xb0; 4096]).into(),
                Sha256::digest([0x5f; 4096]).into(),
            ],
        }
    }

    fn run(fake: &mut Fake, images: &Images, ticket: &RestoreTicket) -> Outcome {
        fake.partitions = vec![(Partition::Boot, device(0)), (Partition::Rootfs, device(0))];
        run_writer(
            fake,
            &WritePlan {
                images: [&images.files[0], &images.files[1]],
                sizes: [4096, 4096],
                sha256: images.sha256,
                ticket,
            },
        )
    }

    #[test]
    fn a_complete_write_stops_freezes_and_writes_rootfs_then_boot_then_the_ticket() {
        let (images, ticket) = (images(), ticket());
        let mut fake = Fake::default();
        assert_eq!(run(&mut fake, &images, &ticket), Outcome::Written);
        assert_eq!(
            fake.calls,
            [
                "stop",
                "freeze",
                "release",
                "open-rootfs",
                "open-boot",
                "publish"
            ]
        );
        assert_eq!(fake.partition(Partition::Rootfs), [0x5f; 4096]);
        assert_eq!(fake.partition(Partition::Boot), [0xb0; 4096]);
    }

    #[test]
    fn the_root_stays_unmountable_until_all_of_it_is_written() {
        let (images, ticket) = (images(), ticket());
        let rootfs = device(0xee);
        let medium = rootfs.try_clone().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = seen.clone();
        BEFORE_HEADER.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                record.lock().unwrap().push(contents(&medium, 4096));
            }))
        });
        let mut fake = Fake {
            partitions: vec![(Partition::Boot, device(0)), (Partition::Rootfs, rootfs)],
            ..Fake::default()
        };
        let outcome = run_writer(
            &mut fake,
            &WritePlan {
                images: [&images.files[0], &images.files[1]],
                sizes: [4096, 4096],
                sha256: images.sha256,
                ticket: &ticket,
            },
        );
        BEFORE_HEADER.with(|hook| *hook.borrow_mut() = None);
        assert_eq!(outcome, Outcome::Written);
        assert_eq!(seen.lock().unwrap()[0], [0; 4096]);
        assert_eq!(fake.partition(Partition::Rootfs), [0x5f; 4096]);
    }

    #[test]
    fn a_failure_before_the_first_partition_write_writes_nothing_and_runs_no_later_step() {
        let (images, ticket) = (images(), ticket());
        for (fail, calls) in [
            ("stop", &["stop"][..]),
            ("freeze", &["stop", "freeze"][..]),
            ("release", &["stop", "freeze", "release"][..]),
            (
                "open-rootfs",
                &["stop", "freeze", "release", "open-rootfs"][..],
            ),
            (
                "open-boot",
                &["stop", "freeze", "release", "open-rootfs", "open-boot"][..],
            ),
        ] {
            let mut fake = Fake {
                fail: Some(fail),
                ..Fake::default()
            };
            assert_eq!(
                run(&mut fake, &images, &ticket),
                Outcome::NotStarted,
                "{fail}"
            );
            assert_eq!(fake.calls, calls, "{fail}");
            assert_eq!(fake.partition(Partition::Rootfs), [0; 4096], "{fail}");
            assert_eq!(fake.partition(Partition::Boot), [0; 4096], "{fail}");
            assert!(fake.log.iter().any(|line| line.contains("not started")));
        }
    }

    #[test]
    fn a_partition_that_cannot_take_its_image_leaves_both_as_they_were() {
        let (images, ticket) = (images(), ticket());
        for small in [Partition::Rootfs, Partition::Boot] {
            let partitions = [Partition::Boot, Partition::Rootfs].map(|partition| {
                let file = device(0xee);
                if partition == small {
                    file.set_len(4095).unwrap();
                }
                (partition, file)
            });
            let held = partitions
                .each_ref()
                .map(|(_, file)| file.try_clone().unwrap());
            let mut fake = Fake {
                partitions: partitions.into(),
                ..Fake::default()
            };
            let outcome = run_writer(
                &mut fake,
                &WritePlan {
                    images: [&images.files[0], &images.files[1]],
                    sizes: [4096, 4096],
                    sha256: images.sha256,
                    ticket: &ticket,
                },
            );
            assert_eq!(outcome, Outcome::NotStarted, "{small:?}");
            assert!(!fake.calls.contains(&"publish".to_string()));
            for file in &held {
                assert_eq!(contents(file, 4095), [0xee; 4095], "{small:?}");
            }
            assert!(fake.log.iter().any(|line| line.contains("not started")));
        }
    }

    #[test]
    fn an_image_that_changed_after_verification_is_never_written() {
        for index in 0..2 {
            let (mut images, ticket) = (images(), ticket());
            images.sha256[index][0] ^= 1;
            let mut fake = Fake::default();
            assert_eq!(run(&mut fake, &images, &ticket), Outcome::NotStarted);
            assert_eq!(fake.calls, ["stop", "freeze", "release"]);
            assert_eq!(fake.partition(Partition::Rootfs), [0; 4096]);
            assert_eq!(fake.partition(Partition::Boot), [0; 4096]);
            assert!(fake.log.iter().any(|line| line.contains("not started")));
        }
    }

    #[test]
    fn a_root_that_reads_back_wrong_cannot_boot_and_boot_stays_as_it_was() {
        let (images, ticket) = (images(), ticket());
        let rootfs = device(0xee);
        let medium = rootfs.try_clone().unwrap();
        AFTER_SYNC.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                medium.write_all_at(&[1], 2048).unwrap();
            }))
        });
        let mut fake = Fake {
            partitions: vec![(Partition::Boot, device(0xbb)), (Partition::Rootfs, rootfs)],
            ..Fake::default()
        };
        let outcome = run_writer(
            &mut fake,
            &WritePlan {
                images: [&images.files[0], &images.files[1]],
                sizes: [4096, 4096],
                sha256: images.sha256,
                ticket: &ticket,
            },
        );
        AFTER_SYNC.with(|hook| *hook.borrow_mut() = None);
        assert_eq!(outcome, Outcome::Failed);
        assert_eq!(fake.partition(Partition::Rootfs), [0; 4096]);
        assert_eq!(fake.partition(Partition::Boot), [0xbb; 4096]);
    }

    #[test]
    fn a_boot_that_reads_back_wrong_leaves_a_root_that_cannot_mount() {
        let (images, ticket) = (images(), ticket());
        let boot = device(0xee);
        let medium = boot.try_clone().unwrap();
        let mut syncs = 0;
        AFTER_SYNC.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                syncs += 1;
                if syncs == 2 {
                    medium.write_all_at(&[1], 2048).unwrap();
                }
            }))
        });
        let mut fake = Fake {
            partitions: vec![(Partition::Boot, boot), (Partition::Rootfs, device(0))],
            ..Fake::default()
        };
        let outcome = run_writer(
            &mut fake,
            &WritePlan {
                images: [&images.files[0], &images.files[1]],
                sizes: [4096, 4096],
                sha256: images.sha256,
                ticket: &ticket,
            },
        );
        AFTER_SYNC.with(|hook| *hook.borrow_mut() = None);
        assert_eq!(outcome, Outcome::Failed);
        assert_eq!(fake.partition(Partition::Rootfs), [0; 4096]);
        assert_ne!(fake.partition(Partition::Boot), [0; 4096]);
    }

    #[test]
    fn the_journal_names_the_eviction_behind_each_read_back() {
        let (images, ticket) = (images(), ticket());
        let mut fake = Fake::default();
        assert_eq!(run(&mut fake, &images, &ticket), Outcome::Written);
        for expected in [
            "raw write: Rootfs written and verified after fadvise, writing and verifying Boot",
            "raw write: Boot written and verified after fadvise",
        ] {
            assert!(
                fake.log.iter().any(|line| line == expected),
                "{expected}: {:?}",
                fake.log
            );
        }
    }

    #[test]
    fn a_ticket_that_cannot_be_published_is_manual_recovery_on_a_complete_system() {
        let (images, ticket) = (images(), ticket());
        let mut fake = Fake {
            fail: Some("publish"),
            ..Fake::default()
        };
        assert_eq!(run(&mut fake, &images, &ticket), Outcome::Failed);
        assert_eq!(
            fake.calls,
            [
                "stop",
                "freeze",
                "release",
                "open-rootfs",
                "open-boot",
                "publish"
            ]
        );
        assert_eq!(fake.partition(Partition::Rootfs), [0x5f; 4096]);
        assert_eq!(fake.partition(Partition::Boot), [0xb0; 4096]);
        assert!(
            fake.log
                .iter()
                .any(|line| line.contains("raw write failed"))
        );
    }
}

mod mode {
    use super::*;
    use rustix::fs::{MemfdFlags, fcntl_add_seals, memfd_create};
    use std::io::Write;

    fn arguments() -> WriterArguments {
        WriterArguments::new(
            [7; 16],
            "0.3.0-raw.13",
            [1025, 65537],
            [[1; 32], [0xab; 32]],
        )
        .unwrap()
    }

    #[test]
    fn writer_arguments_round_trip_and_nothing_else_parses() {
        let args = arguments().to_args();
        assert_eq!(args.len(), 12);
        let parsed = parse_writer_arguments(&args).unwrap();
        assert_eq!(parsed.to_args(), args);
        assert_eq!(parsed.transaction, [7; 16]);
        assert_eq!(parsed.sizes, [1025, 65537]);
        assert_eq!(parsed.sha256, [[1; 32], [0xab; 32]]);
        for length in 0..args.len() {
            assert!(
                parse_writer_arguments(&args[..length]).is_none(),
                "{length}"
            );
        }
        let mut extra = args.clone();
        extra.push("x".into());
        assert!(parse_writer_arguments(&extra).is_none());
        for index in (0..12).step_by(2) {
            let mut bad = args.clone();
            bad[index] = "--other".into();
            assert!(parse_writer_arguments(&bad).is_none(), "flag {index}");
        }
        for (index, value) in [
            (1, "00000000000000000000000000000000".to_string()),
            (1, "07".repeat(15)),
            (1, "0G".repeat(16)),
            (1, "0A".repeat(16)),
            (3, "bad version".to_string()),
            (5, "0".to_string()),
            (7, "size".to_string()),
            (9, "ab".repeat(31)),
            (11, "zz".repeat(32)),
        ] {
            let mut bad = args.clone();
            bad[index] = value.clone().into();
            assert!(parse_writer_arguments(&bad).is_none(), "{index}={value}");
        }
    }

    #[test]
    fn only_a_fully_sealed_memory_image_may_run_the_writer() {
        let memfd = File::from(
            memfd_create(
                "nanokvm-raw-writer-test",
                MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
            )
            .unwrap(),
        );
        (&memfd).write_all(b"\x7fELF synthetic").unwrap();
        assert!(require_sealed(&memfd).is_err(), "unsealed");
        fcntl_add_seals(&memfd, SealFlags::WRITE).unwrap();
        assert!(require_sealed(&memfd).is_err(), "write seal only");
        fcntl_add_seals(
            &memfd,
            SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
        )
        .unwrap();
        require_sealed(&memfd).unwrap();
        assert!(
            require_sealed(&tempfile::tempfile().unwrap()).is_err(),
            "regular file"
        );
    }
}
