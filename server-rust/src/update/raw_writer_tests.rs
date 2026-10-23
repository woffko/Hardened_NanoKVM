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
    fn a_failure_after_the_first_write_is_manual_recovery_and_never_publishes_the_ticket() {
        let (mut images, ticket) = (images(), ticket());
        // ROOTFS reads back wrong: BOOT is never opened, no ticket.
        images.sha256[1][0] ^= 1;
        let mut fake = Fake::default();
        assert_eq!(run(&mut fake, &images, &ticket), Outcome::Failed);
        assert_eq!(fake.calls, ["stop", "freeze", "release", "open-rootfs"]);
        assert_eq!(fake.partition(Partition::Boot), [0; 4096]);
        images.sha256[1][0] ^= 1;
        for (fail, calls) in [
            (
                "open-boot",
                &["stop", "freeze", "release", "open-rootfs", "open-boot"][..],
            ),
            (
                "publish",
                &[
                    "stop",
                    "freeze",
                    "release",
                    "open-rootfs",
                    "open-boot",
                    "publish",
                ][..],
            ),
        ] {
            let mut fake = Fake {
                fail: Some(fail),
                ..Fake::default()
            };
            assert_eq!(run(&mut fake, &images, &ticket), Outcome::Failed, "{fail}");
            assert_eq!(fake.calls, calls, "{fail}");
            assert!(
                fake.log
                    .iter()
                    .any(|line| line.contains("raw write failed"))
            );
        }
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
