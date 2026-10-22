use super::*;

#[test]
fn job_frames_round_trip_and_refuse_every_unfixed_field() {
    let cursor = PicoCursor {
        epoch: [7; 16],
        sequence: 41,
    };
    let id = PicoJobId {
        epoch: [7; 16],
        sequence: 42,
        nonce: [9; 16],
    };
    for request in [
        JobRequest::Cursor,
        JobRequest::SubmitStartup {
            cursor,
            nonce: [9; 16],
        },
        JobRequest::Observe(id),
    ] {
        let bytes = encode_request(request);
        assert_eq!(&bytes[..8], b"NKPJQ001");
        assert_eq!(decode_request(&bytes), Some(request));
        // Any change to a fixed byte, padding or bound refuses.
        for index in [0, 8, 9, 10, 15, 56, 63] {
            let mut bad = bytes;
            bad[index] ^= 0x40;
            assert_eq!(decode_request(&bad), None, "{request:?} byte {index}");
        }
    }
    let mut cursor_with_fields = encode_request(JobRequest::Cursor);
    cursor_with_fields[16] = 1;
    assert_eq!(decode_request(&cursor_with_fields), None);
    for (offset, length) in [(16, 16), (40, 16)] {
        let mut zero = encode_request(JobRequest::Observe(id));
        zero[offset..offset + length].fill(0);
        assert_eq!(decode_request(&zero), None, "zero identity at {offset}");
    }
    let mut first = encode_request(JobRequest::Observe(id));
    first[32..40].fill(0);
    assert_eq!(decode_request(&first), None, "sequence zero is no job");
    let mut wrapping = encode_request(JobRequest::SubmitStartup {
        cursor: PicoCursor {
            epoch: [7; 16],
            sequence: u64::MAX,
        },
        nonce: [9; 16],
    });
    assert_eq!(
        decode_request(&wrapping),
        None,
        "the next sequence cannot wrap"
    );
    wrapping[9] = 1;
    assert_eq!(decode_request(&wrapping), None, "no other kind is wired");

    let reply = JobReply {
        code: JobCode::Ok,
        epoch: [7; 16],
        sequence: 42,
        nonce: [9; 16],
        receipt: [3, 8, 2, 1],
    };
    let bytes = encode_reply(reply);
    assert_eq!(&bytes[..8], b"NKPJS001");
    assert_eq!(decode_reply(&bytes), Some(reply));
    for index in [0, 9, 11, 56, 63] {
        let mut bad = bytes;
        bad[index] ^= 0x40;
        assert_eq!(decode_reply(&bad), None, "reply byte {index}");
    }
    for code in [0, 9, 255] {
        let mut bad = bytes;
        bad[8] = code;
        assert_eq!(decode_reply(&bad), None, "reply code {code}");
    }
}

#[cfg(feature = "sandbox-test-fixture")]
mod endpoint {
    use super::*;
    use crate::native_owner::broker::picoclaw_mutation::tests as fixture;
    use crate::update::{
        operation_lock::ProcessLock, picoclaw_config::jobs, state_writers::StateWriters,
    };
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::Path,
        process::{Command, Stdio},
    };

    fn command(root: &Path, case: &str) -> Command {
        let mut command = Command::new("/usr/bin/unshare");
        command
            .args(["--user", "--map-root-user", "--mount", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_owner::broker::ipc::picoclaw_job::tests::endpoint::job_transport_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_PICO_JOB_ROOT", root)
            .env("NANOKVM_PICO_JOB_CASE", case)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    #[test]
    fn startup_jobs_run_through_the_real_job_endpoint_and_return_the_same_broker() {
        for case in ["settle-noop-absent", "settle-change-absent"] {
            let root = fixture::root();
            let output = command(root.path(), case).output().unwrap();
            assert!(output.status.success(), "{case}: {output:?}");
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("pico-job-transport-checked")
            );
        }
    }

    fn observe_until_settled(
        channel: &mut JobChannel,
        mut reply: JobReply,
        id: PicoJobId,
    ) -> JobReply {
        let wait = Duration::from_secs(5);
        fixture::until(|| {
            if reply.code != JobCode::Pending {
                return true;
            }
            reply = channel.exchange(JobRequest::Observe(id), wait).unwrap();
            false
        });
        reply
    }

    // Runs against the real daemon loop over its real endpoint.
    fn client_checks(case: &str, pair: &fixture::SettlePair) {
        let change = case == "settle-change-absent";
        let reply = run_startup_job(Duration::from_secs(30)).unwrap();
        assert_eq!(reply.code, JobCode::Ok, "{reply:?}");
        assert_eq!(reply.sequence, 1);
        assert_eq!(
            reply.receipt,
            if change { [3, 8, 1, 2] } else { [3, 8, 2, 1] },
            "Startup Completed with Changed/NotRequested or Noop/Unchanged"
        );
        if change {
            fixture::assert_pair_desired(pair, fixture::INTERNAL);
        } else {
            fixture::assert_pair_unchanged(pair);
        }
        assert_eq!(fixture::members_present(), [false; 3]);
        let wait = Duration::from_secs(5);
        let mut channel = JobChannel::connect().unwrap();
        // The SAME broker is back: the idle store reports its next cursor.
        let cursor = channel.exchange(JobRequest::Cursor, wait).unwrap();
        assert_eq!(
            (cursor.code, cursor.epoch, cursor.sequence),
            (JobCode::Ok, reply.epoch, 1)
        );
        let id = PicoJobId {
            epoch: reply.epoch,
            sequence: reply.sequence,
            nonce: reply.nonce,
        };
        assert_eq!(
            channel.exchange(JobRequest::Observe(id), wait).unwrap(),
            reply
        );
        // An identical resubmission observes the SAME receipt, never a new job.
        let first = PicoCursor {
            epoch: reply.epoch,
            sequence: 0,
        };
        let again = channel
            .exchange(
                JobRequest::SubmitStartup {
                    cursor: first,
                    nonce: id.nonce,
                },
                wait,
            )
            .unwrap();
        assert_eq!(observe_until_settled(&mut channel, again, id), reply);
        // A stale cursor with a new nonce is expired; nothing is accepted.
        let stale = PicoJobId {
            nonce: [0x5c; 16],
            ..id
        };
        let expired = channel
            .exchange(
                JobRequest::SubmitStartup {
                    cursor: first,
                    nonce: stale.nonce,
                },
                wait,
            )
            .unwrap();
        assert_eq!(
            observe_until_settled(&mut channel, expired, stale).code,
            JobCode::Expired
        );
        let unknown = PicoJobId { sequence: 7, ..id };
        assert_eq!(
            channel
                .exchange(JobRequest::Observe(unknown), wait)
                .unwrap()
                .code,
            JobCode::Invalid
        );
        assert_eq!(
            channel.exchange(JobRequest::Cursor, wait).unwrap().sequence,
            1
        );
        // A malformed datagram is answered Invalid and closes its connection.
        let raw = JobChannel::connect().unwrap();
        rustix::net::send(&raw.socket, &[0; PACKET], SendFlags::NOSIGNAL).unwrap();
        let mut bytes = [0; PACKET];
        fixture::until(|| {
            matches!(
                rustix::net::recv(&raw.socket, &mut bytes, RecvFlags::DONTWAIT),
                Ok((_, PACKET))
            )
        });
        assert_eq!(decode_reply(&bytes).unwrap().code, JobCode::Invalid);
        fixture::until(|| {
            matches!(
                rustix::net::recv(&raw.socket, &mut bytes, RecvFlags::DONTWAIT),
                Ok((_, 0))
            )
        });
        // No job, admission or fence is left behind.
        drop(ProcessLock::acquire().unwrap());
        drop(StateWriters::default().configuration().unwrap());
    }

    #[test]
    fn job_transport_child() {
        let Some(root) = std::env::var_os("NANOKVM_PICO_JOB_ROOT") else {
            return;
        };
        let case = std::env::var("NANOKVM_PICO_JOB_CASE").unwrap();
        let root = Path::new(&root);
        nix::mount::mount(
            Some("/proc"),
            root.join("proc").as_path(),
            None::<&str>,
            nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
            None::<&str>,
        )
        .unwrap();
        nix::unistd::chroot(root).unwrap();
        std::env::set_current_dir("/").unwrap();
        jobs::prepare_factory_fixture();
        let pair = fixture::settle_home(&case);
        fs::write("/producer-image", b"synthetic private producer image data").unwrap();
        fs::set_permissions("/producer-image", fs::Permissions::from_mode(0o600)).unwrap();
        let mut server = Server::new(Broker::acquire().unwrap(), 0).unwrap();
        server.engine.fixture_pico_image = Some("/producer-image".into());
        let (stop, cancel) = std::sync::mpsc::channel::<()>();
        server.cancel = Some(cancel);
        let client = std::thread::spawn(move || {
            let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                client_checks(&case, &pair)
            }));
            drop(stop);
            checked
        });
        assert_eq!(server.run().unwrap_err().kind(), io::ErrorKind::Interrupted);
        if let Err(panic) = client.join().unwrap() {
            std::panic::resume_unwind(panic);
        }
        println!("pico-job-transport-checked");
    }
}
