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
        JobRequest::Submit {
            cursor,
            nonce: [9; 16],
            kind: JobKind::Startup,
        },
        JobRequest::Submit {
            cursor,
            nonce: [9; 16],
            kind: JobKind::Remove,
        },
        JobRequest::Submit {
            cursor,
            nonce: [9; 16],
            kind: JobKind::Onboard,
        },
        JobRequest::Submit {
            cursor,
            nonce: [9; 16],
            kind: JobKind::Profile { kvm: false },
        },
        JobRequest::Submit {
            cursor,
            nonce: [9; 16],
            kind: JobKind::Profile { kvm: true },
        },
        JobRequest::Observe(id),
    ] {
        let bytes = encode_request(&request);
        assert_eq!(bytes.len(), PACKET);
        assert_eq!(&bytes[..8], b"NKPJQ001");
        assert_eq!(decode_request(&bytes), Some(request.clone()));
        // Any change to a fixed byte, padding or bound refuses.
        for index in [0, 8, 9, 10, 15, 56, 63] {
            let mut bad = bytes.to_vec();
            bad[index] ^= 0x40;
            assert_eq!(decode_request(&bad), None, "{request:?} byte {index}");
        }
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(decode_request(&longer), None, "{request:?} trailing byte");
        assert_eq!(decode_request(&bytes[..PACKET - 1]), None);
    }
    let mut cursor_with_fields = encode_request(&JobRequest::Cursor).to_vec();
    cursor_with_fields[16] = 1;
    assert_eq!(decode_request(&cursor_with_fields), None);
    for (offset, length) in [(16, 16), (40, 16)] {
        let mut zero = encode_request(&JobRequest::Observe(id)).to_vec();
        zero[offset..offset + length].fill(0);
        assert_eq!(decode_request(&zero), None, "zero identity at {offset}");
    }
    let mut first = encode_request(&JobRequest::Observe(id)).to_vec();
    first[32..40].fill(0);
    assert_eq!(decode_request(&first), None, "sequence zero is no job");
    let mut wrapping = encode_request(&JobRequest::Submit {
        cursor: PicoCursor {
            epoch: [7; 16],
            sequence: u64::MAX,
        },
        nonce: [9; 16],
        kind: JobKind::Startup,
    })
    .to_vec();
    assert_eq!(
        decode_request(&wrapping),
        None,
        "the next sequence cannot wrap"
    );
    wrapping[9] = 1;
    assert_eq!(decode_request(&wrapping), None, "no other kind is wired");
    // An install carries exactly one nonzero SHA-512 after the header.
    let install = JobRequest::Submit {
        cursor,
        nonce: [9; 16],
        kind: JobKind::Install { digest: [0x42; 64] },
    };
    let bytes = encode_request(&install);
    assert_eq!((bytes.len(), bytes[9]), (PACKET + 64, 5));
    assert_eq!(decode_request(&bytes), Some(install.clone()));
    assert_eq!(decode_request(&bytes[..PACKET + 63]), None);
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert_eq!(decode_request(&longer), None);
    let mut zero = bytes.to_vec();
    zero[PACKET..].fill(0);
    assert_eq!(decode_request(&zero), None, "a zero digest names no file");
    let mut padded = bytes.to_vec();
    padded[56] = 1;
    assert_eq!(decode_request(&padded), None);
    assert_ne!(
        JobKind::Install { digest: [0x42; 64] }.digest(),
        JobKind::Install { digest: [0x43; 64] }.digest()
    );
    // The profile flag is one typed byte, never another value.
    let mut profile = encode_request(&JobRequest::Submit {
        cursor,
        nonce: [9; 16],
        kind: JobKind::Profile { kvm: true },
    })
    .to_vec();
    assert_eq!((profile[9], profile[56]), (4, 1));
    profile[56] = 2;
    assert_eq!(decode_request(&profile), None);
    assert_ne!(
        JobKind::Profile { kvm: true }.digest(),
        JobKind::Profile { kvm: false }.digest(),
        "the submission digest tells the two profiles apart"
    );

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

fn model(model: &str, api_base: &str, api_key: &str) -> JobKind {
    JobKind::Model {
        model: Zeroizing::new(model.into()),
        api_base: Zeroizing::new(api_base.into()),
        api_key: Zeroizing::new(api_key.into()),
    }
}

#[test]
fn a_model_submission_carries_exactly_its_bounded_fields_and_never_prints_them() {
    let cursor = PicoCursor {
        epoch: [7; 16],
        sequence: 41,
    };
    let kind = model("vendor/model", "https://x.invalid", "synthetic-key");
    let request = JobRequest::Submit {
        cursor,
        nonce: [9; 16],
        kind: kind.clone(),
    };
    let bytes = encode_request(&request);
    assert_eq!(bytes.len(), PACKET + 12 + 17 + 13);
    assert_eq!(bytes[9], 2, "the store's Model kind");
    assert_eq!(decode_request(&bytes), Some(request.clone()));
    // Debug output never carries a field.
    let shown = format!("{request:?}");
    assert!(!shown.contains("synthetic-key") && !shown.contains("vendor/model"));
    // The lengths must account for the whole datagram exactly.
    let mut longer = bytes.to_vec();
    longer.push(b'x');
    assert_eq!(decode_request(&longer), None);
    assert_eq!(decode_request(&bytes[..bytes.len() - 1]), None);
    let mut length = bytes.to_vec();
    length[56] += 1;
    assert_eq!(decode_request(&length), None);
    let mut padded = bytes.to_vec();
    padded[62] = 1;
    assert_eq!(decode_request(&padded), None);
    let mut text = bytes.to_vec();
    text[PACKET] = 0xff;
    assert_eq!(decode_request(&text), None, "fields are UTF-8");
    // Fields must pass the model request check.
    for (model_id, api_base, api_key) in [
        (" vendor/model", "https://x.invalid", "k"),
        ("vendor/model", "https://x.invalid", "k\n"),
        ("vendor/", "https://x.invalid", "k"),
        ("vendor/model", "", "k"),
    ] {
        let bytes = encode_request(&JobRequest::Submit {
            cursor,
            nonce: [9; 16],
            kind: model(model_id, api_base, api_key),
        });
        assert_eq!(decode_request(&bytes), None, "{model_id:?}");
    }
    let oversized = "k".repeat(picoclaw_model::MAX_API_KEY_BYTES + 1);
    let bytes = encode_request(&JobRequest::Submit {
        cursor,
        nonce: [9; 16],
        kind: model("vendor/model", "https://x.invalid", &oversized),
    });
    assert_eq!(
        decode_request(&bytes),
        None,
        "an oversized key never decodes"
    );
    // The in-memory digest tells requests with one identity apart.
    assert_ne!(kind.digest(), JobKind::Startup.digest());
    assert_ne!(
        kind.digest(),
        model("vendor/model", "https://x.invalid", "other-key").digest()
    );
    assert_eq!(kind.digest(), kind.clone().digest());
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
    fn configuration_jobs_run_through_the_real_job_endpoint_and_return_the_broker() {
        for case in [
            "settle-noop-absent",
            "settle-change-absent",
            "settle-model-change-absent",
            "settle-remove-absent",
            "settle-profile-change-absent",
            "settle-install-absent",
        ] {
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
            reply = channel.exchange(&JobRequest::Observe(id), wait).unwrap();
            false
        });
        reply
    }

    // Runs against the real daemon loop over its real endpoint.
    fn client_checks(case: &str, pair: &fixture::SettlePair) {
        let kind = if case.starts_with("settle-model-") {
            fixture::model_kind()
        } else if case.starts_with("settle-remove-") {
            JobKind::Remove
        } else if case.starts_with("settle-profile-") {
            JobKind::Profile { kvm: true }
        } else if case.starts_with("settle-install-") {
            JobKind::Install {
                digest: fixture::staged_digest(),
            }
        } else {
            JobKind::Startup
        };
        let change = case != "settle-noop-absent";
        let reply = match &kind {
            JobKind::Startup => run_startup_job(Duration::from_secs(30)).unwrap(),
            // The mutation fixtures drive onboarding with its one-shot probe.
            JobKind::Onboard => unreachable!("onboarding is covered by the mutation fixtures"),
            JobKind::Remove => run_remove_job(Duration::from_secs(30)).unwrap(),
            JobKind::Profile { kvm } => run_profile_job(*kvm, Duration::from_secs(30)).unwrap(),
            JobKind::Install { digest } => {
                run_install_job(*digest, Duration::from_secs(30)).unwrap()
            }
            JobKind::Model {
                model,
                api_base,
                api_key,
            } => run_model_job(
                model.clone(),
                api_base.clone(),
                api_key.clone(),
                Duration::from_secs(30),
            )
            .unwrap(),
        };
        assert_eq!(reply.code, JobCode::Ok, "{reply:?}");
        assert_eq!(reply.sequence, 1);
        if kind == JobKind::Remove {
            assert_eq!(reply.receipt, [6, 8, 1, 5], "Completed Changed/Removed");
            assert_eq!(fixture::managed_present(), [false; 4]);
            fixture::assert_workspace_kept();
        } else if let JobKind::Profile { .. } = kind {
            assert_eq!(
                reply.receipt,
                [4, 8, 1, 2],
                "Completed Changed/NotRequested"
            );
            fixture::assert_profile_installed();
            fixture::assert_pair_unchanged(pair);
        } else if let JobKind::Install { .. } = kind {
            assert_eq!(
                reply.receipt,
                [5, 8, 1, 2],
                "Completed Changed/NotRequested"
            );
            assert!(fixture::installed_binary().is_some());
            fixture::assert_pair_unchanged(pair);
        } else {
            assert_eq!(
                reply.receipt,
                [
                    kind.code(),
                    8,
                    if change { 1 } else { 2 },
                    if change { 2 } else { 1 }
                ],
                "Completed with Changed/NotRequested or Noop/Unchanged"
            );
            if change {
                fixture::assert_pair_desired(pair, fixture::INTERNAL);
            } else {
                fixture::assert_pair_unchanged(pair);
            }
        }
        assert_eq!(fixture::members_present(), [false; 3]);
        let wait = Duration::from_secs(5);
        let mut channel = JobChannel::connect().unwrap();
        // The SAME broker is back: the idle store reports its next cursor.
        let cursor = channel.exchange(&JobRequest::Cursor, wait).unwrap();
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
            channel.exchange(&JobRequest::Observe(id), wait).unwrap(),
            reply
        );
        // An identical resubmission observes the SAME receipt, never a new job.
        let first = PicoCursor {
            epoch: reply.epoch,
            sequence: 0,
        };
        let again = channel
            .exchange(
                &JobRequest::Submit {
                    cursor: first,
                    nonce: id.nonce,
                    kind: kind.clone(),
                },
                wait,
            )
            .unwrap();
        assert_eq!(observe_until_settled(&mut channel, again, id), reply);
        // The same identity with a different request is refused.
        let other = if kind == JobKind::Startup {
            fixture::model_kind()
        } else {
            JobKind::Startup
        };
        let refused = channel
            .exchange(
                &JobRequest::Submit {
                    cursor: first,
                    nonce: id.nonce,
                    kind: other,
                },
                wait,
            )
            .unwrap();
        // Acceptance refuses it: nothing new is accepted or changed.
        assert_eq!(
            observe_until_settled(&mut channel, refused, id).code,
            JobCode::Rejected
        );
        assert_eq!(fixture::members_present(), [false; 3]);
        // A stale cursor with a new nonce is expired; nothing is accepted.
        let stale = PicoJobId {
            nonce: [0x5c; 16],
            ..id
        };
        let expired = channel
            .exchange(
                &JobRequest::Submit {
                    cursor: first,
                    nonce: stale.nonce,
                    kind: kind.clone(),
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
                .exchange(&JobRequest::Observe(unknown), wait)
                .unwrap()
                .code,
            JobCode::Invalid
        );
        assert_eq!(
            channel
                .exchange(&JobRequest::Cursor, wait)
                .unwrap()
                .sequence,
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
