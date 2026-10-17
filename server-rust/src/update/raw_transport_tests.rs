use super::*;
use std::{fs, io::Write, os::fd::AsRawFd};
use tempfile::tempdir;

fn context() -> TransferContext {
    TransferContext::new([42; 16], "0.3.0-raw.fixture", [1025, 65537]).unwrap()
}

fn image(bytes: &[u8]) -> File {
    let mut writable = tempfile::tempfile().unwrap();
    writable.write_all(bytes).unwrap();
    let readonly = File::open(format!("/proc/self/fd/{}", writable.as_raw_fd())).unwrap();
    drop(writable);
    readonly
}

fn images() -> [File; 2] {
    [image(&[0x35; 1025]), image(&[0x77; 65537])]
}

fn record(expected: &TransferContext, files: &[File; 2]) -> [u8; RECORD_BYTES] {
    let mut record = [0; RECORD_BYTES];
    record[..CONTEXT_BYTES].copy_from_slice(&expected.encode());
    for (out, file) in record[CONTEXT_BYTES..]
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .zip(files)
    {
        let metadata = file.metadata().unwrap();
        out[..8].copy_from_slice(&metadata.dev().to_be_bytes());
        out[8..].copy_from_slice(&metadata.ino().to_be_bytes());
    }
    record
}

fn raw_send(socket: &OwnedFd, bytes: &[u8], files: &[File]) {
    let descriptors: Vec<_> = files.iter().map(AsFd::as_fd).collect();
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(32))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !descriptors.is_empty() {
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
    }
    assert_eq!(
        sendmsg(
            socket,
            &[IoSlice::new(bytes)],
            &mut ancillary,
            SendFlags::NOSIGNAL
        )
        .unwrap(),
        bytes.len()
    );
}

#[test]
fn exact_two_readonly_images_survive_sender_close_and_have_independent_pread_cursors() {
    let context = context();
    let (sender, receiver) = channel().unwrap();
    let files = images();
    let mut offset_alias = files[0].try_clone().unwrap();
    sender.send(&context, files).unwrap();
    offset_alias.seek(SeekFrom::End(0)).unwrap();
    let received = receiver.receive(&context).unwrap();
    for (mut source, (size, value)) in received.into_iter().zip([(1025, 0x35), (65537, 0x77)]) {
        assert!(
            fcntl_getfd(&source.file)
                .unwrap()
                .contains(FdFlags::CLOEXEC)
        );
        assert_eq!(
            fcntl_getfl(&source.file).unwrap() & OFlags::ACCMODE,
            OFlags::RDONLY
        );
        assert_eq!(source.file.metadata().unwrap().nlink(), 0);
        assert!(
            source
                .file
                .try_clone()
                .unwrap()
                .write_all(b"tamper")
                .is_err()
        );
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, vec![value; size]);
        source.rewind().unwrap();
        assert_eq!(source.read(&mut [0; 1]).unwrap(), 1);
        assert!(source.seek(SeekFrom::End(1)).is_err());
        assert!(source.seek(SeekFrom::Start(u64::MAX)).is_err());
        assert!(source.seek(SeekFrom::Current(i64::MIN)).is_err());
    }
}

#[test]
fn context_rejects_unbounded_empty_and_invalid_transaction_fields() {
    for (id, version, sizes) in [
        ([0; 16], "valid", [1, 1]),
        ([1; 16], "", [1, 1]),
        ([1; 16], "bad/../version", [1, 1]),
        ([1; 16], "bad\nversion", [1, 1]),
        ([1; 16], "nonascii-ü", [1, 1]),
        ([1; 16], "valid", [0, 1]),
        ([1; 16], "valid", [MAX_IMAGE_BYTES, 1]),
        ([1; 16], "valid", [u64::MAX, 1]),
    ] {
        assert!(TransferContext::new(id, version, sizes).is_err());
    }
    assert!(TransferContext::new([1; 16], &"a".repeat(65), [1, 1]).is_err());
    assert!(TransferContext::new([1; 16], &"a".repeat(64), [1, 1]).is_ok());
}

#[test]
fn fixed_record_rejects_wrong_size_magic_context_and_inode_order() {
    for case in 0..8 {
        let files = images();
        let expected = context();
        let (sender, receiver) = channel().unwrap();
        let mut bytes = record(&expected, &files).to_vec();
        match case {
            0 => {
                bytes.pop();
            }
            1 => bytes.push(0),
            2 => bytes[0] ^= 1,
            3 => bytes[8] ^= 1,
            4 => bytes[25] ^= 1,
            5 => bytes[25 + VERSION_BYTES] ^= 1,
            6 => bytes[CONTEXT_BYTES] ^= 1,
            7 => bytes[CONTEXT_BYTES..].rotate_left(16),
            _ => unreachable!(),
        }
        raw_send(&sender.socket, &bytes, &files);
        drop(sender);
        assert!(receiver.receive(&expected).is_err());
    }
}

#[test]
fn exact_descriptor_count_and_no_control_truncation_are_required() {
    for count in [0, 1, 3, 32] {
        let files = images();
        let expected = context();
        let bytes = record(&expected, &files);
        let (sender, receiver) = channel().unwrap();
        let descriptors: Vec<_> = (0..count)
            .map(|index| files[index % 2].try_clone().unwrap())
            .collect();
        raw_send(&sender.socket, &bytes, &descriptors);
        drop(sender);
        assert!(receiver.receive(&expected).is_err());
    }
}

#[test]
fn sender_and_receiver_reject_writable_named_nonregular_wrong_size_or_duplicate_images() {
    for case in 0..6 {
        let root = tempdir().unwrap();
        let mut files = images();
        match case {
            0 => {
                files[0] = tempfile::tempfile().unwrap();
                files[0].set_len(1025).unwrap();
            }
            1 => {
                let path = root.path().join("named");
                fs::write(&path, vec![0; 1025]).unwrap();
                files[0] = File::open(path).unwrap();
            }
            2 => files[0] = File::open("/dev/null").unwrap(),
            3 => files[0] = image(&[0; 1024]),
            4 => files[0] = File::open(root.path()).unwrap(),
            5 => files[0] = files[1].try_clone().unwrap(),
            _ => unreachable!(),
        }
        let expected = context();
        let (sender, receiver) = channel().unwrap();
        let bytes = record(&expected, &files);
        raw_send(&sender.socket, &bytes, &files);
        drop(sender);
        assert!(receiver.receive(&expected).is_err());
        let (sender, _receiver) = channel().unwrap();
        assert!(sender.send(&expected, files).is_err());
    }
}

#[test]
fn alias_of_same_inode_cannot_fill_both_image_roles_even_when_sizes_match() {
    let expected = TransferContext::new([42; 16], "v1", [1025, 1025]).unwrap();
    let first = image(&[1; 1025]);
    let second = first.try_clone().unwrap();
    let files = [first, second];
    let (sender, receiver) = channel().unwrap();
    raw_send(&sender.socket, &record(&expected, &files), &files);
    drop(sender);
    assert!(receiver.receive(&expected).is_err());
    let (sender, _receiver) = channel().unwrap();
    assert!(sender.send(&expected, files).is_err());
}

#[test]
fn socket_kind_and_expected_peer_are_not_inferred_from_arbitrary_owned_fds() {
    let (_sender, receiver) = channel().unwrap();
    assert!(
        ImageReceiver::adopt(receiver.socket, nix::unistd::getpid().as_raw() as u32 + 1).is_err()
    );
    for kind in [SocketType::STREAM, SocketType::DGRAM] {
        let (_a, b) = socketpair(AddressFamily::UNIX, kind, SocketFlags::CLOEXEC, None).unwrap();
        assert!(ImageReceiver::adopt(b, nix::unistd::getpid().as_raw() as u32).is_err());
    }
    assert!(
        ImageReceiver::adopt(
            tempfile::tempfile().unwrap().into(),
            nix::unistd::getpid().as_raw() as u32
        )
        .is_err()
    );
}

#[test]
fn peer_close_before_record_is_an_error_and_never_an_empty_success() {
    let (sender, receiver) = channel().unwrap();
    drop(sender);
    assert!(receiver.receive(&context()).is_err());
    let (sender, receiver) = channel().unwrap();
    drop(receiver);
    assert!(sender.send(&context(), images()).is_err());
}

#[test]
fn live_silent_peer_hits_the_configured_receive_timeout() {
    let (_sender, receiver) = channel().unwrap();
    assert_eq!(
        rustix::net::sockopt::socket_timeout(&receiver.socket, Timeout::Recv).unwrap(),
        Some(SOCKET_TIMEOUT)
    );
    let error = receiver.receive(&context()).err().unwrap();
    assert!(
        matches!(error, TransferError::Io(ref error) if error.kind() == io::ErrorKind::WouldBlock)
    );
}

#[test]
fn unexpected_kernel_credentials_or_ancillary_truncation_fail_closed() {
    let (sender, receiver) = channel().unwrap();
    rustix::net::sockopt::set_socket_passcred(&receiver.socket, true).unwrap();
    sender.send(&context(), images()).unwrap();
    assert!(matches!(
        receiver.receive(&context()),
        Err(TransferError::Record)
    ));
}

#[test]
fn adopted_endpoint_and_received_images_always_have_cloexec() {
    let (sender, receiver) = channel().unwrap();
    fcntl_setfd(&receiver.socket, FdFlags::empty()).unwrap();
    let receiver =
        ImageReceiver::adopt(receiver.socket, nix::unistd::getpid().as_raw() as u32).unwrap();
    assert!(
        fcntl_getfd(&receiver.socket)
            .unwrap()
            .contains(FdFlags::CLOEXEC)
    );
    let files = images();
    fcntl_setfd(&files[0], FdFlags::empty()).unwrap();
    // Direct sender API rejects non-CLOEXEC; raw SCM send demonstrates that
    // CMSG_CLOEXEC atomically sets the receiver copy, irrespective of source.
    raw_send(&sender.socket, &record(&context(), &files), &files);
    drop(sender);
    let received = receiver.receive(&context()).unwrap();
    assert!(
        fcntl_getfd(&received[0].file)
            .unwrap()
            .contains(FdFlags::CLOEXEC)
    );
    let (sender, _receiver) = channel().unwrap();
    assert!(sender.send(&context(), files).is_err());
}

#[test]
fn closing_one_shot_receiver_releases_fds_in_unprocessed_extra_packets() {
    let (sender, receiver) = channel().unwrap();
    let files = images();
    raw_send(&sender.socket, &record(&context(), &files), &files);
    let (read, write) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NONBLOCK).unwrap();
    raw_send(&sender.socket, b"never processed", &[write.into()]);
    drop(sender);
    let _received = receiver.receive(&context()).unwrap();
    let mut reader = File::from(read);
    // Only the queued SCM_RIGHTS reference could still hold the pipe writer.
    // EOF proves endpoint teardown released it; NONBLOCK makes a leak fail
    // immediately instead of hanging this test.
    assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn rejected_packets_cleanup_child_fixture() {
    if std::env::var_os("NANOKVM_RAW_CHANNEL_CLEANUP_FIXTURE").is_none() {
        return;
    }
    let count_fds = || fs::read_dir("/proc/self/fd").unwrap().count();
    let before = count_fds();
    for count in [0, 1, 2, 3, 32] {
        {
            let files = images();
            let (sender, receiver) = channel().unwrap();
            let mut bytes = record(&context(), &files);
            if count == 2 {
                bytes[0] ^= 1;
            }
            let descriptors: Vec<_> = (0..count)
                .map(|index| files[index % 2].try_clone().unwrap())
                .collect();
            raw_send(&sender.socket, &bytes, &descriptors);
            drop(sender);
            assert!(receiver.receive(&context()).is_err());
        }
        assert_eq!(
            count_fds(),
            before,
            "rejected/truncated ancillary FDs leaked"
        );
    }
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn rejected_truncated_and_overflow_packets_do_not_leak_received_descriptors() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::raw_transport::tests::rejected_packets_cleanup_child_fixture",
            "--nocapture",
        ])
        .env_clear()
        .env("NANOKVM_RAW_CHANNEL_CLEANUP_FIXTURE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated descriptor cleanup fixture failed"
    );
}
