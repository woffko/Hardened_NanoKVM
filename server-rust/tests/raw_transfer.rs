#![cfg(feature = "sandbox-test-fixture")]

use nanokvm_rust_server::update::raw_transport::{TransferContext, channel};
use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    process::{Command, Stdio},
};

fn image(bytes: &[u8]) -> File {
    let mut writable = tempfile::tempfile().unwrap();
    writable.write_all(bytes).unwrap();
    let readonly = File::open(format!("/proc/self/fd/{}", writable.as_raw_fd())).unwrap();
    drop(writable);
    readonly
}

#[test]
fn readonly_images_cross_a_real_exec_boundary_only_via_private_stdio_socket() {
    let (sender, receiver) = channel().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nanokvm-raw-transfer-fixture"))
        .env_clear()
        .stdin(receiver.into_stdio())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let images = [image(&[0x35; 1025]), image(&[0x77; 65537])];
    let mut alias = images[0].try_clone().unwrap();
    let context = TransferContext::new([42; 16], "0.3.0-raw.fixture", [1025, 65537]).unwrap();
    sender.send(&context, images).unwrap();
    // SCM_RIGHTS shares the open description offset. Child pread must ignore it.
    alias.seek(SeekFrom::End(0)).unwrap();
    assert!(
        child.wait().unwrap().success(),
        "fresh-process transfer probe failed"
    );
}
