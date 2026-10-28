//! The broker's exec into the raw writer, end to end up to the device ticket
//! store. The child runs as root in fresh user, mount and PID namespaces:
//! there the writer's reboot only ends the namespace, and its kernel log is a
//! file that this test reads.
#![cfg(feature = "sandbox-test-fixture")]

use nanokvm_rust_server::{
    native_owner::broker::raw_install::{exec_writer, sealed_copy},
    update::{raw_transport, raw_writer::WriterArguments},
};
use std::{
    fs::File,
    io::Write,
    os::fd::AsRawFd,
    path::Path,
    process::{Command, Stdio},
};

const CHILD: &str = "NANOKVM_RAW_EXEC_CHILD_LOG";
const MISMATCH: &str = "NANOKVM_RAW_EXEC_MISMATCH";
const BOOT: &[u8] = b"synthetic boot image";
const ROOTFS: &[u8] = b"synthetic root filesystem image";

fn snapshot(bytes: &[u8]) -> File {
    let mut writable = tempfile::tempfile().unwrap();
    writable.write_all(bytes).unwrap();
    File::open(format!("/proc/self/fd/{}", writable.as_raw_fd())).unwrap()
}

fn arguments(transaction: u8) -> WriterArguments {
    let sizes = [BOOT.len() as u64, ROOTFS.len() as u64];
    WriterArguments::new([transaction; 16], "0.3.0-raw.13", sizes, [[1; 32], [2; 32]]).unwrap()
}

#[test]
fn exec_child() {
    let Some(log) = std::env::var_os(CHILD) else {
        return;
    };
    // The writer must stop at the missing ticket store, never reach a device,
    // and its reboot fallback (sysrq) must not be writable by the outer user.
    assert!(
        !Path::new("/dev/mmcblk0p1").exists() && !Path::new("/dev/mmcblk0p2").exists(),
        "refusing to run beside an SD card's partitions"
    );
    let map = std::fs::read_to_string("/proc/self/uid_map").unwrap();
    let outer = map.split_whitespace().nth(1).unwrap();
    assert_ne!(outer, "0", "refusing to run as the real root user");
    nix::mount::mount(
        Some(Path::new(&log)),
        "/dev/kmsg",
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .unwrap();
    let sent = arguments(7);
    let expected = arguments(if std::env::var_os(MISMATCH).is_some() {
        8
    } else {
        7
    });
    let (sender, receiver) = raw_transport::channel().unwrap();
    sender
        .send(sent.context(), [snapshot(BOOT), snapshot(ROOTFS)])
        .unwrap();
    let program = sealed_copy(Path::new(env!("CARGO_BIN_EXE_nanokvm-native-broker"))).unwrap();
    panic!(
        "exec failed: {}",
        exec_writer(&program, &expected, receiver)
    );
}

// The kernel log line the writer left, and the child's stderr.
fn writer_log(mismatch: bool) -> (String, String) {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("kmsg");
    File::create(&log).unwrap();
    let mut command = Command::new("/usr/bin/unshare");
    command
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--fork",
            "--mount-proc",
            "--",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "exec_child", "--nocapture", "--test-threads=1"])
        .env_clear()
        .env(CHILD, &log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if mismatch {
        command.env(MISMATCH, "1");
    }
    let output = command.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    // The writer never returns once it runs from the sealed copy: it reboots,
    // which in a child PID namespace ends the namespace.
    assert!(!output.status.success(), "{stderr}");
    assert!(!stderr.contains("exec failed"), "{stderr}");
    (std::fs::read_to_string(&log).unwrap(), stderr)
}

#[test]
fn the_sealed_writer_receives_the_images_and_stops_at_the_missing_ticket_store() {
    let (log, stderr) = writer_log(false);
    assert!(
        log.lines().any(|line| line
            .starts_with("<3>nanokvm-raw-writer: raw write not started: boot restore I/O failed")),
        "{log}\n{stderr}"
    );
    assert!(!log.contains("raw write step:"), "{log}");
    assert!(
        !log.contains("raw writer received verified inputs:"),
        "{log}"
    );
}

#[test]
fn images_sent_under_another_context_are_refused_before_the_ticket() {
    let (log, stderr) = writer_log(true);
    assert!(
        log.lines().any(|line| line.starts_with(
            "<3>nanokvm-raw-writer: raw write not started: invalid or truncated raw transfer"
        )),
        "{log}\n{stderr}"
    );
    assert!(!log.contains("raw write step:"), "{log}");
    assert!(
        !log.contains("raw writer received verified inputs:"),
        "{log}"
    );
}
