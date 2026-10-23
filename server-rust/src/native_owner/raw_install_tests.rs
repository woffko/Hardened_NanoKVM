use super::*;
use rustix::{
    fs::fcntl_get_seals,
    io::{FdFlags, fcntl_getfd},
    net::{AddressFamily, SocketFlags, SocketType, socketpair},
};
use std::{
    io::{Read, Seek, Write},
    process::{Command, Stdio},
};

const FD_CHILD: &str = "NANOKVM_RAW_EXEC_FD_CHILD";
const LEAKED: RawFd = 50;

#[test]
fn the_writer_copy_is_identical_and_sealed_against_any_change() {
    let mut source = tempfile::NamedTempFile::new().unwrap();
    let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    source.write_all(&bytes).unwrap();
    let mut copy = sealed_copy(source.path()).unwrap();
    assert!(
        fcntl_get_seals(&copy)
            .unwrap()
            .contains(SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE | SealFlags::SEAL)
    );
    assert!(fcntl_getfd(&copy).unwrap().contains(FdFlags::CLOEXEC));
    let mut read = Vec::new();
    copy.rewind().unwrap();
    copy.read_to_end(&mut read).unwrap();
    assert_eq!(read, bytes);
    // Changing the source afterwards changes nothing in the copy.
    source.as_file().set_len(0).unwrap();
    assert_eq!(copy.metadata().unwrap().len(), bytes.len() as u64);
    assert!(copy.write_all(b"x").is_err());
    assert!(copy.set_len(1).is_err());
    assert!(copy.set_len(bytes.len() as u64 + 1).is_err());
    assert!(fcntl_add_seals(&copy, SealFlags::FUTURE_WRITE).is_err());
    assert!(sealed_copy(&source.path().with_extension("missing")).is_err());
}

// Run in a fresh process: the exec replaces it with a sealed copy of the shell,
// which lists its own descriptors.
#[test]
fn exec_fd_child() {
    if std::env::var_os(FD_CHILD).is_none() {
        return;
    }
    let inheritable = File::open("/dev/null").unwrap();
    nix::unistd::dup2(inheritable.as_raw_fd(), LEAKED).unwrap();
    let (socket, _peer) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let program = sealed_copy(Path::new("/bin/sh")).unwrap();
    let argv = [
        c"sh".to_owned(),
        c"-c".to_owned(),
        // libtest has printed an unterminated "test ... " line by now.
        c"echo; echo descriptors:; ls /proc/$$/fd; test -S /proc/$$/fd/0 && echo stdin-is-a-socket"
            .to_owned(),
    ];
    panic!("exec failed: {}", exec_with_stdin(&program, &argv, socket));
}

#[test]
fn the_exec_keeps_only_stdio_and_makes_the_socket_stdin() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_owner::broker::raw_install::tests::exec_fd_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(FD_CHILD, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    let descriptors: Vec<&str> = stdout
        .lines()
        .skip_while(|line| *line != "descriptors:")
        .filter(|line| !line.is_empty() && line.bytes().all(|byte| byte.is_ascii_digit()))
        .collect();
    assert_eq!(descriptors, ["0", "1", "2"], "{stdout}");
    assert!(stdout.contains("stdin-is-a-socket"), "{stdout}");
}
