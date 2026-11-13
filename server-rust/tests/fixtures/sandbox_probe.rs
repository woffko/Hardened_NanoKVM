use nix::{
    fcntl::{FcntlArg, fcntl},
    sys::signal::kill,
    unistd::getppid,
};
use std::{
    fs,
    net::TcpStream,
    os::unix::fs::FileTypeExt,
    process::{Command, ExitCode},
};

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--expect-inherited-fd128") {
        return if fcntl(128, FcntlArg::F_GETFD).is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(20)
        };
    }
    let stop = fs::read_to_string("/etc/probe-stop").unwrap_or_default();
    if stop == "0" {
        return ExitCode::from(100);
    }
    let caps = rustix::thread::capabilities(None).unwrap();
    if !caps.effective.is_empty() || !caps.permitted.is_empty() || !caps.inheritable.is_empty() {
        return ExitCode::from(10);
    }
    for bit in 0..64 {
        let capability = rustix::thread::CapabilitySet::from_bits_retain(1_u64 << bit);
        match rustix::thread::capability_is_in_bounding_set(capability) {
            Ok(false) => {}
            Err(rustix::io::Errno::INVAL) => break,
            _ => return ExitCode::from(18),
        }
    }
    if stop == "1" {
        return ExitCode::from(101);
    }
    if !rustix::thread::no_new_privs().unwrap() {
        return ExitCode::from(11);
    }
    if nix::sys::prctl::get_pdeathsig().unwrap() != Some(nix::sys::signal::Signal::SIGKILL) {
        return ExitCode::from(21);
    }
    for (resource, expected) in [
        (nix::sys::resource::Resource::RLIMIT_CORE, 0),
        (nix::sys::resource::Resource::RLIMIT_FSIZE, 0),
        (nix::sys::resource::Resource::RLIMIT_NOFILE, 64),
        (nix::sys::resource::Resource::RLIMIT_AS, 128 * 1024 * 1024),
        (nix::sys::resource::Resource::RLIMIT_CPU, 10),
    ] {
        if nix::sys::resource::getrlimit(resource).unwrap() != (expected, expected) {
            return ExitCode::from(22);
        }
    }
    if stop == "2" {
        return ExitCode::from(102);
    }
    let outside = fs::read_to_string("/etc/outside-path").unwrap();
    if fs::read(outside.trim()).is_ok()
        || fs::read(format!("..{}", outside.trim())).is_ok()
        || fs::read("/proc/self/status").is_ok()
    {
        return ExitCode::from(12);
    }
    if !fs::metadata("/dev/null")
        .unwrap()
        .file_type()
        .is_char_device()
    {
        return ExitCode::from(19);
    }
    if stop == "3" {
        return ExitCode::from(103);
    }
    if fs::write("/write-attempt", b"synthetic")
        .err()
        .and_then(|e| e.raw_os_error())
        != Some(nix::libc::EROFS)
    {
        return ExitCode::from(13);
    }
    if stop == "4" {
        return ExitCode::from(104);
    }
    if TcpStream::connect("127.0.0.1:9")
        .err()
        .and_then(|e| e.raw_os_error())
        != Some(nix::libc::EPERM)
    {
        return ExitCode::from(14);
    }
    if stop == "5" {
        return ExitCode::from(105);
    }
    // Signal 0 never sends a signal, even if a broken filter mistakenly allows it.
    if kill(getppid(), None) != Err(nix::errno::Errno::EPERM) {
        return ExitCode::from(15);
    }
    // An unlisted fcntl request is denied before kernel processing. Duplication
    // of null would remain harmless even if a broken filter allowed it.
    if fcntl(0, FcntlArg::F_DUPFD_CLOEXEC(32)) != Err(nix::errno::Errno::EPERM) {
        return ExitCode::from(23);
    }
    if stop == "6" {
        return ExitCode::from(106);
    }
    // Command::status must create a child before exec. The initial execve is
    // necessarily allowed; this checks clone/fork, not a pathname exec filter.
    if Command::new("/not-present")
        .status()
        .err()
        .and_then(|e| e.raw_os_error())
        != Some(nix::libc::EPERM)
    {
        return ExitCode::from(16);
    }
    if stop == "7" {
        return ExitCode::from(107);
    }
    for fd in 3..256 {
        if fcntl(fd, FcntlArg::F_GETFD) != Err(nix::errno::Errno::EBADF) {
            return ExitCode::from(17);
        }
    }
    if fs::metadata("/etc/runtime-bind-probe").is_ok() {
        if fs::read("/usr/runtime-link").unwrap() != b"synthetic signed-runtime bytes"
            || fs::read("/etc/ssl/runtime-proof").unwrap() != b"synthetic provider config"
            || fs::read("/etc/ld-musl-riscv64.path").unwrap() != b"/lib:/usr/lib\n"
            || fs::read("/usr/link-outside").is_ok()
        {
            return ExitCode::from(24);
        }
        for path in [
            "/usr/runtime-proof",
            "/etc/ssl/runtime-proof",
            "/etc/ld-musl-riscv64.path",
        ] {
            if fs::write(path, b"synthetic")
                .err()
                .and_then(|e| e.raw_os_error())
                != Some(nix::libc::EROFS)
            {
                return ExitCode::from(25);
            }
        }
        // execve is intentionally admitted by the shared filter. This exact
        // config mount must still be NOEXEC. If broken, the copied probe exits20
        // via this argument (not a false-success /bin/true or recursive run).
        let args = [
            std::ffi::CString::new("/etc/ssl/exec-probe").unwrap(),
            std::ffi::CString::new("--expect-inherited-fd128").unwrap(),
        ];
        let env: [std::ffi::CString; 0] = [];
        if nix::unistd::execve(&args[0], &args, &env) != Err(nix::errno::Errno::EACCES) {
            return ExitCode::from(26);
        }
    }
    ExitCode::SUCCESS
}
