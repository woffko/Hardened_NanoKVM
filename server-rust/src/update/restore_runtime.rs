//! Fresh-process, fixed-command SSH sandbox. This validates isolation, not the
//! origin of its prepared root. Signed-image extraction/binding is mandatory at
//! the caller and is not inferred from a pathname or a successful native test.

use super::{
    restore_effective::RootContext,
    restore_fs,
    restore_key::{CHALLENGE, KeyOperation, KeyStage},
    restore_rootfs::RootfsView,
};
use nix::{
    fcntl::{FcntlArg, FdFlag, fcntl},
    mount::{MntFlags, MsFlags, mount, umount2},
    sched::{CloneFlags, unshare},
    sys::{
        prctl,
        resource::{Resource, setrlimit},
        signal::Signal,
    },
    unistd::{chdir, dup2, execve, fchdir, geteuid, getppid, pivot_root},
};
use rustix::{
    fs::{Dir, OFlags},
    thread::{self, CapabilitiesSecureBits as Bits, CapabilitySet, CapabilitySets},
};
use std::{
    convert::Infallible,
    ffi::CString,
    fs::{self, File},
    os::fd::{AsRawFd, OwnedFd},
    os::unix::fs::MetadataExt,
    path::Path,
};

#[path = "restore_runtime_filter.rs"]
mod filter;

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("SSH sandbox requires a fresh privileged process and a live parent lease")]
    Process,
    #[error("SSH sandbox root is not a bounded private prepared runtime")]
    Layout,
    #[error("SSH sandbox namespace or root isolation failed at {0}")]
    Isolation(&'static str),
    #[error("SSH sandbox resource limits failed")]
    Limits,
    #[error("SSH sandbox capability removal failed")]
    Capabilities,
    #[error("SSH sandbox syscall filter failed")]
    Filter,
    #[error("SSH sandbox native executable failed")]
    Exec,
}
impl SandboxError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Process => 70,
            Self::Layout => 71,
            Self::Isolation(_) => 72,
            Self::Limits => 73,
            Self::Capabilities => 74,
            Self::Filter => 75,
            Self::Exec => 76,
        }
    }
}

/// Irreversibly isolate this fresh single-threaded helper, then exec exactly
/// sshd -e -t against its prepared root. Never call in the server process.
/// The parent must already authenticate/bind the target runtime and snapshot;
/// this is NOT a signature-verification or restore-authorization API.
pub fn exec_sshd_syntax(root: &Path, expected_parent: u32) -> Result<Infallible, SandboxError> {
    exec_sshd(root, expected_parent, None, Check::Syntax)
}

/// Separate provenance-aware entry. The caller must authenticate the immutable
/// ROOTFS first; this function binds its runtime, not a mutable p3/target tree.
/// Prepared identity is still strictly inspected BEFORE any fixed image binds.
pub fn exec_sshd_syntax_from_image(
    root: &Path,
    expected_parent: u32,
    image: RootfsView,
) -> Result<Infallible, SandboxError> {
    exec_sshd(
        root,
        expected_parent,
        Some(ImageSource::Verified(image)),
        Check::Syntax,
    )
}

/// Native -T/-C for root at ONE explicit connection context. Output must be a
/// private anonymous write pipe; parent drains bounded/zeroizing, checks native
/// success+EOF and wall timeout/kill/reap. No raw output belongs in diagnostics.
pub fn exec_sshd_effective_from_image(
    root: &Path,
    expected_parent: u32,
    image: RootfsView,
    context: RootContext,
    output: OwnedFd,
) -> Result<Infallible, SandboxError> {
    exec_sshd(
        root,
        expected_parent,
        Some(ImageSource::Verified(image)),
        Check::Effective { context, output },
    )
}

/// Fixed native public/sign/verify mode, in the SAME exact-image boundary.
/// Challenge/allowed/signature inputs must already be in the private root.
pub fn exec_host_key_from_image(
    root: &Path,
    expected_parent: u32,
    image: RootfsView,
    operation: KeyOperation,
    output: OwnedFd,
) -> Result<Infallible, SandboxError> {
    exec_sshd(
        root,
        expected_parent,
        Some(ImageSource::Verified(image)),
        Check::Key { operation, output },
    )
}

enum Check {
    Syntax,
    Effective {
        context: RootContext,
        output: OwnedFd,
    },
    Key {
        operation: KeyOperation,
        output: OwnedFd,
    },
}

enum ImageSource {
    Verified(RootfsView),
    #[cfg(feature = "sandbox-test-fixture")]
    Fixture(std::path::PathBuf),
}

#[doc(hidden)]
#[cfg(feature = "sandbox-test-fixture")]
pub fn exec_sshd_syntax_image_fixture(
    root: &Path,
    expected_parent: u32,
    image: &Path,
) -> Result<Infallible, SandboxError> {
    exec_sshd(
        root,
        expected_parent,
        Some(ImageSource::Fixture(image.to_path_buf())),
        Check::Syntax,
    )
}

#[doc(hidden)]
#[cfg(feature = "sandbox-test-fixture")]
pub fn exec_sshd_effective_image_fixture(
    root: &Path,
    expected_parent: u32,
    image: &Path,
    context: RootContext,
    output: OwnedFd,
) -> Result<Infallible, SandboxError> {
    exec_sshd(
        root,
        expected_parent,
        Some(ImageSource::Fixture(image.to_path_buf())),
        Check::Effective { context, output },
    )
}

#[doc(hidden)]
#[cfg(feature = "sandbox-test-fixture")]
pub fn exec_host_key_image_fixture(
    root: &Path,
    expected_parent: u32,
    image: &Path,
    operation: KeyOperation,
    output: OwnedFd,
) -> Result<Infallible, SandboxError> {
    exec_sshd(
        root,
        expected_parent,
        Some(ImageSource::Fixture(image.to_path_buf())),
        Check::Key { operation, output },
    )
}

fn exec_sshd(
    root: &Path,
    expected_parent: u32,
    image: Option<ImageSource>,
    check: Check,
) -> Result<Infallible, SandboxError> {
    if !geteuid().is_root()
        || expected_parent <= 1
        || getppid().as_raw() as u32 != expected_parent
        || fs::read_dir("/proc/self/task")
            .map_err(|_| SandboxError::Process)?
            .count()
            != 1
    {
        return Err(SandboxError::Process);
    }
    prctl::set_pdeathsig(Signal::SIGKILL).map_err(|_| SandboxError::Process)?;
    if getppid().as_raw() as u32 != expected_parent {
        return Err(SandboxError::Process);
    }
    if let Check::Effective { output, .. } | Check::Key { output, .. } = &check {
        let stat = rustix::fs::fstat(output)
            .map_err(|_| SandboxError::Isolation("private output pipe"))?;
        let flags = rustix::fs::fcntl_getfl(output)
            .map_err(|_| SandboxError::Isolation("private output pipe"))?;
        if output.as_raw_fd() <= 2
            || stat.st_uid != 0
            || rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Fifo
            || rustix::fs::fstatfs(output)
                .map_err(|_| SandboxError::Isolation("private output pipe"))?
                .f_type as u64
                != u64::from(linux_raw_sys::general::PIPEFS_MAGIC)
            || flags & OFlags::ACCMODE != OFlags::WRONLY
            || flags.contains(OFlags::NONBLOCK)
            || !rustix::io::fcntl_getfd(output)
                .map_err(|_| SandboxError::Isolation("private output pipe"))?
                .contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(SandboxError::Isolation("private output pipe"));
        }
    }
    let pinned = restore_fs::open_root(root, true).map_err(|_| SandboxError::Layout)?;
    let original = pinned.metadata().map_err(|_| SandboxError::Layout)?;
    if original.uid() != 0 || original.mode() & 0o7077 != 0 {
        return Err(SandboxError::Layout);
    }
    let mut count = 0;
    let mut bytes = 0;
    inspect_tree(&pinned, "", 0, &mut count, &mut bytes)?;
    for path in [".oldroot", "proc", "sys", "data"] {
        require_empty_directory(&pinned, path)?;
    }
    let null_placeholder = restore_fs::open_beneath(&pinned, "dev/null", OFlags::RDONLY)
        .map_err(|_| SandboxError::Layout)?;
    let placeholder = null_placeholder
        .metadata()
        .map_err(|_| SandboxError::Layout)?;
    if !placeholder.is_file() || placeholder.len() != 0 {
        return Err(SandboxError::Layout);
    }
    if image.is_none() {
        let sshd = restore_fs::open_beneath(&pinned, "usr/sbin/sshd", OFlags::RDONLY)
            .map_err(|_| SandboxError::Layout)?;
        let executable = sshd.metadata().map_err(|_| SandboxError::Layout)?;
        if !executable.is_file() || executable.mode() & 0o111 == 0 {
            return Err(SandboxError::Layout);
        }
        drop(sshd);
    }
    drop(null_placeholder);
    let bpf = filter::compile()?;
    mark_inherited_close_on_exec()?;
    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET)
        .map_err(|_| SandboxError::Isolation("namespace"))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|_| SandboxError::Isolation("mount propagation"))?;
    let setup = restore_fs::open_root(root, true)
        .map_err(|_| SandboxError::Isolation("setup root reopen"))?;
    let actual = setup.metadata().map_err(|_| SandboxError::Layout)?;
    if actual.dev() != original.dev() || actual.ino() != original.ino() {
        return Err(SandboxError::Isolation("setup root identity"));
    }
    if let Some(image) = &image {
        let result = match image {
            ImageSource::Verified(view) => view.bind_ssh_runtime(&setup),
            #[cfg(feature = "sandbox-test-fixture")]
            ImageSource::Fixture(path) => super::restore_rootfs::bind_fixture_runtime(path, &setup),
        };
        result.map_err(|_| SandboxError::Isolation("image runtime binding"))?;
    }
    // Open only after CLONE_NEWNS: a proc-fd opened in the previous mount
    // namespace still refers to that old mount and is not a valid bind source.
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|_| SandboxError::Isolation("null open"))?;
    let null_source = format!("/proc/self/fd/{}", null.as_raw_fd());
    let null_target = root.join("dev/null");
    mount(
        Some(null_source.as_str()),
        &null_target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|_| SandboxError::Isolation("null bind"))?;
    mount(
        None::<&str>,
        &null_target,
        None::<&str>,
        MsFlags::MS_BIND
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|_| SandboxError::Isolation("null flags"))?;
    mount(
        Some(root),
        root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|_| SandboxError::Isolation("root bind"))?;
    // Reopen after bind so cwd/root uses the new mount, not the earlier pinned
    // descriptor's old writable mount. Require the exact same directory inode.
    let bound =
        restore_fs::open_root(root, false).map_err(|_| SandboxError::Isolation("root reopen"))?;
    let actual = bound
        .metadata()
        .map_err(|_| SandboxError::Isolation("root metadata"))?;
    if actual.dev() != original.dev() || actual.ino() != original.ino() {
        return Err(SandboxError::Isolation("root identity"));
    }
    fchdir(bound.as_raw_fd()).map_err(|_| SandboxError::Isolation("root cwd"))?;
    pivot_root(".", ".oldroot").map_err(|_| SandboxError::Isolation("pivot"))?;
    chdir("/").map_err(|_| SandboxError::Isolation("new cwd"))?;
    umount2("/.oldroot", MntFlags::MNT_DETACH)
        .map_err(|_| SandboxError::Isolation("old root detach"))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_BIND
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NODEV
            | MsFlags::MS_NOSUID,
        None::<&str>,
    )
    .map_err(|_| SandboxError::Isolation("root flags"))?;
    drop(pinned);
    drop(bound);
    drop(setup);
    drop(image); // all outside image/loop owners closed before native execution.
    // Open only after pivot: native stdin is a readonly descriptor INSIDE the
    // isolated root, not a proc-fd/old mount reference or a live parent pipe.
    let input = if matches!(&check, Check::Key { operation, .. } if operation.stage != KeyStage::Public)
    {
        let file = File::open(CHALLENGE).map_err(|_| SandboxError::Layout)?;
        let metadata = file.metadata().map_err(|_| SandboxError::Layout)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() != 32
        {
            return Err(SandboxError::Layout);
        }
        Some(file)
    } else {
        None
    };
    for (resource, maximum) in [
        (Resource::RLIMIT_CORE, 0),
        (Resource::RLIMIT_FSIZE, 0),
        (Resource::RLIMIT_NOFILE, 64),
        (Resource::RLIMIT_AS, 128 * 1024 * 1024),
        (Resource::RLIMIT_CPU, 10),
    ] {
        setrlimit(resource, maximum, maximum).map_err(|_| SandboxError::Limits)?;
    }
    drop_capabilities()?;
    thread::set_no_new_privs(true).map_err(|_| SandboxError::Capabilities)?;
    if getppid().as_raw() as u32 != expected_parent
        || prctl::get_pdeathsig().ok() != Some(Some(Signal::SIGKILL))
    {
        return Err(SandboxError::Process);
    }
    seccompiler::apply_filter(&bpf).map_err(|_| SandboxError::Filter)?;
    // -T and fixed key probes have private stdout. Stderr stays silent; no native config
    // or failure text is diagnostics. Pipe owner must enforce bounded reading.
    let (arguments, context) = match check {
        Check::Syntax => {
            for fd in 0..=1 {
                dup2(null.as_raw_fd(), fd).map_err(|_| SandboxError::Exec)?;
            }
            (
                vec!["/usr/sbin/sshd", "-e", "-t", "-f", "/etc/ssh/sshd_config"],
                None,
            )
        }
        Check::Effective { context, output } => {
            dup2(null.as_raw_fd(), 0).map_err(|_| SandboxError::Exec)?;
            dup2(null.as_raw_fd(), 2).map_err(|_| SandboxError::Exec)?;
            dup2(output.as_raw_fd(), 1).map_err(|_| SandboxError::Exec)?;
            drop(output);
            (
                vec!["/usr/sbin/sshd", "-e", "-T", "-f", "/etc/ssh/sshd_config"],
                Some(context),
            )
        }
        Check::Key { operation, output } => {
            dup2(input.as_ref().unwrap_or(&null).as_raw_fd(), 0).map_err(|_| SandboxError::Exec)?;
            dup2(null.as_raw_fd(), 2).map_err(|_| SandboxError::Exec)?;
            dup2(output.as_raw_fd(), 1).map_err(|_| SandboxError::Exec)?;
            drop(output);
            (operation.native_arguments(), None)
        }
    };
    drop(input);
    drop(null);
    let mut args = arguments
        .into_iter()
        .map(|s| CString::new(s).map_err(|_| SandboxError::Exec))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(context) = context {
        args.push(CString::new("-C").map_err(|_| SandboxError::Exec)?);
        args.push(CString::new(context.as_argument()).map_err(|_| SandboxError::Exec)?);
    }
    let env = [
        "LC_ALL=C",
        "PATH=/usr/bin:/bin",
        "HOME=/",
        "SSH_ASKPASS_REQUIRE=never",
    ]
    .into_iter()
    .map(|s| CString::new(s).map_err(|_| SandboxError::Exec))
    .collect::<Result<Vec<_>, _>>()?;
    execve(&args[0], &args, &env).map_err(|_| SandboxError::Exec)
}

fn inspect_tree(
    root: &File,
    path: &str,
    depth: usize,
    count: &mut usize,
    bytes: &mut u64,
) -> Result<(), SandboxError> {
    if depth > 16 {
        return Err(SandboxError::Layout);
    }
    let directory = if path.is_empty() {
        root.try_clone().map_err(|_| SandboxError::Layout)?
    } else {
        restore_fs::open_beneath(root, path, OFlags::RDONLY | OFlags::DIRECTORY)
            .map_err(|_| SandboxError::Layout)?
    };
    for entry in Dir::new(directory).map_err(|_| SandboxError::Layout)? {
        let entry = entry.map_err(|_| SandboxError::Layout)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| SandboxError::Layout)?;
        if name == "." || name == ".." {
            continue;
        }
        *count += 1;
        if *count > 1024 {
            return Err(SandboxError::Layout);
        }
        let relative = if path.is_empty() {
            name.to_string()
        } else {
            format!("{path}/{name}")
        };
        if relative.len() > 240 {
            return Err(SandboxError::Layout);
        }
        let file = restore_fs::open_beneath(root, &relative, OFlags::PATH)
            .map_err(|_| SandboxError::Layout)?;
        let metadata = file.metadata().map_err(|_| SandboxError::Layout)?;
        if metadata.uid() != 0 || metadata.mode() & 0o7022 != 0 {
            return Err(SandboxError::Layout);
        }
        if metadata.is_dir() {
            inspect_tree(root, &relative, depth + 1, count, bytes)?;
        } else if metadata.is_file() && metadata.nlink() == 1 {
            *bytes = bytes
                .checked_add(metadata.len())
                .ok_or(SandboxError::Layout)?;
            if *bytes > 64 * 1024 * 1024 {
                return Err(SandboxError::Layout);
            }
        } else {
            return Err(SandboxError::Layout);
        }
    }
    Ok(())
}

fn require_empty_directory(root: &File, path: &str) -> Result<(), SandboxError> {
    let file = restore_fs::open_beneath(root, path, OFlags::RDONLY | OFlags::DIRECTORY)
        .map_err(|_| SandboxError::Layout)?;
    for entry in Dir::new(file).map_err(|_| SandboxError::Layout)? {
        let entry = entry.map_err(|_| SandboxError::Layout)?;
        if ![b".".as_slice(), b"..".as_slice()].contains(&entry.file_name().to_bytes()) {
            return Err(SandboxError::Layout);
        }
    }
    Ok(())
}

fn mark_inherited_close_on_exec() -> Result<(), SandboxError> {
    for entry in fs::read_dir("/proc/self/fd").map_err(|_| SandboxError::Process)? {
        let entry = entry.map_err(|_| SandboxError::Process)?;
        let fd = entry
            .file_name()
            .to_str()
            .ok_or(SandboxError::Process)?
            .parse::<i32>()
            .map_err(|_| SandboxError::Process)?;
        if fd > 2 {
            fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|_| SandboxError::Process)?;
        }
    }
    Ok(())
}

fn drop_capabilities() -> Result<(), SandboxError> {
    thread::clear_ambient_capability_set().map_err(|_| SandboxError::Capabilities)?;
    thread::set_capabilities_secure_bits(
        Bits::NO_ROOT
            | Bits::NO_ROOT_LOCKED
            | Bits::NO_SETUID_FIXUP
            | Bits::NO_SETUID_FIXUP_LOCKED
            | Bits::KEEP_CAPS_LOCKED
            | Bits::NO_CAP_AMBIENT_RAISE
            | Bits::NO_CAP_AMBIENT_RAISE_LOCKED,
    )
    .map_err(|_| SandboxError::Capabilities)?;
    for bit in 0..64 {
        let capability = CapabilitySet::from_bits_retain(1_u64 << bit);
        match thread::capability_is_in_bounding_set(capability) {
            Ok(_) => thread::remove_capability_from_bounding_set(capability)
                .map_err(|_| SandboxError::Capabilities)?,
            Err(rustix::io::Errno::INVAL) => break,
            Err(_) => return Err(SandboxError::Capabilities),
        }
    }
    let empty = CapabilitySet::empty();
    thread::set_capabilities(
        None,
        CapabilitySets {
            effective: empty,
            permitted: empty,
            inheritable: empty,
        },
    )
    .map_err(|_| SandboxError::Capabilities)
}
