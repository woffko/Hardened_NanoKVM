use nanokvm_rust_server::update::{
    raw_transport::{ImageReceiver, TransferContext},
    restore_effective::RootContext,
    restore_rootfs::{RootfsError, RootfsView},
    restore_runtime::{
        SandboxError, exec_sshd_effective_from_image, exec_sshd_syntax, exec_sshd_syntax_from_image,
    },
};
use std::{
    convert::Infallible,
    ffi::OsString,
    fs::File,
    os::fd::{AsFd, AsRawFd},
    path::Path,
    process::ExitCode,
};

enum Mode<'a> {
    Prepared {
        root: &'a Path,
        parent: u32,
    },
    Image {
        root: &'a Path,
        parent: u32,
        mountpoint: &'a Path,
        context: TransferContext,
        query: Option<RootContext>,
    },
}

#[derive(Debug, thiserror::Error)]
enum RunError {
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
    #[error(transparent)]
    Rootfs(#[from] RootfsError),
    #[error("SSH image sandbox descriptor handoff failed")]
    Transfer,
}

impl RunError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Sandbox(error) => error.exit_code(),
            Self::Rootfs(RootfsError::Process) => 70,
            Self::Rootfs(RootfsError::Image | RootfsError::Layout | RootfsError::Accounts) => 71,
            Self::Rootfs(RootfsError::Namespace | RootfsError::Device | RootfsError::Mount) => 72,
            Self::Rootfs(RootfsError::Io(_)) => 73,
            Self::Transfer => 77,
        }
    }
}

fn parse(args: &[OsString]) -> Option<Mode<'_>> {
    if !matches!(args.len(), 5 | 15 | 17) || args[1] != "--root" || args[3] != "--parent-pid" {
        return None;
    }
    let root = Path::new(&args[2]);
    let parent = args[4]
        .to_str()?
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 1)?;
    if args.len() == 5 {
        return Some(Mode::Prepared { root, parent });
    }
    for (index, flag) in [
        (5, "--image-root"),
        (7, "--transaction"),
        (9, "--version"),
        (11, "--boot-size"),
        (13, "--rootfs-size"),
    ] {
        if args[index] != flag {
            return None;
        }
    }
    let encoded = args[8].to_str()?.as_bytes();
    if encoded.len() != 32 {
        return None;
    }
    let mut transaction = [0; 16];
    for (out, pair) in transaction.iter_mut().zip(encoded.as_chunks::<2>().0) {
        let hex = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        *out = hex(pair[0])? * 16 + hex(pair[1])?;
    }
    let sizes = [
        args[12].to_str()?.parse::<u64>().ok()?,
        args[14].to_str()?.parse::<u64>().ok()?,
    ];
    let context = TransferContext::new(transaction, args[10].to_str()?, sizes).ok()?;
    let query = if args.len() == 17 {
        if args[15] != "--effective-root" {
            return None;
        }
        Some(RootContext::parse(args[16].to_str()?).ok()?)
    } else {
        None
    };
    Some(Mode::Image {
        root,
        parent,
        mountpoint: Path::new(&args[6]),
        context,
        query,
    })
}

fn run(mode: Mode<'_>) -> Result<Infallible, RunError> {
    let (root, parent, mountpoint, context, query) = match mode {
        Mode::Prepared { root, parent } => {
            return exec_sshd_syntax(root, parent).map_err(Into::into);
        }
        Mode::Image {
            root,
            parent,
            mountpoint,
            context,
            query,
        } => (root, parent, mountpoint, context, query),
    };
    if nix::unistd::getppid().as_raw() as u32 != parent {
        return Err(RootfsError::Process.into());
    }
    nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL)
        .map_err(|_| RootfsError::Process)?;
    if nix::unistd::getppid().as_raw() as u32 != parent {
        return Err(RootfsError::Process.into());
    }
    // Public context is not signature authorization. The trusted parent must
    // authenticate both immutable images, close writable/Command aliases and
    // enforce a wall timeout with kill/reap. Never accept a mutable image path.
    let socket = rustix::io::fcntl_dupfd_cloexec(std::io::stdin().as_fd(), 3)
        .map_err(|_| RunError::Transfer)?;
    let null = File::open("/dev/null").map_err(|_| RunError::Transfer)?;
    nix::unistd::dup2(null.as_raw_fd(), 0).map_err(|_| RunError::Transfer)?;
    let output = if query.is_some() {
        let output = rustix::io::fcntl_dupfd_cloexec(std::io::stdout().as_fd(), 3)
            .map_err(|_| RunError::Transfer)?;
        nix::unistd::dup2(null.as_raw_fd(), 1).map_err(|_| RunError::Transfer)?;
        Some(output)
    } else {
        None
    };
    drop(null);
    let receiver = ImageReceiver::adopt(socket, parent).map_err(|_| RunError::Transfer)?;
    let [boot, rootfs] = receiver.receive(&context).map_err(|_| RunError::Transfer)?;
    drop(boot); // Syntax preflight never boots or writes either image.
    let view = RootfsView::mount(rootfs, mountpoint, parent)?;
    match (query, output) {
        (Some(query), Some(output)) => {
            exec_sshd_effective_from_image(root, parent, view, query, output).map_err(Into::into)
        }
        (None, None) => exec_sshd_syntax_from_image(root, parent, view).map_err(Into::into),
        _ => Err(RunError::Transfer),
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().take(18).collect();
    let Some(mode) = parse(&args) else {
        eprintln!(
            "usage: nanokvm-ssh-sandbox --root PRIVATE_PREPARED_ROOT --parent-pid PID [--image-root EMPTY_PRIVATE_MOUNTPOINT --transaction HEX32 --version VERSION --boot-size BYTES --rootfs-size BYTES [--effective-root FIXED_ROOT_CONNECTION_SPEC]]"
        );
        return ExitCode::from(64);
    };
    match run(mode) {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<OsString> {
        [
            "helper",
            "--root",
            "/private",
            "--parent-pid",
            "42",
            "--image-root",
            "/image",
            "--transaction",
            "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
            "--version",
            "0.3.0-raw.fixture",
            "--boot-size",
            "1025",
            "--rootfs-size",
            "65537",
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }

    #[test]
    fn accepts_only_fixed_legacy_or_image_modes() {
        let all = args();
        assert!(matches!(
            parse(&all[..5]),
            Some(Mode::Prepared { parent: 42, .. })
        ));
        let expected = TransferContext::new([42; 16], "0.3.0-raw.fixture", [1025, 65537]).unwrap();
        assert!(
            matches!(parse(&all), Some(Mode::Image { parent: 42, context, .. }) if context == expected)
        );
        for length in 0..all.len() {
            if length != 5 {
                assert!(parse(&all[..length]).is_none());
            }
        }
        let mut extra = all;
        extra.push("extra".into());
        assert!(parse(&extra).is_none());
    }

    #[test]
    fn rejects_bad_flags_and_public_context_before_handoff() {
        for index in [1, 3, 5, 7, 9, 11, 13] {
            let mut invalid = args();
            invalid[index] = "--unknown".into();
            assert!(parse(&invalid).is_none());
        }
        for (index, values) in [
            (4, vec!["0", "1", "-1", "4294967296"]),
            (
                8,
                vec![
                    "",
                    "2a",
                    "00000000000000000000000000000000",
                    "ga2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
                ],
            ),
            (10, vec!["", "bad/version"]),
            (12, vec!["0", "-1", "18446744073709551616", "2147483648"]),
            (14, vec!["0", "-1", "18446744073709551616", "2147483648"]),
        ] {
            for value in values {
                let mut invalid = args();
                invalid[index] = value.into();
                assert!(parse(&invalid).is_none(), "index {index}");
            }
        }
    }

    #[test]
    fn effective_mode_requires_image_context_and_fixed_root_spec() {
        let mut image = args();
        image.extend([
            "--effective-root".into(),
            "user=root,host=fixture.example,addr=198.51.100.7,laddr=192.0.2.1,lport=22".into(),
        ]);
        assert!(matches!(
            parse(&image),
            Some(Mode::Image { query: Some(_), .. })
        ));
        let mut legacy = args()[..5].to_vec();
        legacy.extend_from_slice(&image[15..]);
        assert!(parse(&legacy).is_none());
        image[16] = "user=admin,host=x,addr=198.51.100.7,laddr=192.0.2.1,lport=22".into();
        assert!(parse(&image).is_none());
    }
}
