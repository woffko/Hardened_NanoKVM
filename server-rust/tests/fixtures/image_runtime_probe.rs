use nanokvm_rust_server::{
    config::Config,
    update::{
        restore_archive, restore_capsule,
        restore_effective::RootContext,
        restore_identity::{capture_effective, check_identity},
        restore_native::AccountFiles,
        restore_preflight::{PreparedSshRoot, prepare_sshd_root},
        restore_runtime::{exec_sshd_effective_image_fixture, exec_sshd_syntax_image_fixture},
    },
};
use std::{io::Cursor, os::fd::AsFd, path::Path, process::ExitCode};

// Synthetic host-only provenance: build and authenticate our own fixture
// capsule, then use the REAL typed identity builder. This does not verify a
// signed target image or authorize production restoration.
fn prepare_fixture(
    source: &Path,
    root: &Path,
) -> Result<PreparedSshRoot, Box<dyn std::error::Error>> {
    let signed = AccountFiles {
        passwd: b"root:x:0:0:root:/root:/bin/sh\nsshd:x:999:999:sshd:/var/empty:/bin/false\n",
        group: b"root:x:0:\nsshd:x:999:\n",
        shadow: b"root:!:::::::\nsshd:!:::::::\n",
        gshadow: None,
    };
    let mut config = Config::default();
    config.jwt.secret_key = "synthetic image builder fixture, not a credential".to_string();
    let mut archive = capture_effective(
        source,
        root,
        &config,
        Path::new("/etc/kvm"),
        Path::new("/etc/kvm/server.yaml"),
        &signed,
    )?;
    let mut ciphertext = Vec::new();
    let secret = restore_capsule::prepare_capsule(
        "0.3.0-raw.fixture",
        archive.size(),
        &mut archive,
        &mut ciphertext,
    )?;
    let plaintext = restore_capsule::open_capsule(&secret, &mut Cursor::new(ciphertext), root)?;
    let mut identity = check_identity(restore_archive::validate(plaintext)?, &signed)?;
    Ok(prepare_sshd_root(&mut identity, root)?)
}

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().collect();
    if !matches!(arguments.len(), 4 | 6 | 8) {
        return ExitCode::from(64);
    }
    let Some(parent) = arguments[3].to_str().and_then(|s| s.parse().ok()) else {
        return ExitCode::from(64);
    };
    let with_identity = arguments.len() >= 6 && arguments[4] == "--prepare-identity";
    let query_index = if with_identity { 6 } else { 4 };
    let query =
        if arguments.len() == query_index + 2 && arguments[query_index] == "--effective-root" {
            match arguments[query_index + 1]
                .to_str()
                .and_then(|v| RootContext::parse(v).ok())
            {
                Some(q) => Some(q),
                None => return ExitCode::from(64),
            }
        } else if arguments.len() == query_index {
            None
        } else {
            return ExitCode::from(64);
        };
    let _prepared = if with_identity {
        match prepare_fixture(Path::new(&arguments[5]), Path::new(&arguments[1])) {
            Ok(prepared) => Some(prepared),
            Err(_) => {
                eprintln!("synthetic identity builder fixture failed");
                return ExitCode::from(78);
            }
        }
    } else {
        None
    };
    let result = if let Some(query) = query {
        let Ok(output) = rustix::io::fcntl_dupfd_cloexec(std::io::stdout().as_fd(), 3) else {
            return ExitCode::from(78);
        };
        exec_sshd_effective_image_fixture(
            Path::new(&arguments[1]),
            parent,
            Path::new(&arguments[2]),
            query,
            output,
        )
    } else {
        exec_sshd_syntax_image_fixture(Path::new(&arguments[1]), parent, Path::new(&arguments[2]))
    };
    match result {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.exit_code())
        }
    }
}
