use nanokvm_rust_server::{
    config::Config,
    update::{
        restore_archive, restore_capsule,
        restore_identity::{capture_effective, check_identity},
        restore_native::AccountFiles,
        restore_preflight::{PreparedSshRoot, prepare_sshd_root},
        restore_runtime::exec_sshd_syntax_image_fixture,
    },
};
use std::{io::Cursor, path::Path, process::ExitCode};

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
    if !matches!(arguments.len(), 4 | 6)
        || (arguments.len() == 6 && arguments[4] != "--prepare-identity")
    {
        return ExitCode::from(64);
    }
    let Some(parent) = arguments[3].to_str().and_then(|s| s.parse().ok()) else {
        return ExitCode::from(64);
    };
    let _prepared = if arguments.len() == 6 {
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
    match exec_sshd_syntax_image_fixture(Path::new(&arguments[1]), parent, Path::new(&arguments[2]))
    {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.exit_code())
        }
    }
}
