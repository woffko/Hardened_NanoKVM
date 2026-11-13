use super::*;
use crate::update::{restore_archive, restore_capsule::open_capsule};
use std::{
    fs,
    io::{Cursor, Read},
    os::unix::fs::PermissionsExt,
    path::Path,
};
use tempfile::{TempDir, tempdir};

const VERSION: &str = "0.3.0-raw.13";

fn private() -> TempDir {
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn the_capsule_is_published_whole_under_its_transaction_and_opens_with_its_secret() {
    let (source, staging, capsules) = (tempdir().unwrap(), private(), private());
    let mut archive = restore_archive::fixture_archive(source.path(), staging.path());
    let mut plaintext = Vec::new();
    archive.rewind().unwrap();
    archive.read_to_end(&mut plaintext).unwrap();
    let directory = File::open(capsules.path()).unwrap();

    let sealed = seal_capsule(&mut archive, VERSION, &directory).unwrap();

    assert_eq!(names(capsules.path()), [sealed.name().to_string()]);
    let path = capsules.path().join(sealed.name());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let encrypted = fs::read(&path).unwrap();
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&encrypted)),
        *sealed.sha256()
    );
    let name = sealed.name().to_string();
    let secret = sealed.into_secret();
    assert_eq!(name, format!("{}{SUFFIX}", hex(&secret.transaction_id())));
    let mut payload = open_capsule(&secret, &mut Cursor::new(encrypted), staging.path()).unwrap();
    let mut opened = Vec::new();
    payload.read_to_end(&mut opened).unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn every_seal_has_a_fresh_transaction_and_never_replaces_a_capsule() {
    let (source, staging, capsules) = (tempdir().unwrap(), private(), private());
    let mut archive = restore_archive::fixture_archive(source.path(), staging.path());
    let directory = File::open(capsules.path()).unwrap();
    let first = seal_capsule(&mut archive, VERSION, &directory).unwrap();
    let second = seal_capsule(&mut archive, VERSION, &directory).unwrap();
    assert_ne!(first.name(), second.name());
    assert_ne!(first.sha256(), second.sha256());
    assert_eq!(names(capsules.path()).len(), 2);
}

#[test]
fn an_interrupted_seal_leaves_neither_a_temporary_nor_a_capsule() {
    let (source, staging, capsules) = (tempdir().unwrap(), private(), private());
    let mut archive = restore_archive::fixture_archive(source.path(), staging.path());
    let directory = File::open(capsules.path()).unwrap();
    for step in [
        FailBefore::Sync,
        FailBefore::Rename,
        FailBefore::DirectorySync,
    ] {
        FAIL_AT.with(|fail| fail.set(Some(step)));
        let result = seal_capsule(&mut archive, VERSION, &directory);
        FAIL_AT.with(|fail| fail.set(None));
        assert!(matches!(result, Err(CaptureError::Io(_))));
        assert!(
            names(capsules.path()).is_empty(),
            "left after an injected fault"
        );
    }
    fs::set_permissions(capsules.path(), fs::Permissions::from_mode(0o500)).unwrap();
    assert!(seal_capsule(&mut archive, VERSION, &directory).is_err());
    fs::set_permissions(capsules.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(names(capsules.path()).is_empty());
}

mod composed {
    use super::*;
    use crate::update::{
        restore_accounts,
        restore_capsule::ticket::Phase,
        restore_identity::tests::{CONFIG_PATH, CWD, fixture, signed_accounts},
    };

    const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
    const IMAGE_APP: &str = "2.1.3";

    #[derive(Default)]
    struct Image {
        ssh_checked: bool,
        fail_ssh: bool,
        cancel_in_ssh: bool,
        account_members: Vec<String>,
        no_restore: bool,
    }
    impl TargetImage for Image {
        fn signed_accounts(&mut self, _: &AtomicBool) -> Result<SignedAccounts> {
            let facts = restore_accounts::ImageFacts {
                app_version: IMAGE_APP.to_string(),
                restorable: !self.no_restore,
            };
            let encoded = restore_accounts::encode(&signed_accounts(), &facts).unwrap();
            Ok(restore_accounts::decode(&encoded).unwrap())
        }
        fn check_ssh(
            &mut self,
            restore: &mut IdentityCheckedRestore,
            cancel: &AtomicBool,
        ) -> Result<()> {
            self.ssh_checked = true;
            self.account_members = restore
                .members()
                .iter()
                .map(|member| member.path.clone())
                .filter(|path| path.starts_with("etc/"))
                .collect();
            if self.cancel_in_ssh {
                cancel.store(true, Ordering::SeqCst);
            }
            if self.fail_ssh {
                return Err(CaptureError::Image(JobError::Native));
            }
            Ok(())
        }
    }

    fn request<'a>(
        source: &'a Path,
        staging: &'a Path,
        capsules: &'a File,
        config: &'a Config,
    ) -> CaptureRequest<'a> {
        CaptureRequest {
            source_root: source,
            private_staging: staging,
            capsule_directory: capsules,
            config,
            working_dir: Path::new(CWD),
            config_path: Path::new(CONFIG_PATH),
            target_version: VERSION,
            target: "sg2002-licheervnano-sd",
            boot_image_sha256: [2; 32],
            rootfs_image_sha256: [3; 32],
            source_boot: BootId::parse(SOURCE).unwrap(),
            device_id: [1; 32],
        }
    }

    #[test]
    fn capture_seals_checks_and_binds_a_prepared_ticket_to_its_capsule() {
        let (source, config) = fixture();
        let (staging, capsules) = (private(), private());
        let directory = File::open(capsules.path()).unwrap();
        let mut image = Image::default();
        let cancel = AtomicBool::new(false);

        let captured = capture(
            &request(source.path(), staging.path(), &directory, &config),
            &mut image,
            &cancel,
        )
        .unwrap();

        assert!(image.ssh_checked);
        assert!(image.account_members.contains(&"etc/passwd".to_string()));
        assert_eq!(
            names(capsules.path()),
            [captured.capsule_name().to_string()]
        );
        let ticket = captured.into_ticket();
        assert_eq!(ticket.phase(), Phase::Prepared);
        assert_eq!(ticket.target_app_version(), IMAGE_APP);
        assert_eq!(
            format!("{}{SUFFIX}", hex(&ticket.transaction_id())),
            names(capsules.path())[0]
        );
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    }

    #[test]
    fn an_image_without_its_early_restore_is_refused_before_anything_is_sealed() {
        let (source, config) = fixture();
        let (staging, capsules) = (private(), private());
        let directory = File::open(capsules.path()).unwrap();
        let mut image = Image {
            no_restore: true,
            ..Image::default()
        };
        assert!(matches!(
            capture(
                &request(source.path(), staging.path(), &directory, &config),
                &mut image,
                &AtomicBool::new(false),
            ),
            Err(CaptureError::NotRestorable)
        ));
        assert!(!image.ssh_checked);
        assert!(names(capsules.path()).is_empty());
    }

    #[test]
    fn a_failure_or_cancellation_after_sealing_removes_the_capsule() {
        let (source, config) = fixture();
        let (staging, capsules) = (private(), private());
        let directory = File::open(capsules.path()).unwrap();
        let cancel = AtomicBool::new(false);
        let failing = &mut Image {
            fail_ssh: true,
            ..Image::default()
        };
        assert!(matches!(
            capture(
                &request(source.path(), staging.path(), &directory, &config),
                failing,
                &cancel
            ),
            Err(CaptureError::Image(JobError::Native))
        ));
        assert!(names(capsules.path()).is_empty());
        let cancelling = &mut Image {
            cancel_in_ssh: true,
            ..Image::default()
        };
        assert!(matches!(
            capture(
                &request(source.path(), staging.path(), &directory, &config),
                cancelling,
                &cancel
            ),
            Err(CaptureError::Cancelled)
        ));
        assert!(names(capsules.path()).is_empty());
        // Cancelled before anything: no capture and no capsule.
        assert!(matches!(
            capture(
                &request(source.path(), staging.path(), &directory, &config),
                &mut Image::default(),
                &cancel
            ),
            Err(CaptureError::Cancelled)
        ));
        assert!(names(capsules.path()).is_empty());
        let mut bad = request(source.path(), staging.path(), &directory, &config);
        let invalid_target = "bad target";
        bad.target = invalid_target;
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            capture(&bad, &mut Image::default(), &cancel),
            Err(CaptureError::Ticket(_))
        ));
        assert!(names(capsules.path()).is_empty());
    }

    #[test]
    fn a_capsule_changed_after_sealing_is_refused_before_decryption() {
        let (source, staging, capsules) = (tempdir().unwrap(), private(), private());
        let mut archive = restore_archive::fixture_archive(source.path(), staging.path());
        let directory = File::open(capsules.path()).unwrap();
        let sealed = seal_capsule(&mut archive, VERSION, &directory).unwrap();
        let path = capsules.path().join(sealed.name());
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            verify_sealed(&sealed, &directory, staging.path(), &signed_accounts()),
            Err(CaptureError::Changed)
        ));
    }
}

mod ssh_checks {
    use super::*;
    use crate::update::restore_identity::{
        check_identity,
        tests::{CONFIG_PATH, CWD, fixture, preflight_namespace, signed_accounts},
    };

    fn checked_fixture(staging: &Path) -> IdentityCheckedRestore {
        let (source, config) = fixture();
        let signed = signed_accounts();
        let mut archive = restore_identity::capture_effective(
            source.path(),
            staging,
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
            &signed,
        )
        .unwrap();
        let capsules = private();
        let directory = File::open(capsules.path()).unwrap();
        let sealed = seal_capsule(&mut archive, VERSION, &directory).unwrap();
        let mut file = File::open(capsules.path().join(sealed.name())).unwrap();
        let payload = open_capsule(&sealed.secret, &mut file, staging).unwrap();
        check_identity(restore_archive::validate(payload).unwrap(), &signed).unwrap()
    }

    fn kind(check: &Check) -> &'static str {
        match check {
            Check::Syntax => "syntax",
            Check::Effective(_) => "effective",
            Check::HostKeys => "host-keys",
        }
    }

    #[test]
    fn every_check_gets_its_own_empty_root_and_leaves_none_behind() {
        if !preflight_namespace(concat!(
            module_path!(),
            "::every_check_gets_its_own_empty_root_and_leaves_none_behind"
        )) {
            return;
        }
        let (staging, roots) = (private(), private());
        let mut restore = checked_fixture(staging.path());
        let checks = [
            Check::Syntax,
            Check::Effective(probe_context("kvm-test").unwrap()),
            Check::HostKeys,
        ];
        let mut seen = Vec::new();
        run_ssh_checks(&mut restore, roots.path(), checks, |identity, check| {
            let root = identity.checked_path().unwrap().to_path_buf();
            assert_eq!(names(roots.path()), [format!("check-{}", seen.len())]);
            assert!(root.join("etc/passwd").is_file(), "{}", root.display());
            seen.push(kind(&check));
            identity.cleanup().unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, ["syntax", "effective", "host-keys"]);
        assert!(names(roots.path()).is_empty());

        // A failing check stops the sequence; its root is still removed.
        let mut seen = Vec::new();
        let result = run_ssh_checks(
            &mut restore,
            roots.path(),
            [Check::Syntax, Check::HostKeys],
            |identity, check| {
                seen.push(kind(&check));
                identity.cleanup().unwrap();
                Err(CaptureError::Image(JobError::Native))
            },
        );
        assert!(matches!(result, Err(CaptureError::Image(JobError::Native))));
        assert_eq!(seen, ["syntax"]);
        assert!(names(roots.path()).is_empty());

        // Unknown entries left in a root are preserved, and the error wins.
        let result = run_ssh_checks(
            &mut restore,
            roots.path(),
            [Check::Syntax],
            |identity, _| {
                let root = identity.checked_path().unwrap().to_path_buf();
                identity.cleanup().unwrap();
                fs::write(root.join("unknown"), b"keep").unwrap();
                Ok(())
            },
        );
        assert!(matches!(result, Err(CaptureError::Io(_))));
        assert_eq!(
            fs::read(roots.path().join("check-0/unknown")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn the_probe_context_is_a_fixed_root_profile_on_documentation_addresses() {
        assert!(probe_context("kvm-test").is_ok());
        assert!(matches!(probe_context(""), Err(CaptureError::Context)));
        assert!(matches!(
            probe_context("bad host"),
            Err(CaptureError::Context)
        ));
    }
}
