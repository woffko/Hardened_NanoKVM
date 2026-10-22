use super::*;

/// `openssl passwd -6 -salt Fx1./abcdEFGH234` of a synthetic password; the
/// image's BusyBox `mkpasswd -m sha512` prints the same line.
const ROOT_HASH: &str = "$6$Fx1./abcdEFGH234$2qHO9tMVYA0mOOe16irs2YWy6hEOtOydJUoBSmIWuKej9klY2b3zcJ9B4Z.PnBDbsCrinnVBtfhfxJS6DU2vx.";
const SALT: &str = "Fx1./abcdEFGH234";
const SHADOW: &[u8] = b"root:$5$synthetic$oldhash:19000:0:99999:7:::\n\
daemon:*:10933:0:99999:7:::\n\
sshd:!:19000::::::\n";
const OLD_ACCOUNT: &[u8] = b"{\"username\":\"operator\",\"password\":\"old\"}\n";
const NEW_ACCOUNT: &[u8] = b"{\"username\":\"operator\",\"password\":\"new\"}\n";
const STEPS: [Step; 3] = [Step::Journaled, Step::ShadowReplaced, Step::AccountReplaced];

struct Fixture {
    _dir: tempfile::TempDir,
    files: CredentialFiles,
}

fn fixture(account: Option<&[u8]>) -> Fixture {
    fixture_with(SHADOW, account)
}

fn fixture_with(shadow: &[u8], account: Option<&[u8]>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("kvm")).unwrap();
    let files = CredentialFiles {
        shadow: dir.path().join("shadow"),
        account: dir.path().join("kvm/pwd"),
    };
    fs::write(&files.shadow, shadow).unwrap();
    fs::set_permissions(&files.shadow, Permissions::from_mode(0o640)).unwrap();
    if let Some(account) = account {
        fs::write(&files.account, account).unwrap();
        fs::set_permissions(&files.account, Permissions::from_mode(0o600)).unwrap();
    }
    Fixture { _dir: dir, files }
}

impl Fixture {
    fn shadow(&self) -> Vec<u8> {
        fs::read(&self.files.shadow).unwrap()
    }

    fn account(&self) -> Option<Vec<u8>> {
        match fs::read(&self.files.account) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => panic!("{error}"),
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o7777
    }

    fn leftovers(&self) -> Vec<PathBuf> {
        std::iter::once(self.files.journal())
            .chain(self.files.scratch())
            .filter(|path| path.symlink_metadata().is_ok())
            .collect()
    }

    /// The stores are exactly as the fixture made them, with nothing left over.
    fn assert_untouched(&self, account: Option<&[u8]>) {
        assert_eq!(self.shadow(), SHADOW);
        assert_eq!(Self::mode(&self.files.shadow), 0o640);
        assert_eq!(self.account().as_deref(), account);
        if account.is_some() {
            assert_eq!(Self::mode(&self.files.account), 0o600);
        }
        assert_eq!(self.leftovers(), Vec::<PathBuf>::new());
        assert!(!self.files.recovery_pending());
    }
}

/// Clears an injected fault even when an assertion fails.
struct Faulted;

impl Drop for Faulted {
    fn drop(&mut self) {
        inject(None);
    }
}

fn fault(step: Step, fault: Fault) -> Faulted {
    inject(Some((step, fault)));
    Faulted
}

fn change_for(account: Option<&[u8]>) -> Change {
    if account.is_some() {
        Change::Replace
    } else {
        Change::Setup
    }
}

#[test]
fn a_change_replaces_root_and_web_together_and_leaves_no_journal() {
    let fixture = fixture(Some(OLD_ACCOUNT));
    replace(&fixture.files, Change::Replace, NEW_ACCOUNT, ROOT_HASH).unwrap();

    let day = today().map_or_else(|| "19000".to_string(), |day| day.to_string());
    let expected = format!(
        "root:{ROOT_HASH}:{day}:0:99999:7:::\ndaemon:*:10933:0:99999:7:::\nsshd:!:19000::::::\n"
    );
    assert_eq!(String::from_utf8(fixture.shadow()).unwrap(), expected);
    assert_eq!(Fixture::mode(&fixture.files.shadow), 0o640);
    assert_eq!(fixture.account().as_deref(), Some(NEW_ACCOUNT));
    assert_eq!(Fixture::mode(&fixture.files.account), 0o600);
    assert_eq!(fixture.leftovers(), Vec::<PathBuf>::new());
    assert!(!fixture.files.recovery_pending());
    assert!(!recover(&fixture.files).unwrap());
}

#[test]
fn setup_needs_no_account_and_a_change_needs_one() {
    let existing = fixture(Some(OLD_ACCOUNT));
    assert!(matches!(
        replace(&existing.files, Change::Setup, NEW_ACCOUNT, ROOT_HASH),
        Err(AppError::Conflict(_))
    ));
    existing.assert_untouched(Some(OLD_ACCOUNT));

    let fresh = fixture(None);
    assert!(matches!(
        replace(&fresh.files, Change::Replace, NEW_ACCOUNT, ROOT_HASH),
        Err(AppError::NotFound(_))
    ));
    fresh.assert_untouched(None);

    replace(&fresh.files, Change::Setup, NEW_ACCOUNT, ROOT_HASH).unwrap();
    assert_eq!(fresh.account().as_deref(), Some(NEW_ACCOUNT));
    assert!(
        fresh
            .shadow()
            .starts_with(format!("root:{ROOT_HASH}:").as_bytes())
    );
}

#[test]
fn a_failed_step_restores_both_stores_at_once() {
    for account in [Some(OLD_ACCOUNT), None] {
        for step in STEPS {
            let fixture = fixture(account);
            let _fault = fault(step, Fault::Fail);
            let result = replace(&fixture.files, change_for(account), NEW_ACCOUNT, ROOT_HASH);
            assert!(
                matches!(result, Err(AppError::Io(_))),
                "{step:?}: {result:?}"
            );
            fixture.assert_untouched(account);
        }
    }
}

#[test]
fn an_interrupted_change_is_restored_at_the_next_start() {
    for account in [Some(OLD_ACCOUNT), None] {
        for step in STEPS {
            let fixture = fixture(account);
            {
                let _crash = fault(step, Fault::Crash);
                assert!(
                    replace(&fixture.files, change_for(account), NEW_ACCOUNT, ROOT_HASH).is_err()
                );
            }
            assert!(fixture.files.recovery_pending(), "{step:?}");
            assert!(fixture.files.journal().is_file(), "{step:?}");
            if step == Step::AccountReplaced {
                // Both stores hold the new credentials; only the commit is missing.
                assert_eq!(fixture.account().as_deref(), Some(NEW_ACCOUNT));
                assert_ne!(fixture.shadow(), SHADOW);
            }
            // Until the start-time recovery, no further change is admitted.
            assert!(matches!(
                replace(&fixture.files, change_for(account), NEW_ACCOUNT, ROOT_HASH),
                Err(AppError::Conflict(ref text)) if text == PENDING
            ));

            assert!(recover(&fixture.files).unwrap(), "{step:?}");
            fixture.assert_untouched(account);
            assert!(!recover(&fixture.files).unwrap());

            replace(&fixture.files, change_for(account), NEW_ACCOUNT, ROOT_HASH).unwrap();
            assert_eq!(fixture.account().as_deref(), Some(NEW_ACCOUNT));
        }
    }
}

#[test]
fn scratch_left_by_a_crash_before_the_journal_binds_nothing() {
    let fixture = fixture(Some(OLD_ACCOUNT));
    for path in fixture.files.scratch() {
        fs::write(&path, b"partial synthetic scratch").unwrap();
    }
    assert!(fixture.files.recovery_pending());
    assert!(!recover(&fixture.files).unwrap());
    fixture.assert_untouched(Some(OLD_ACCOUNT));
}

#[test]
fn a_damaged_journal_is_kept_and_keeps_refusing_changes() {
    let fixture = fixture(Some(OLD_ACCOUNT));
    {
        let _crash = fault(Step::ShadowReplaced, Fault::Crash);
        assert!(replace(&fixture.files, Change::Replace, NEW_ACCOUNT, ROOT_HASH).is_err());
    }
    let journal = fixture.files.journal();
    let bytes = fs::read(&journal).unwrap();
    let damaged = [
        {
            let mut flipped = bytes.clone();
            flipped[MAGIC.len() + 20] ^= 1;
            flipped
        },
        bytes[..bytes.len() - 1].to_vec(),
        Vec::new(),
    ];
    for copy in damaged {
        fs::write(&journal, &copy).unwrap();
        assert!(matches!(
            recover(&fixture.files),
            Err(AppError::Internal(_))
        ));
        assert_eq!(fs::read(&journal).unwrap(), copy);
        assert!(matches!(
            replace(&fixture.files, Change::Replace, NEW_ACCOUNT, ROOT_HASH),
            Err(AppError::Conflict(_))
        ));
    }
    // The intact journal still restores the previous stores.
    fs::write(&journal, &bytes).unwrap();
    assert!(recover(&fixture.files).unwrap());
    fixture.assert_untouched(Some(OLD_ACCOUNT));
}

#[test]
fn the_root_entry_must_be_unique_and_well_formed() {
    let shadows: [&[u8]; 4] = [
        b"daemon:*:10933:0:99999:7:::\n",
        b"root:x:19000:0:99999:7:::\nroot:y:19000:0:99999:7:::\n",
        b"root:x\n",
        b"",
    ];
    for shadow in shadows {
        let fixture = fixture_with(shadow, Some(OLD_ACCOUNT));
        assert!(matches!(
            replace(&fixture.files, Change::Replace, NEW_ACCOUNT, ROOT_HASH),
            Err(AppError::Internal(_))
        ));
        assert_eq!(fixture.shadow(), shadow);
        assert_eq!(fixture.account().as_deref(), Some(OLD_ACCOUNT));
        assert_eq!(fixture.leftovers(), Vec::<PathBuf>::new());
    }
    // A hash carrying a field or line separator never reaches the file.
    for hash in ["$6$a:b", "$6$a\nroot::0:::::", ""] {
        assert!(with_root_hash(SHADOW, hash, Some(20_000)).is_err());
    }
}

#[test]
fn an_unset_clock_keeps_the_previous_change_day() {
    let unset = with_root_hash(SHADOW, ROOT_HASH, None).unwrap();
    assert!(unset.starts_with(format!("root:{ROOT_HASH}:19000:0:99999:7:::\n").as_bytes()));
    let stamped = with_root_hash(SHADOW, ROOT_HASH, Some(20_000)).unwrap();
    assert!(stamped.starts_with(format!("root:{ROOT_HASH}:20000:0:99999:7:::\n").as_bytes()));
    assert!(stamped.ends_with(b"\ndaemon:*:10933:0:99999:7:::\nsshd:!:19000::::::\n"));
    // A last entry without a newline keeps that form.
    let last = with_root_hash(b"daemon:*:1::::::\nroot:x:19000::::::", ROOT_HASH, None).unwrap();
    assert_eq!(
        &last[..],
        format!("daemon:*:1::::::\nroot:{ROOT_HASH}:19000::::::").as_bytes()
    );
    assert!(today().is_none_or(|day| day >= FIRST_PLAUSIBLE_DAY));
}

#[test]
fn only_one_sha512_line_for_the_chosen_salt_is_accepted() {
    let line = format!("{ROOT_HASH}\n");
    assert_eq!(parse_root_hash(line.as_bytes(), SALT).unwrap(), ROOT_HASH);
    let digest = &ROOT_HASH[ROOT_HASH.len() - SHA512_CRYPT_CHARS..];
    let rejected = [
        ROOT_HASH.to_string(),
        format!("{ROOT_HASH}\r\n"),
        format!("{ROOT_HASH}\n{ROOT_HASH}\n"),
        format!("$5${SALT}${digest}\n"),
        format!("$6$Fx1./abcdEFGH235${digest}\n"),
        format!("$6${SALT}${}\n", &digest[1..]),
        format!("$6${SALT}${}:\n", &digest[1..]),
        String::new(),
        "\n".to_string(),
    ];
    for output in rejected {
        assert!(
            parse_root_hash(output.as_bytes(), SALT).is_err(),
            "{output:?}"
        );
    }
    assert!(parse_root_hash(line.as_bytes(), "Fx1./abcdEFGH23").is_err());
}

#[test]
fn salts_are_sixteen_crypt_characters() {
    let salts: Vec<String> = (0..32).map(|_| root_salt().unwrap()).collect();
    for salt in &salts {
        assert_eq!(salt.len(), SALT_CHARS);
        assert!(salt.bytes().all(is_crypt_char), "{salt}");
    }
    assert!(salts.windows(2).any(|pair| pair[0] != pair[1]));
}

#[test]
fn a_symlinked_store_is_refused_and_its_target_kept() {
    let fixture = fixture(Some(OLD_ACCOUNT));
    let target = fixture.files.shadow.with_file_name("elsewhere");
    fs::rename(&fixture.files.shadow, &target).unwrap();
    std::os::unix::fs::symlink(&target, &fixture.files.shadow).unwrap();
    assert!(replace(&fixture.files, Change::Replace, NEW_ACCOUNT, ROOT_HASH).is_err());
    assert_eq!(fs::read(&target).unwrap(), SHADOW);
    assert_eq!(fixture.account().as_deref(), Some(OLD_ACCOUNT));
    assert_eq!(fixture.leftovers(), Vec::<PathBuf>::new());
}

#[test]
fn an_account_file_is_replaced_whole() {
    let fixture = fixture(Some(OLD_ACCOUNT));
    write_private(&fixture.files.account, NEW_ACCOUNT).unwrap();
    assert_eq!(fixture.account().as_deref(), Some(NEW_ACCOUNT));
    assert_eq!(Fixture::mode(&fixture.files.account), 0o600);
    assert_eq!(fixture.leftovers(), Vec::<PathBuf>::new());
}
