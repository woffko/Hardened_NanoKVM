use super::*;
use crate::update::restore_capsule::{open_capsule, prepare_capsule};
use std::{fs, io::Cursor, path::Path};
use tempfile::{TempDir, tempdir};

fn put(root: &Path, path: &str, bytes: &[u8]) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn source_fixture() -> TempDir {
    let root = tempdir().unwrap();
    for path in crate::update::restore_policy::REQUIRED {
        put(root.path(), path, b"synthetic archive fixture\n");
    }
    put(
        root.path(),
        "etc/kvm/session_secret",
        b"synthetic archive secret\n",
    );
    put(root.path(), MAIN, b"Include sshd_config.d/*.conf\n");
    put(root.path(), HOST_KEYS[2], b"synthetic key, presence only");
    root
}

fn archive_snapshot(source: &SourceRoot, snapshot: &mut Snapshot) -> ValidatedRestore {
    let staging = tempdir().unwrap();
    let settings = snapshot.take_settings();
    let captured = restore_archive::capture_canonical(
        source,
        staging.path(),
        &settings,
        &[restore_archive::SnapshottedTree::SshdConfig],
    )
    .unwrap();
    authenticate(captured)
}

fn authenticate(mut captured: restore_archive::CapturedArchive) -> ValidatedRestore {
    let staging = tempdir().unwrap();
    let mut ciphertext = Vec::new();
    let secret = prepare_capsule(
        "0.3.0-raw.13",
        captured.size(),
        &mut captured,
        &mut ciphertext,
    )
    .unwrap();
    let plaintext = open_capsule(&secret, &mut Cursor::new(ciphertext), staging.path()).unwrap();
    restore_archive::validate(plaintext).unwrap()
}

fn fixture(config: &[u8]) -> Vec<File> {
    vec![
        File {
            path: MAIN.to_string(),
            bytes: Zeroizing::new(config.to_vec()),
        },
        File {
            path: HOST_KEYS[2].to_string(),
            bytes: Zeroizing::new(b"synthetic guard fixture, not a valid private key".to_vec()),
        },
    ]
}

#[test]
fn shipped_ssh_config_is_supported_without_rewriting_root_password_policy() {
    let files = fixture(include_bytes!(
        "../../../buildroot-external/hardened-sg2002/board/sg2002/overlay/etc/ssh/sshd_config"
    ));
    check(&files, true).unwrap();
}

#[test]
fn path_authority_cannot_escape_to_p3_private_identity_or_unverified_commands() {
    for text in [
        "HostKey /data/.hardened-kvmcache/private-key",
        "HostDSAKey /data/media/key",
        "HostCertificate /data/media/cert.pub",
        "Include /data/media/*.conf",
        "Include /etc/ssh/sshd_config.d/../../data/x.conf",
        "AuthorizedKeysFile /data/media/authorized_keys",
        "AuthorizedKeysFile %h/../../data/key",
        "AuthorizedKeysFile ~other/.ssh/authorized_keys",
        "Banner /etc/ssh/ssh_host_ed25519_key",
        "Banner /etc/kvm/session_secret",
        "TrustedUserCAKeys /data/media/ca.pub",
        "RevokedKeys /data/media/revoked",
        "AuthorizedPrincipalsFile /data/principals",
        "AuthorizedKeysCommand /data/helper",
        "AuthorizedPrincipalsCommand /bin/sh -c bad",
        "HostKeyAgent /tmp/agent.sock",
        "HostKeyAgent SSH_AUTH_SOCK",
        "SecurityKeyProvider /data/provider.so",
        "PidFile /etc/shadow",
        "SshdSessionPath /data/session",
        "SshdAuthPath /data/auth",
        "XAuthLocation /data/xauth",
        "Subsystem sftp /bin/sh -c bad",
        "Subsystem other internal-sftp",
        "ForceCommand /bin/sh -c bad",
        "ChrootDirectory /data/jail",
        "PermitUserEnvironment yes",
        "UsePAM yes",
        "FutureExecutableHook /data/helper",
    ] {
        assert!(
            check(&fixture(text.as_bytes()), true).is_err(),
            "unsafe synthetic authority was accepted"
        );
    }
}

#[test]
fn all_match_and_include_file_branches_are_checked_not_just_current_effective_values() {
    let mut files = fixture(
        b"Include sshd_config.d/*.conf\nMatch User nobody\n AuthorizedKeysCommand /data/helper\n",
    );
    assert!(check(&files, true).is_err());
    files[0].bytes = Zeroizing::new(b"Include /etc/ssh/sshd_config.d/*.conf\n".to_vec());
    files.push(File {
        path: "etc/ssh/sshd_config.d/conditional.conf".into(),
        bytes: Zeroizing::new(b"Match Address 192.0.2.1\n HostKeyAgent /tmp/agent\n".to_vec()),
    });
    assert!(check(&files, true).is_err());
}

#[test]
fn safe_paths_relative_includes_and_internal_sftp_arguments_remain_supported() {
    let config = b"Include sshd_config.d/[a-z]*.conf\nHostKey /etc/ssh/ssh_host_ed25519_key\nAuthorizedKeysFile .ssh/authorized_keys %h/.ssh/authorized_keys2\nHostKeyAgent none\nSecurityKeyProvider internal\nPidFile /run/sshd.pid\nSshdSessionPath /usr/libexec/sshd-session\nSshdAuthPath /usr/libexec/sshd-auth\nXAuthLocation /usr/bin/xauth\nAuthorizedKeysCommand none\nAuthorizedPrincipalsCommand none\nChrootDirectory none\nPermitUserEnvironment no\nSubsystem sftp internal-sftp -u 077 -d /data/media -R\nMatch User operator\n ForceCommand internal-sftp -R\n";
    check(&fixture(config), true).unwrap();
}

#[test]
fn host_key_presence_respects_disabled_ssh_but_never_proves_key_syntax() {
    let mut files = fixture(b"");
    check(&files, true).unwrap();
    files.pop();
    check(&files, false).unwrap();
    assert!(check(&files, true).is_err());
    assert!(check(&[], false).is_err());
}

#[test]
fn role_binding_prevents_banner_from_disclosing_other_captured_secrets() {
    let mut files =
        fixture(b"Banner /etc/ssh/banner\nTrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pub\n");
    assert!(check(&files, true).is_err());
    for path in ["etc/ssh/banner", "etc/ssh/trusted-user-ca-keys.pub"] {
        files.push(File {
            path: path.into(),
            bytes: Zeroizing::new(Vec::new()),
        });
    }
    check(&files, true).unwrap();
    files[0].bytes = Zeroizing::new(b"Banner /etc/ssh/ssh_host_ed25519_key\n".to_vec());
    assert!(check(&files, true).is_err());
}

#[test]
fn quotes_escapes_equals_and_comments_cannot_hide_authority() {
    for text in [
        "hostkey=/data/key",
        "HOSTKEY = '/data/key' # comment",
        "Ho\"stKey\" /data/key",
        "\"HostKey\" /data/key",
        "HostKey /data/ke\"y\"",
        "HostKey \\/data/key",
        "=HostKey /data/key",
        "Include \"/data/*.conf\"",
        "ForceCommand int\"ernal\"-sftp -R",
        "ForceCommand n\"one\"",
        "Subsystem sftp /usr/libexec/sftp-server -d /tmp;bad",
    ] {
        assert!(check(&fixture(text.as_bytes()), true).is_err());
    }
    for text in [
        "HostKey=\"/etc/ssh/ssh_host_ed25519_key\" # comment",
        "Ho\"stKey\" '/etc/ssh/ssh_host_ed25519_key'",
        "HostKey /etc/ssh/ssh_host_\"ed25519\"_key",
        "VersionAddendum quoted\\ value\n",
        "# HostKey /data/key\n",
    ] {
        check(&fixture(text.as_bytes()), true).unwrap();
    }
}

#[test]
fn lexical_arguments_match_pinned_openssh_argv_split_rules() {
    let line = lexer::parse(
        b"SetEnv A='quoted value' B=literal#hash C=escaped\\ space D=\"one\\'two\" # end",
    )
    .unwrap()
    .unwrap();
    assert_eq!(line.len(), 4);
    assert_eq!(line.arg(0), Some("A=quoted value"));
    assert_eq!(line.arg(1), Some("B=literal#hash"));
    assert_eq!(line.arg(2), Some("C=escaped space"));
    assert_eq!(line.arg(3), Some("D=one'two"));
    assert!(lexer::parse(b"HostKey '/etc/ssh/unterminated").is_err());
    assert!(lexer::parse(b"HostKey /etc/ssh/key\0ignored").is_err());
}

#[test]
fn unknown_directives_limits_and_errors_fail_closed_without_config_disclosure() {
    let error = check(&fixture(b"FutureHook synthetic-secret-marker\n"), true)
        .err()
        .unwrap();
    assert!(!format!("{error:?} {error}").contains("synthetic-secret-marker"));
    assert!(lexer::parse(&vec![b'x'; 8193]).is_err());
    let line = format!("AuthorizedKeysFile {}", "none ".repeat(129));
    assert!(lexer::parse(line.as_bytes()).is_err());
    let mut names = BTreeSet::new();
    for (list, _) in policy::RULES {
        for name in *list {
            assert!(names.insert(*name), "duplicate directive classification");
        }
    }
}

#[test]
fn checked_ssh_snapshot_never_rereads_live_bytes_or_imports_late_files() {
    let root = source_fixture();
    let fragment = "etc/ssh/sshd_config.d/operator.conf";
    put(root.path(), fragment, b"PasswordAuthentication yes\n");
    let source = SourceRoot::open(root.path()).unwrap();
    let mut snapshot = Snapshot::capture(&source).unwrap();
    put(root.path(), MAIN, b"HostKeyAgent /data/late-agent\n");
    put(root.path(), HOST_KEYS[2], b"late unchecked key bytes");
    put(root.path(), fragment, b"Banner /etc/shadow\n");
    put(
        root.path(),
        "etc/ssh/sshd_config.d/late.conf",
        b"Include /data/*.conf\n",
    );
    put(root.path(), "etc/ssh/banner", b"late unchecked banner");
    let mut archive = archive_snapshot(&source, &mut snapshot);
    check_archive(&mut archive).unwrap();
    for (path, expected) in [
        (MAIN, &b"Include sshd_config.d/*.conf\n"[..]),
        (HOST_KEYS[2], &b"synthetic key, presence only"[..]),
        (fragment, &b"PasswordAuthentication yes\n"[..]),
    ] {
        let indexes: Vec<_> = archive
            .members()
            .iter()
            .enumerate()
            .filter_map(|(i, member)| (member.path == path).then_some(i))
            .collect();
        assert_eq!(indexes.len(), 1);
        let mut bytes = Vec::new();
        archive.copy_file(indexes[0], &mut bytes).unwrap();
        assert_eq!(bytes, expected);
    }
    assert!(
        !archive
            .members()
            .iter()
            .any(|m| m.path == "etc/ssh/banner" || m.path.ends_with("/late.conf"))
    );
}

#[test]
fn ssh_enablement_and_absence_are_pinned_with_the_keyless_disabled_snapshot() {
    let root = source_fixture();
    fs::remove_file(root.path().join(HOST_KEYS[2])).unwrap();
    put(root.path(), "etc/kvm/ssh_stop", b"");
    let source = SourceRoot::open(root.path()).unwrap();
    let mut snapshot = Snapshot::capture(&source).unwrap();
    fs::remove_file(root.path().join("etc/kvm/ssh_stop")).unwrap();
    put(root.path(), "boot/start_ssh_once", b"");
    put(root.path(), HOST_KEYS[2], b"late key must not be restored");
    let mut archive = archive_snapshot(&source, &mut snapshot);
    check_archive(&mut archive).unwrap();
    for (path, action) in [
        ("etc/kvm/ssh_stop", RestoreAction::Write),
        ("boot/start_ssh_once", RestoreAction::Absent),
    ] {
        assert_eq!(
            archive
                .members()
                .iter()
                .find(|m| m.path == path)
                .unwrap()
                .action,
            action
        );
    }
    assert!(
        !archive
            .members()
            .iter()
            .any(|m| HOST_KEYS.contains(&m.path.as_str()))
    );
}

#[test]
fn match_criteria_are_closed_but_every_conditional_directive_is_still_checked() {
    for line in [
        "Match all\nPasswordAuthentication yes",
        "Match User=root Group root Address=192.0.2.0/24 LocalPort 22\nPasswordAuthentication yes",
        "Match invalid-user Host *.invalid LocalAddress 192.0.2.1 RDomain 0 Version OpenSSH_*\nPasswordAuthentication yes",
    ] {
        check(&fixture(line.as_bytes()), true).unwrap();
    }
    for line in [
        "Match all User root",
        "Match User",
        "Match User=",
        "Match exec /data/helper",
        "Match FutureCriterion yes",
    ] {
        assert!(check(&fixture(line.as_bytes()), true).is_err());
    }
    assert!(check(&fixture(b"Match User other\nBanner /etc/shadow\n"), true).is_err());
}

#[test]
fn authenticated_enablement_flags_obey_the_same_budget_as_source_capture() {
    let root = source_fixture();
    put(root.path(), "etc/kvm/ssh_stop", &vec![b'x'; MAX_DATA + 1]);
    let source = SourceRoot::open(root.path()).unwrap();
    assert!(Snapshot::capture(&source).is_err());
    let staging = tempdir().unwrap();
    let captured = restore_archive::capture_canonical(&source, staging.path(), &[], &[]).unwrap();
    let mut archive = authenticate(captured);
    assert!(matches!(
        check_archive(&mut archive),
        Err(SshRestoreError::Limit)
    ));
}
