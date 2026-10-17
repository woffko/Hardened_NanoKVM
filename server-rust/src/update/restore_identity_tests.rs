use super::*;
use crate::update::{
    restore_capsule::{open_capsule, prepare_capsule},
    restore_policy,
};
use std::{
    fs,
    io::{Cursor, Read},
    os::unix::fs::symlink,
};
use tar::{Archive, Builder};
use tempfile::{TempDir, tempdir};

const CONFIG_PATH: &str = "/etc/kvm/server.yaml";
const CWD: &str = "/etc/kvm";

fn put(root: &Path, path: &str, bytes: &[u8]) {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}
fn write_config(root: &Path, path: &str, config: &Config) {
    put(
        root,
        path,
        serde_yaml::to_string(config).unwrap().as_bytes(),
    );
}
fn fixture() -> (TempDir, Config) {
    let root = tempdir().unwrap();
    for path in restore_policy::REQUIRED {
        put(root.path(), path, b"synthetic OS identity\n");
    }
    let account = Account {
        username: "operator".to_string(),
        password: bcrypt::hash("synthetic fixture password", 4).unwrap(),
    };
    put(root.path(), ACCOUNT, &serde_json::to_vec(&account).unwrap());
    let mut config = Config::default();
    config.jwt.secret_key = "synthetic runtime key, not a credential".to_string();
    write_config(root.path(), CONFIG_PATH, &config);
    (root, config)
}
fn captured(root: &Path, config: &Config, cwd: &str, config_path: &str) -> Vec<u8> {
    let staging = tempdir().unwrap();
    let mut archive = capture_effective(
        root,
        staging.path(),
        config,
        Path::new(cwd),
        Path::new(config_path),
    )
    .unwrap();
    let mut bytes = Vec::new();
    archive.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.len() as u64, archive.size());
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    bytes
}
fn checked(bytes: &[u8]) -> Result<IdentityCheckedRestore> {
    let staging = tempdir().unwrap();
    let mut ciphertext = Vec::new();
    let secret = prepare_capsule(
        "0.3.0-raw.13",
        bytes.len() as u64,
        &mut Cursor::new(bytes),
        &mut ciphertext,
    )
    .unwrap();
    let plaintext = open_capsule(&secret, &mut Cursor::new(ciphertext), staging.path()).unwrap();
    check_identity(restore_archive::validate(plaintext).unwrap())
}
fn member(archive: &mut IdentityCheckedRestore, path: &str) -> Vec<u8> {
    let index = archive
        .members()
        .iter()
        .position(|m| m.path == path)
        .unwrap();
    let mut bytes = Vec::new();
    archive.copy_file(index, &mut bytes).unwrap();
    bytes
}
fn alter(bytes: &[u8], path: &str, replacement: Option<&[u8]>) -> Vec<u8> {
    let mut result = Vec::new();
    {
        let mut out = Builder::new(&mut result);
        let mut archive = Archive::new(Cursor::new(bytes));
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            let mut header = entry.header().clone();
            if header.path_bytes() == format!("files/{path}").as_bytes() {
                let Some(replacement) = replacement else {
                    continue;
                };
                data = replacement.to_vec();
                header.set_size(data.len() as u64);
                header.set_cksum();
            }
            out.append(&header, &data[..]).unwrap();
        }
        out.finish().unwrap();
    }
    result
}

#[test]
fn absent_optional_config_uses_defaults_and_existing_effective_file_secret() {
    let (root, config) = fixture();
    fs::remove_file(root.path().join(CONFIG)).unwrap();
    put(
        root.path(),
        SESSION,
        format!("{}\n", config.jwt.secret_key).as_bytes(),
    );
    let original = fs::read(root.path().join(ACCOUNT)).unwrap();
    let mut restored = checked(&captured(root.path(), &config, CWD, CONFIG_PATH)).unwrap();
    let canonical: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(canonical.proto, "http");
    assert_eq!(canonical.jwt.secret_key, config.jwt.secret_key);
    assert_eq!(canonical.cert.crt, "/etc/kvm/server.crt");
    assert_eq!(member(&mut restored, ACCOUNT), original);
    assert!(!root.path().join(CONFIG).exists());
    assert_eq!(fs::read(root.path().join(ACCOUNT)).unwrap(), original);
}

#[test]
fn embedded_whitespace_key_without_session_file_is_preserved_verbatim() {
    let (root, mut config) = fixture();
    config.jwt.secret_key = "  synthetic\tkey\nwith trailing whitespace  ".to_string();
    write_config(root.path(), CONFIG_PATH, &config);
    assert!(!root.path().join(SESSION).exists());
    let mut restored = checked(&captured(root.path(), &config, CWD, CONFIG_PATH)).unwrap();
    let canonical: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(canonical.jwt.secret_key, config.jwt.secret_key);
    assert_eq!(
        member(&mut restored, SESSION),
        format!("{}\n", config.jwt.secret_key).as_bytes()
    );
}

#[test]
fn custom_config_account_secret_and_relative_tls_paths_become_canonical() {
    let (root, mut effective) = fixture();
    let account = fs::read(root.path().join(ACCOUNT)).unwrap();
    put(root.path(), "root/custom/account", &account);
    effective.paths.account_file = PathBuf::from("account");
    effective.paths.session_secret_file = PathBuf::from("secret");
    effective.cert.crt = "tls/certificate.pem".to_string();
    effective.cert.key = "tls/private.pem".to_string();
    effective.proto = "https".to_string();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["fixture.invalid".to_string()]).unwrap();
    put(
        root.path(),
        "root/custom/tls/certificate.pem",
        cert.pem().as_bytes(),
    );
    put(
        root.path(),
        "root/custom/tls/private.pem",
        key_pair.serialize_pem().as_bytes(),
    );
    put(
        root.path(),
        "root/custom/secret",
        format!("{}\n", effective.jwt.secret_key).as_bytes(),
    );
    let mut persisted = effective.clone();
    persisted.jwt.secret_key.clear();
    write_config(root.path(), "/root/custom/config.yaml", &persisted);
    put(root.path(), ACCOUNT, b"stale default account must not win");
    put(root.path(), KEY, b"stale default key must not win");
    let mut restored = checked(&captured(
        root.path(),
        &effective,
        "/root/custom",
        "/root/custom/config.yaml",
    ))
    .unwrap();
    let config: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(config.proto, "https");
    assert_eq!(config.paths.account_file, Path::new("/etc/kvm/pwd"));
    assert_eq!(
        config.paths.session_secret_file,
        Path::new("/etc/kvm/session_secret")
    );
    assert_eq!(member(&mut restored, ACCOUNT), account);
    assert_eq!(member(&mut restored, CERT), cert.pem().as_bytes());
    assert_eq!(
        member(&mut restored, KEY),
        key_pair.serialize_pem().as_bytes()
    );
    assert!(
        !restored
            .members()
            .iter()
            .any(|m| m.path.starts_with("root/custom/"))
    );
}

#[test]
fn newer_persisted_preferences_are_not_overwritten_by_startup_config() {
    let (root, effective) = fixture();
    let mut persisted = effective.clone();
    persisted.security.allow_raw_system_updates = true;
    persisted.security.allow_terminal = true;
    persisted.security.access_token_duration = 1800;
    persisted.host = "127.0.0.1".to_string();
    persisted.port.http = 8080;
    persisted.turn.turn_cred = "synthetic saved preference".to_string();
    write_config(root.path(), CONFIG_PATH, &persisted);
    let before = fs::read(root.path().join(CONFIG)).unwrap();
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let config: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(config.host, persisted.host);
    assert_eq!(config.port.http, 8080);
    assert!(config.security.allow_raw_system_updates && config.security.allow_terminal);
    assert_eq!(config.security.access_token_duration, 1800);
    assert_eq!(config.turn.turn_cred, persisted.turn.turn_cred);
    assert_eq!(fs::read(root.path().join(CONFIG)).unwrap(), before);
}

#[test]
fn valid_pending_tls_preferences_are_preserved_but_http_is_not_forced_to_https() {
    let (root, effective) = fixture();
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let unchanged: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(unchanged.proto, "http");
    assert!(
        !restored
            .members()
            .iter()
            .any(|m| m.path == CERT || m.path == KEY)
    );
    let pair = rcgen::generate_simple_self_signed(vec!["fixture.invalid".to_string()]).unwrap();
    let mut persisted = effective.clone();
    persisted.proto = "https".to_string();
    persisted.cert.crt = "/root/pending/certificate".to_string();
    persisted.cert.key = "/root/pending/key".to_string();
    put(
        root.path(),
        "root/pending/certificate",
        pair.cert.pem().as_bytes(),
    );
    put(
        root.path(),
        "root/pending/key",
        pair.key_pair.serialize_pem().as_bytes(),
    );
    write_config(root.path(), CONFIG_PATH, &persisted);
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let next_boot: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(next_boot.proto, "https");
    assert_eq!(member(&mut restored, CERT), pair.cert.pem().as_bytes());
}

#[test]
fn canonicalization_preserves_all_known_config_fields_except_fixed_paths_and_legacy_alias() {
    let (root, effective) = fixture();
    let mut persisted = effective.clone();
    persisted.authentication = "disable".to_string();
    persisted.security.allow_auth_disable = true;
    persisted.security.allowed_origins = vec!["https://fixture.invalid".to_string()];
    persisted.logger.level = "debug".to_string();
    persisted.logger.file = "stdout".to_string();
    persisted.stun = "stun:fixture.invalid:3478".to_string();
    persisted.turn.turn_user = "synthetic turn user".to_string();
    persisted.turn.turn_cred = "synthetic turn preference".to_string();
    persisted.compatibility_mode = true;
    write_config(root.path(), CONFIG_PATH, &persisted);
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let actual: serde_yaml::Value = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    persisted.cert.crt = "/etc/kvm/server.crt".to_string();
    persisted.cert.key = "/etc/kvm/server.key".to_string();
    let expected = serde_yaml::to_value(&persisted).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn legacy_embedded_key_and_media_alias_are_normalized_without_losing_secret() {
    let (root, effective) = fixture();
    put(
        root.path(),
        CONFIG,
        format!(
            "jwt:\n  secretKey: '{}'\npaths:\n  image_directory: /data\n",
            effective.jwt.secret_key
        )
        .as_bytes(),
    );
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let canonical: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(canonical.jwt.secret_key, effective.jwt.secret_key);
    assert!(canonical.jwt.secret_key_legacy.is_empty());
    assert_eq!(
        canonical.paths.image_directory,
        Paths::default().image_directory
    );
}

#[test]
fn maximum_file_secret_with_crlf_is_accepted_without_trimming_embedded_keys() {
    let (root, mut effective) = fixture();
    effective.jwt.secret_key = "s".repeat(MAX_SECRET);
    let mut persisted = effective.clone();
    persisted.jwt.secret_key.clear();
    write_config(root.path(), CONFIG_PATH, &persisted);
    put(
        root.path(),
        SESSION,
        format!("{}\r\n", effective.jwt.secret_key).as_bytes(),
    );
    let mut restored = checked(&captured(root.path(), &effective, CWD, CONFIG_PATH)).unwrap();
    let canonical: Config = serde_yaml::from_slice(&member(&mut restored, CONFIG)).unwrap();
    assert_eq!(canonical.jwt.secret_key, effective.jwt.secret_key);
}

#[test]
fn pending_identity_changes_fail_before_creating_any_capture_spool() {
    for kind in [0, 1, 2] {
        let (root, effective) = fixture();
        let staging = tempdir().unwrap();
        let mut persisted = effective.clone();
        match kind {
            0 => persisted.paths.account_file = PathBuf::from("/root/other-account"),
            1 => persisted.jwt.secret_key = "synthetic pending rotation".to_string(),
            _ => {
                persisted.jwt.secret_key.clear();
                put(root.path(), SESSION, b"synthetic mismatched file key\n");
            }
        }
        write_config(root.path(), CONFIG_PATH, &persisted);
        assert!(matches!(
            capture_effective(
                root.path(),
                staging.path(),
                &effective,
                Path::new(CWD),
                Path::new(CONFIG_PATH)
            ),
            Err(RestoreIdentityError::InvalidState)
        ));
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    }
}

#[test]
fn malformed_account_or_config_has_no_fallback_and_no_secret_in_error() {
    for path in [ACCOUNT, CONFIG] {
        let (root, config) = fixture();
        let staging = tempdir().unwrap();
        put(root.path(), path, b"synthetic-secret-marker: [malformed");
        let error = capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH),
        )
        .err()
        .unwrap();
        assert!(!format!("{error:?} {error}").contains("synthetic-secret-marker"));
        assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
    }
}

#[test]
fn invalid_account_hashes_and_missing_identity_are_not_restore_ready() {
    let (root, config) = fixture();
    let bytes = captured(root.path(), &config, CWD, CONFIG_PATH);
    for hash in [
        "plaintext is not a hash",
        "$2b$99$invalid",
        "$argon2id$v=19$m=0,t=0,p=0$salt$hash",
    ] {
        let account = serde_json::to_vec(&Account {
            username: "operator".to_string(),
            password: hash.to_string(),
        })
        .unwrap();
        assert!(checked(&alter(&bytes, ACCOUNT, Some(&account))).is_err());
    }
    assert!(checked(&alter(&bytes, CONFIG, None)).is_err());
    // Structural validation rejects missing/empty account and secret already.
    assert!(checked(&alter(&bytes, CERT, None)).is_ok());
}

#[test]
fn existing_argon2_hashes_are_preserved_without_rehashing() {
    let (root, config) = fixture();
    let account = Account {
        username: "operator".to_string(),
        password: crate::auth::password::hash_password("synthetic fixture password").unwrap(),
    };
    let bytes = serde_json::to_vec(&account).unwrap();
    put(root.path(), ACCOUNT, &bytes);
    let mut restored = checked(&captured(root.path(), &config, CWD, CONFIG_PATH)).unwrap();
    assert_eq!(member(&mut restored, ACCOUNT), bytes);
}

#[test]
fn https_missing_malformed_and_mismatched_keys_are_rejected() {
    let (root, mut config) = fixture();
    config.proto = "https".to_string();
    write_config(root.path(), CONFIG_PATH, &config);
    let staging = tempdir().unwrap();
    assert!(
        capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH)
        )
        .is_err()
    );
    put(root.path(), CERT, b"not a certificate");
    put(root.path(), KEY, b"not a private key");
    assert!(
        capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH)
        )
        .is_err()
    );
    let a = rcgen::generate_simple_self_signed(vec!["fixture.invalid".to_string()]).unwrap();
    let b = rcgen::generate_simple_self_signed(vec!["fixture.invalid".to_string()]).unwrap();
    put(root.path(), CERT, a.cert.pem().as_bytes());
    put(root.path(), KEY, b.key_pair.serialize_pem().as_bytes());
    assert!(
        capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH)
        )
        .is_err()
    );
    put(root.path(), KEY, a.key_pair.serialize_pem().as_bytes());
    let bytes = captured(root.path(), &config, CWD, CONFIG_PATH);
    assert!(
        checked(&alter(
            &bytes,
            KEY,
            Some(b.key_pair.serialize_pem().as_bytes())
        ))
        .is_err()
    );
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
}

#[test]
fn restored_config_cannot_redirect_identity_or_weaken_signed_layout() {
    let (root, config) = fixture();
    let bytes = captured(root.path(), &config, CWD, CONFIG_PATH);
    for kind in [0, 1, 2, 3] {
        let mut canonical = checked(&bytes).unwrap();
        let mut changed: Config = serde_yaml::from_slice(&member(&mut canonical, CONFIG)).unwrap();
        match kind {
            0 => changed.paths.account_file = PathBuf::from("/data/media/account"),
            1 => changed.paths.system_update_public_key = PathBuf::from("/data/key"),
            2 => changed.paths.image_directory = PathBuf::from("/"),
            _ => changed.jwt.secret_key = "synthetic replaced secret".to_string(),
        }
        assert!(
            checked(&alter(
                &bytes,
                CONFIG,
                Some(serde_yaml::to_string(&changed).unwrap().as_bytes())
            ))
            .is_err()
        );
    }
}

#[test]
fn custom_source_aliases_traversal_and_oversized_state_fail_closed() {
    let (root, mut config) = fixture();
    config.paths.account_file = PathBuf::from("/root/custom-account");
    write_config(root.path(), CONFIG_PATH, &config);
    fs::create_dir_all(root.path().join("root")).unwrap();
    symlink(
        root.path().join(ACCOUNT),
        root.path().join("root/custom-account"),
    )
    .unwrap();
    let staging = tempdir().unwrap();
    assert!(
        capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH)
        )
        .is_err()
    );
    fs::remove_file(root.path().join("root/custom-account")).unwrap();
    put(
        root.path(),
        "root/custom-account",
        &vec![b'a'; MAX_ACCOUNT + 1],
    );
    assert!(
        capture_effective(
            root.path(),
            staging.path(),
            &config,
            Path::new(CWD),
            Path::new(CONFIG_PATH)
        )
        .is_err()
    );
    assert!(source_path(Path::new("../account"), Path::new(CWD)).is_err());
    assert!(source_path(Path::new("account"), Path::new("relative-cwd")).is_err());
    assert!(source_path(Path::new(""), Path::new(CWD)).is_err());
    assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
}

#[test]
fn identity_resource_limits_and_secret_consistency_are_enforced() {
    let (root, config) = fixture();
    let bytes = captured(root.path(), &config, CWD, CONFIG_PATH);
    assert!(checked(&alter(&bytes, CONFIG, Some(&vec![b'a'; MAX_CONFIG + 1]))).is_err());
    assert!(
        checked(&alter(
            &bytes,
            SESSION,
            Some(b"synthetic different secret\n")
        ))
        .is_err()
    );
    let mut out = PrivateBuffer {
        bytes: Zeroizing::new(Vec::with_capacity(4)),
        limit: 4,
    };
    out.write_all(b"1234").unwrap();
    assert!(out.write_all(b"5").is_err());
    assert_eq!(&*out.bytes, b"1234");
}
