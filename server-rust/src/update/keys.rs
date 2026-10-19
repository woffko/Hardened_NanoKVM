use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{AppError, Result, update::state_writers::StateWriters};

pub const LEGACY_UPDATE_KEY_ID: &str = "hardened-system-dev";
pub const LEGACY_TEST_UPDATE_KEY_ID: &str = "hardened-system-test";
const UPDATE_KEYRING_DIR: &str = "update-keys";
const UPDATE_KEY_POLICY_FILE: &str = "update-key-policy";
const LEGACY_UPDATE_PUBLIC_KEY_FILE: &str = "system-update-signing.pub.pem";
const UPDATE_PUBLIC_KEY_SUFFIX: &str = ".pub.pem";
const MAX_UPDATE_KEY_ID_BYTES: usize = 128;
const MAX_UPDATE_KEY_POLICY_BYTES: u64 = 16 * 1024;
const MAX_UPDATE_PUBLIC_KEY_BYTES: u64 = 64 * 1024;
const MAX_BUNDLED_UPDATE_KEYS: usize = 64;
static TRUST_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn install_bundled_update_trust(
    writers: &StateWriters,
    bundled_root: &Path,
    configured_key: &Path,
) -> Result<usize> {
    // Enroll before reading the bundle and retain admission through policy-last
    // publication. An app install freeze must exclude this startup writer too.
    let _permit = writers.configuration()?;
    let bundled_metadata = match fs::symlink_metadata(bundled_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    require_secure_directory(bundled_root, &bundled_metadata)?;

    let runtime_root = configured_key.parent().ok_or_else(|| {
        AppError::Config("system update public key path has no parent".to_string())
    })?;
    let legacy_source = bundled_root.join(LEGACY_UPDATE_PUBLIC_KEY_FILE);
    let legacy_bytes = read_bounded_regular_file(
        &legacy_source,
        MAX_UPDATE_PUBLIC_KEY_BYTES,
        "bundled legacy update public key",
    )?;
    let policy_source = bundled_root.join(UPDATE_KEY_POLICY_FILE);
    let policy_bytes = read_bounded_regular_file(
        &policy_source,
        MAX_UPDATE_KEY_POLICY_BYTES,
        "bundled update key policy",
    )?;
    let policy_text = std::str::from_utf8(&policy_bytes)
        .map_err(|_| AppError::Config("update key policy is not UTF-8".to_string()))?;
    let allowed = parse_update_key_policy(policy_text)?;

    let bundled_keyring = bundled_root.join(UPDATE_KEYRING_DIR);
    let keyring_metadata = fs::symlink_metadata(&bundled_keyring).map_err(|error| {
        AppError::Config(format!(
            "bundled update keyring is unavailable: {}: {error}",
            bundled_keyring.display()
        ))
    })?;
    require_secure_directory(&bundled_keyring, &keyring_metadata)?;

    let mut bundled_keys = BTreeMap::new();
    for entry in fs::read_dir(&bundled_keyring)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            AppError::Config("bundled update key filename is not UTF-8".to_string())
        })?;
        let Some(key_id) = name.strip_suffix(UPDATE_PUBLIC_KEY_SUFFIX) else {
            continue;
        };
        validate_update_key_id(key_id)?;
        if bundled_keys.len() >= MAX_BUNDLED_UPDATE_KEYS {
            return Err(AppError::Config(
                "bundled update keyring contains too many public keys".to_string(),
            ));
        }
        let bytes = read_bounded_regular_file(
            &entry.path(),
            MAX_UPDATE_PUBLIC_KEY_BYTES,
            "bundled update public key",
        )?;
        bundled_keys.insert(key_id.to_string(), bytes);
    }

    for key_id in &allowed {
        if matches!(
            key_id.as_str(),
            LEGACY_UPDATE_KEY_ID | LEGACY_TEST_UPDATE_KEY_ID
        ) {
            continue;
        }
        if !bundled_keys.contains_key(key_id) {
            return Err(AppError::Config(format!(
                "update key policy references a missing bundled public key: {key_id}"
            )));
        }
    }

    ensure_secure_runtime_directory(runtime_root)?;
    let runtime_keyring = runtime_root.join(UPDATE_KEYRING_DIR);
    ensure_secure_runtime_directory(&runtime_keyring)?;
    let runtime_policy = runtime_root.join(UPDATE_KEY_POLICY_FILE);

    validate_replaceable_destination(configured_key)?;
    for key_id in &allowed {
        if matches!(
            key_id.as_str(),
            LEGACY_UPDATE_KEY_ID | LEGACY_TEST_UPDATE_KEY_ID
        ) {
            continue;
        }
        validate_replaceable_destination(
            &runtime_keyring.join(format!("{key_id}{UPDATE_PUBLIC_KEY_SUFFIX}")),
        )?;
    }
    validate_replaceable_destination(&runtime_policy)?;

    let mut changed = usize::from(atomic_install_file(configured_key, &legacy_bytes, 0o644)?);
    for key_id in &allowed {
        if matches!(
            key_id.as_str(),
            LEGACY_UPDATE_KEY_ID | LEGACY_TEST_UPDATE_KEY_ID
        ) {
            continue;
        }
        let destination = runtime_keyring.join(format!("{key_id}{UPDATE_PUBLIC_KEY_SUFFIX}"));
        changed += usize::from(atomic_install_file(
            &destination,
            &bundled_keys[key_id],
            0o644,
        )?);
    }
    // Publish the allowlist last so it can never reference a key that has not
    // already reached its final on-disk location.
    changed += usize::from(atomic_install_file(&runtime_policy, &policy_bytes, 0o644)?);
    Ok(changed)
}

pub fn resolve_update_public_key(configured_key: &Path, key_id: &str) -> Result<PathBuf> {
    validate_update_key_id(key_id)?;

    let parent = configured_key.parent().ok_or_else(|| {
        AppError::Config("system update public key path has no parent".to_string())
    })?;
    enforce_update_key_policy(parent, key_id)?;

    if matches!(key_id, LEGACY_UPDATE_KEY_ID | LEGACY_TEST_UPDATE_KEY_ID) {
        return require_public_key(configured_key.to_path_buf(), key_id);
    }

    let keyring = parent.join(UPDATE_KEYRING_DIR);
    let candidate = keyring.join(format!("{key_id}{UPDATE_PUBLIC_KEY_SUFFIX}"));
    if !candidate.starts_with(&keyring) {
        return Err(AppError::Config(
            "update public key path escapes keyring".to_string(),
        ));
    }
    require_public_key(candidate, key_id)
}

fn require_public_key(path: PathBuf, key_id: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(&path).map_err(|_| {
        AppError::Config(format!(
            "update public key is not configured for key id {key_id}: {}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(AppError::Config(format!(
            "update public key must be a regular, non-writable-by-group-or-other file for key id {key_id}: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn validate_update_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty()
        || key_id.len() > MAX_UPDATE_KEY_ID_BYTES
        || key_id.starts_with('.')
        || key_id.ends_with('.')
        || key_id.contains("..")
        || !key_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+'))
    {
        return Err(AppError::BadRequest(
            "invalid update signature key id".to_string(),
        ));
    }
    Ok(())
}

fn enforce_update_key_policy(parent: &Path, key_id: &str) -> Result<()> {
    let path = parent.join(UPDATE_KEY_POLICY_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(AppError::Config(format!(
            "update key policy must be a regular, non-writable-by-group-or-other file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_UPDATE_KEY_POLICY_BYTES {
        return Err(AppError::Config(
            "update key policy is too large".to_string(),
        ));
    }

    let content = fs::read_to_string(&path)?;
    let allowed = parse_update_key_policy(&content)?;
    if !allowed.contains(key_id) {
        return Err(AppError::BadRequest(format!(
            "update signature key id is not allowed by policy: {key_id}"
        )));
    }
    Ok(())
}

fn parse_update_key_policy(content: &str) -> Result<BTreeSet<String>> {
    let mut allowed = BTreeSet::new();
    for line in content.lines() {
        let candidate = line.trim();
        if candidate.is_empty() || candidate.starts_with('#') {
            continue;
        }
        if validate_update_key_id(candidate).is_err() {
            return Err(AppError::Config(format!(
                "invalid key id in update key policy: {candidate}"
            )));
        }
        allowed.insert(candidate.to_string());
    }
    if allowed.is_empty() {
        return Err(AppError::Config(
            "update key policy contains no allowed key ids".to_string(),
        ));
    }
    Ok(allowed)
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64, description: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::Config(format!(
            "{description} is unavailable: {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(AppError::Config(format!(
            "{description} must be a regular, non-writable-by-group-or-other file: {}",
            path.display()
        )));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(AppError::Config(format!(
            "{description} has an invalid size: {}",
            path.display()
        )));
    }
    Ok(fs::read(path)?)
}

fn require_secure_directory(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(AppError::Config(format!(
            "update trust directory must be a directory that is not writable by group or other: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_secure_runtime_directory(path: &Path) -> Result<()> {
    let created = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            require_secure_directory(path, &metadata)?;
            false
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            fs::create_dir(path)?;
            true
        }
        Err(error) => return Err(error.into()),
    };
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    sync_directory(path)?;
    if created && let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn validate_replaceable_destination(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(AppError::Config(format!(
            "update trust destination is not replaceable: {}",
            path.display()
        ))),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn atomic_install_file(path: &Path, bytes: &[u8], mode: u32) -> Result<bool> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_file()
        && fs::read(path)? == bytes
    {
        let current_mode = metadata.permissions().mode() & 0o7777;
        if current_mode == mode {
            return Ok(false);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        File::open(path)?.sync_all()?;
        sync_directory(path.parent().ok_or_else(|| {
            AppError::Config("update trust destination has no parent".to_string())
        })?)?;
        return Ok(true);
    }

    let parent = path
        .parent()
        .ok_or_else(|| AppError::Config("update trust destination has no parent".to_string()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            AppError::Config("update trust destination has an invalid filename".to_string())
        })?;
    let mut temp_path = None;
    let mut temp_file = None;
    for _ in 0..32 {
        let counter = TRUST_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{file_name}.nanokvm-trust-{}-{counter}.tmp",
            process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => {
                temp_path = Some(candidate);
                temp_file = Some(file);
                break;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let temp_path = temp_path.ok_or_else(|| {
        AppError::Config("could not allocate a temporary update trust file".to_string())
    })?;
    let mut temp_file = temp_file.expect("temporary path and file are created together");
    let install_result = (|| -> std::io::Result<()> {
        temp_file.write_all(bytes)?;
        temp_file.set_permissions(fs::Permissions::from_mode(mode))?;
        temp_file.sync_all()?;
        drop(temp_file);
        fs::rename(&temp_path, path)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if install_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    install_result?;
    Ok(true)
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn write_bundled_trust(root: &Path, policy: &[u8]) {
        fs::create_dir_all(root.join(UPDATE_KEYRING_DIR)).unwrap();
        fs::write(root.join(LEGACY_UPDATE_PUBLIC_KEY_FILE), b"legacy").unwrap();
        fs::write(
            root.join(UPDATE_KEYRING_DIR)
                .join("hardened-system-prod-2026.pub.pem"),
            b"production",
        )
        .unwrap();
        fs::write(
            root.join(UPDATE_KEYRING_DIR).join("unused-key.pub.pem"),
            b"unused",
        )
        .unwrap();
        fs::write(root.join(UPDATE_KEY_POLICY_FILE), policy).unwrap();
    }

    #[test]
    fn resolves_legacy_and_keyring_public_keys_by_id() {
        let temp = tempfile::tempdir().unwrap();
        let configured = temp.path().join("system-update-signing.pub.pem");
        std::fs::write(&configured, b"legacy").unwrap();
        let keyring = temp.path().join(UPDATE_KEYRING_DIR);
        std::fs::create_dir_all(&keyring).unwrap();
        let production = keyring.join("hardened-system-prod-2026.pub.pem");
        std::fs::write(&production, b"production").unwrap();

        assert_eq!(
            resolve_update_public_key(&configured, LEGACY_UPDATE_KEY_ID).unwrap(),
            configured
        );
        assert_eq!(
            resolve_update_public_key(&configured, LEGACY_TEST_UPDATE_KEY_ID).unwrap(),
            configured
        );
        assert_eq!(
            resolve_update_public_key(&configured, "hardened-system-prod-2026").unwrap(),
            production
        );
    }

    #[test]
    fn rejects_unknown_or_unsafe_update_key_ids() {
        let temp = tempfile::tempdir().unwrap();
        let configured = temp.path().join("system-update-signing.pub.pem");
        std::fs::write(&configured, b"legacy").unwrap();

        assert!(resolve_update_public_key(&configured, "unknown-key").is_err());
        assert!(resolve_update_public_key(&configured, "../key").is_err());
        assert!(resolve_update_public_key(&configured, "bad/key").is_err());
        assert!(resolve_update_public_key(&configured, &"a".repeat(129)).is_err());
    }

    #[test]
    fn policy_can_disable_the_legacy_key_after_rotation() {
        let temp = tempfile::tempdir().unwrap();
        let configured = temp.path().join("system-update-signing.pub.pem");
        std::fs::write(&configured, b"legacy").unwrap();
        let keyring = temp.path().join(UPDATE_KEYRING_DIR);
        std::fs::create_dir_all(&keyring).unwrap();
        let production = keyring.join("hardened-system-prod-2026.pub.pem");
        std::fs::write(&production, b"production").unwrap();
        std::fs::write(
            temp.path().join(UPDATE_KEY_POLICY_FILE),
            b"# production trust set\nhardened-system-prod-2026\n",
        )
        .unwrap();

        assert_eq!(
            resolve_update_public_key(&configured, "hardened-system-prod-2026").unwrap(),
            production
        );
        assert!(resolve_update_public_key(&configured, LEGACY_UPDATE_KEY_ID).is_err());
        assert!(resolve_update_public_key(&configured, LEGACY_TEST_UPDATE_KEY_ID).is_err());
    }

    #[test]
    fn rejects_empty_or_malformed_key_policy() {
        let temp = tempfile::tempdir().unwrap();
        let configured = temp.path().join("system-update-signing.pub.pem");
        std::fs::write(&configured, b"legacy").unwrap();
        let policy = temp.path().join(UPDATE_KEY_POLICY_FILE);

        std::fs::write(&policy, b"# no active keys\n").unwrap();
        assert!(resolve_update_public_key(&configured, LEGACY_UPDATE_KEY_ID).is_err());

        std::fs::write(&policy, b"../unsafe\n").unwrap();
        assert!(resolve_update_public_key(&configured, LEGACY_UPDATE_KEY_ID).is_err());
    }

    #[test]
    fn installs_bundled_update_trust_atomically_and_idempotently() {
        let temp = tempfile::tempdir().unwrap();
        let writers = StateWriters::for_test_parent(File::open(temp.path()).unwrap());
        let bundled = temp.path().join("bundled");
        let runtime = temp.path().join("runtime");
        write_bundled_trust(
            &bundled,
            b"hardened-system-dev\nhardened-system-test\nhardened-system-prod-2026\n",
        );
        fs::create_dir(&runtime).unwrap();
        let configured = runtime.join(LEGACY_UPDATE_PUBLIC_KEY_FILE);

        assert_eq!(
            install_bundled_update_trust(&writers, &bundled, &configured).unwrap(),
            3
        );
        assert_eq!(fs::read(&configured).unwrap(), b"legacy");
        let production = runtime
            .join(UPDATE_KEYRING_DIR)
            .join("hardened-system-prod-2026.pub.pem");
        assert_eq!(fs::read(&production).unwrap(), b"production");
        assert_eq!(
            fs::read(runtime.join(UPDATE_KEY_POLICY_FILE)).unwrap(),
            b"hardened-system-dev\nhardened-system-test\nhardened-system-prod-2026\n"
        );
        assert!(
            !runtime
                .join(UPDATE_KEYRING_DIR)
                .join("unused-key.pub.pem")
                .exists()
        );
        assert_eq!(
            fs::metadata(&production).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            install_bundled_update_trust(&writers, &bundled, &configured).unwrap(),
            0
        );

        fs::set_permissions(&production, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            install_bundled_update_trust(&writers, &bundled, &configured).unwrap(),
            1
        );
        assert_eq!(
            fs::metadata(&production).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn validates_policy_and_sources_before_installing_trust() {
        let temp = tempfile::tempdir().unwrap();
        let writers = StateWriters::for_test_parent(File::open(temp.path()).unwrap());
        let bundled = temp.path().join("bundled");
        let runtime = temp.path().join("runtime");
        write_bundled_trust(&bundled, b"missing-production-key\n");
        fs::create_dir(&runtime).unwrap();
        let configured = runtime.join(LEGACY_UPDATE_PUBLIC_KEY_FILE);
        fs::write(&configured, b"existing-legacy").unwrap();

        assert!(install_bundled_update_trust(&writers, &bundled, &configured).is_err());
        assert_eq!(fs::read(&configured).unwrap(), b"existing-legacy");
        assert!(!runtime.join(UPDATE_KEY_POLICY_FILE).exists());
    }

    #[test]
    fn rejects_symlinked_bundled_keys_without_mutating_runtime() {
        let temp = tempfile::tempdir().unwrap();
        let writers = StateWriters::for_test_parent(File::open(temp.path()).unwrap());
        let bundled = temp.path().join("bundled");
        let runtime = temp.path().join("runtime");
        write_bundled_trust(&bundled, b"hardened-system-prod-2026\n");
        let production = bundled
            .join(UPDATE_KEYRING_DIR)
            .join("hardened-system-prod-2026.pub.pem");
        fs::remove_file(&production).unwrap();
        fs::write(temp.path().join("outside-key"), b"outside").unwrap();
        symlink(temp.path().join("outside-key"), &production).unwrap();
        fs::create_dir(&runtime).unwrap();
        let configured = runtime.join(LEGACY_UPDATE_PUBLIC_KEY_FILE);

        assert!(install_bundled_update_trust(&writers, &bundled, &configured).is_err());
        assert!(!configured.exists());
        assert!(!runtime.join(UPDATE_KEY_POLICY_FILE).exists());
    }

    #[test]
    fn atomically_replaces_destination_symlink_without_touching_referent() {
        let temp = tempfile::tempdir().unwrap();
        let writers = StateWriters::for_test_parent(File::open(temp.path()).unwrap());
        let bundled = temp.path().join("bundled");
        let runtime = temp.path().join("runtime");
        write_bundled_trust(&bundled, b"hardened-system-prod-2026\n");
        fs::create_dir(&runtime).unwrap();
        fs::create_dir(runtime.join(UPDATE_KEYRING_DIR)).unwrap();
        let sensitive = temp.path().join("sensitive");
        fs::write(&sensitive, b"do-not-touch").unwrap();
        let destination = runtime
            .join(UPDATE_KEYRING_DIR)
            .join("hardened-system-prod-2026.pub.pem");
        symlink(&sensitive, &destination).unwrap();
        let configured = runtime.join(LEGACY_UPDATE_PUBLIC_KEY_FILE);

        install_bundled_update_trust(&writers, &bundled, &configured).unwrap();
        assert_eq!(fs::read(&sensitive).unwrap(), b"do-not-touch");
        assert!(
            fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_file()
        );
        assert_eq!(fs::read(&destination).unwrap(), b"production");
    }

    #[tokio::test]
    async fn trust_publication_obeys_configuration_serialization_and_install_freeze() {
        use std::time::Duration;
        let temp = tempfile::tempdir().unwrap();
        let writers = StateWriters::for_test_parent(File::open(temp.path()).unwrap());
        // A separate instance opens the same kernel lock namespace, as another
        // backend startup would. No in-process mutex is the safety boundary.
        let startup = StateWriters::for_test_parent(File::open(temp.path()).unwrap());
        let bundled = temp.path().join("bundled");
        let runtime = temp.path().join("runtime");
        write_bundled_trust(&bundled, b"hardened-system-prod-2026\n");
        let configured = runtime.join(LEGACY_UPDATE_PUBLIC_KEY_FILE);
        let permit = writers.configuration().unwrap();
        assert!(matches!(
            install_bundled_update_trust(&startup, &bundled, &configured),
            Err(AppError::Conflict(_))
        ));
        assert!(!runtime.exists());
        drop(permit);
        let freeze = writers.drain(Duration::from_secs(5)).await.unwrap();
        assert!(matches!(
            install_bundled_update_trust(&startup, &bundled, &configured),
            Err(AppError::Conflict(_))
        ));
        // Even an absent bundle is checked only AFTER writer admission: no
        // success result may masquerade as publication under a live freeze.
        assert!(matches!(
            install_bundled_update_trust(&startup, &temp.path().join("absent"), &configured),
            Err(AppError::Conflict(_))
        ));
        assert!(!runtime.exists());
        drop(freeze);
        assert_eq!(
            install_bundled_update_trust(&startup, &bundled, &configured).unwrap(),
            3
        );
        assert_eq!(fs::read(&configured).unwrap(), b"legacy");
        drop(writers.drain(Duration::from_secs(5)).await.unwrap());
    }
}
