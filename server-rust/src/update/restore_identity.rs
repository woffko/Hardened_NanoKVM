//! Canonical effective app identity for an authenticated raw restore.

use std::{
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use argon2::{Algorithm, Params, PasswordHash, Version};
use base64::Engine as _;
use tokio_rustls::rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use zeroize::{Zeroize, Zeroizing};

use super::restore_archive::{
    self, CanonicalSetting, CapturedArchive, RestoreAction, RestoreArchiveError, SourceRoot,
    ValidatedRestore,
};
use crate::{
    auth::password::Account,
    config::{Config, Paths},
};

const CONFIG: &str = "etc/kvm/server.yaml";
const ACCOUNT: &str = "etc/kvm/pwd";
const SESSION: &str = "etc/kvm/session_secret";
const CERT: &str = "etc/kvm/server.crt";
const KEY: &str = "etc/kvm/server.key";
const MAX_CONFIG: usize = 64 * 1024;
const MAX_ACCOUNT: usize = 16 * 1024;
const MAX_SECRET: usize = 16 * 1024;
const MAX_CERT: usize = 256 * 1024;
const MAX_KEY: usize = 64 * 1024;

#[path = "restore_config_schema.rs"]
mod config_schema;

#[derive(Debug, thiserror::Error)]
pub enum RestoreIdentityError {
    #[error("restore authentication or TLS state is invalid or incomplete")]
    InvalidState,
    #[error("restore runtime layout requires an explicit migration")]
    UnsupportedLayout,
    #[error("restore config contains unsupported extensions; explicit migration is required")]
    UnsupportedConfig,
    #[error("restore identity exceeds its resource budget")]
    Limit,
    #[error(transparent)]
    Archive(#[from] RestoreArchiveError),
}
type Result<T> = std::result::Result<T, RestoreIdentityError>;

// No Debug/Clone/serialization: the snapshot remains private. This wrapper is
// proof of identity/config checks, not proof of ticket authorization or replay.
pub struct IdentityCheckedRestore {
    archive: ValidatedRestore,
}
impl IdentityCheckedRestore {
    pub fn members(&self) -> &[restore_archive::RestoreMember] {
        self.archive.members()
    }
    pub fn copy_file<W: Write>(&mut self, index: usize, out: &mut W) -> Result<()> {
        self.archive.copy_file(index, out)?;
        Ok(())
    }
}

/// The effective Config must come from the running server, after Config::load.
/// Callers must hold the common update lock and quiesce all settings writers.
/// working_dir is the running process's logical absolute cwd, not source_root.
/// config_path is the exact active NANOKVM_CONFIG/default path selected at boot.
/// No live file, credential or setting is changed by capture.
pub fn capture_effective(
    source_root: &Path,
    private_staging: &Path,
    effective: &Config,
    working_dir: &Path,
    config_path: &Path,
) -> Result<CapturedArchive> {
    if effective.jwt.secret_key.is_empty() || effective.jwt.secret_key.len() > MAX_SECRET {
        return Err(RestoreIdentityError::InvalidState);
    }
    let source = SourceRoot::open(source_root)?;
    let mut canonical =
        match source.read_setting(&source_path(config_path, working_dir)?, MAX_CONFIG)? {
            Some(bytes) => parse_config(&bytes)?,
            None => PrivateConfig(Config::default()),
        };
    canonical.0.normalize_legacy_fields();
    validate_layout(&canonical.0)?;
    // Never overwrite newer disk settings with the immutable startup Config.
    // A pending identity/key change is ambiguous: require its ordinary server
    // restart first rather than choose a different login identity while flashing.
    if source_path(&canonical.0.paths.account_file, working_dir)?
        != source_path(&effective.paths.account_file, working_dir)?
    {
        return Err(RestoreIdentityError::InvalidState);
    }
    if canonical.0.jwt.secret_key.is_empty() {
        if source_path(&canonical.0.paths.session_secret_file, working_dir)?
            != source_path(&effective.paths.session_secret_file, working_dir)?
        {
            return Err(RestoreIdentityError::InvalidState);
        }
        let bytes = source
            .read_setting(
                &source_path(&canonical.0.paths.session_secret_file, working_dir)?,
                MAX_SECRET + 2,
            )?
            .ok_or(RestoreIdentityError::InvalidState)?;
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| RestoreIdentityError::InvalidState)?
            .trim();
        if value != effective.jwt.secret_key {
            return Err(RestoreIdentityError::InvalidState);
        }
    } else if canonical.0.jwt.secret_key != effective.jwt.secret_key {
        return Err(RestoreIdentityError::InvalidState);
    }
    let account = source
        .read_setting(
            &source_path(&effective.paths.account_file, working_dir)?,
            MAX_ACCOUNT,
        )?
        .ok_or(RestoreIdentityError::InvalidState)?;
    validate_account(&account)?;
    let cert = source.read_setting(
        &source_path(Path::new(&canonical.0.cert.crt), working_dir)?,
        MAX_CERT,
    )?;
    let key = source.read_setting(
        &source_path(Path::new(&canonical.0.cert.key), working_dir)?,
        MAX_KEY,
    )?;
    validate_tls(
        canonical.0.proto == "https",
        cert.as_deref().map(|v| v.as_slice()),
        key.as_deref().map(|v| v.as_slice()),
    )?;
    canonical.0.paths.account_file = PathBuf::from(format!("/{ACCOUNT}"));
    canonical.0.paths.session_secret_file = PathBuf::from(format!("/{SESSION}"));
    canonical.0.cert.crt = format!("/{CERT}");
    canonical.0.cert.key = format!("/{KEY}");
    if canonical.0.jwt.secret_key.is_empty() {
        canonical.0.jwt.secret_key = effective.jwt.secret_key.clone();
    }
    canonical.0.jwt.secret_key_legacy.zeroize();
    // Keep the effective key embedded verbatim. In particular, embedded keys
    // containing whitespace must not be changed by session-file trim behavior.
    let yaml = encode_config(&canonical.0)?;
    let mut secret = Zeroizing::new(Vec::with_capacity(effective.jwt.secret_key.len() + 1));
    secret.extend_from_slice(effective.jwt.secret_key.as_bytes());
    secret.push(b'\n');
    let replacements = [
        CanonicalSetting {
            path: CONFIG,
            bytes: Some(yaml),
        },
        CanonicalSetting {
            path: ACCOUNT,
            bytes: Some(account),
        },
        CanonicalSetting {
            path: SESSION,
            bytes: Some(secret),
        },
        CanonicalSetting {
            path: CERT,
            bytes: cert,
        },
        CanonicalSetting {
            path: KEY,
            bytes: key,
        },
    ];
    Ok(restore_archive::capture_canonical(
        &source,
        private_staging,
        &replacements,
    )?)
}

/// Run only after complete capsule authentication and archive validation.
/// A later applier must consume this type together with an authorized ticket.
pub fn check_identity(mut archive: ValidatedRestore) -> Result<IdentityCheckedRestore> {
    let yaml =
        read_member(&mut archive, CONFIG, MAX_CONFIG)?.ok_or(RestoreIdentityError::InvalidState)?;
    let config = parse_config(&yaml)?;
    validate_layout(&config.0)?;
    if config.0.paths.account_file != Path::new(&format!("/{ACCOUNT}"))
        || config.0.paths.session_secret_file != Path::new(&format!("/{SESSION}"))
        || config.0.cert.crt != format!("/{CERT}")
        || config.0.cert.key != format!("/{KEY}")
        || config.0.jwt.secret_key.is_empty()
        || config.0.jwt.secret_key.len() > MAX_SECRET
        || !config.0.jwt.secret_key_legacy.is_empty()
    {
        return Err(RestoreIdentityError::InvalidState);
    }
    let account = read_member(&mut archive, ACCOUNT, MAX_ACCOUNT)?
        .ok_or(RestoreIdentityError::InvalidState)?;
    validate_account(&account)?;
    let secret = read_member(&mut archive, SESSION, MAX_SECRET + 1)?
        .ok_or(RestoreIdentityError::InvalidState)?;
    if secret.len() != config.0.jwt.secret_key.len() + 1
        || !secret.starts_with(config.0.jwt.secret_key.as_bytes())
        || secret.last() != Some(&b'\n')
    {
        return Err(RestoreIdentityError::InvalidState);
    }
    let cert = read_member(&mut archive, CERT, MAX_CERT)?;
    let key = read_member(&mut archive, KEY, MAX_KEY)?;
    validate_tls(
        config.0.proto == "https",
        cert.as_deref().map(|v| v.as_slice()),
        key.as_deref().map(|v| v.as_slice()),
    )?;
    Ok(IdentityCheckedRestore { archive })
}

struct PrivateConfig(Config);
impl Drop for PrivateConfig {
    fn drop(&mut self) {
        self.0.jwt.secret_key.zeroize();
        self.0.jwt.secret_key_legacy.zeroize();
        self.0.turn.turn_user.zeroize();
        self.0.turn.turn_cred.zeroize();
    }
}

fn parse_config(bytes: &[u8]) -> Result<PrivateConfig> {
    if bytes.len() > MAX_CONFIG {
        return Err(RestoreIdentityError::Limit);
    }
    let config = PrivateConfig(
        serde_yaml::from_slice(bytes).map_err(|_| RestoreIdentityError::InvalidState)?,
    );
    // Runtime Config deliberately tolerates unknown YAML. A canonical restore
    // cannot round-trip those extensions, so stop before producing a snapshot.
    config_schema::check(bytes).map_err(|_| RestoreIdentityError::UnsupportedConfig)?;
    Ok(config)
}

fn validate_layout(config: &Config) -> Result<()> {
    let defaults = Paths::default();
    if config.paths.web_root != defaults.web_root
        || config.paths.image_directory != defaults.image_directory
        || config.paths.update_cache_dir != defaults.update_cache_dir
        || config.paths.system_update_public_key != defaults.system_update_public_key
    {
        return Err(RestoreIdentityError::UnsupportedLayout);
    }
    if !matches!(config.proto.as_str(), "http" | "https")
        || config.listen_addr().is_err()
        || config.https_listen_addr().is_err()
    {
        return Err(RestoreIdentityError::InvalidState);
    }
    Ok(())
}

fn source_path(path: &Path, cwd: &Path) -> Result<String> {
    if path.as_os_str().is_empty() || !cwd.is_absolute() {
        return Err(RestoreIdentityError::InvalidState);
    }
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let mut relative = PathBuf::new();
    for part in joined.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => relative.push(part),
            _ => return Err(RestoreIdentityError::InvalidState),
        }
    }
    relative
        .to_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or(RestoreIdentityError::InvalidState)
}

fn validate_account(bytes: &[u8]) -> Result<()> {
    let mut account: Account =
        serde_json::from_slice(bytes).map_err(|_| RestoreIdentityError::InvalidState)?;
    let valid = !account.username.is_empty()
        && account.username.len() <= 64
        && !account.username.chars().any(char::is_control)
        && hash_is_supported(&account.password);
    account.password.zeroize();
    if valid {
        Ok(())
    } else {
        Err(RestoreIdentityError::InvalidState)
    }
}

fn hash_is_supported(hash: &str) -> bool {
    if hash.starts_with("$2") {
        return hash.len() == 60
            && hash.is_ascii()
            && hash
                .parse::<bcrypt::HashParts>()
                .is_ok_and(|parts| (4..=31).contains(&parts.get_cost()))
            && bcrypt::BASE_64
                .decode(&hash.as_bytes()[7..29])
                .is_ok_and(|v| v.len() == 16)
            && bcrypt::BASE_64
                .decode(&hash.as_bytes()[29..])
                .is_ok_and(|v| v.len() == 23);
    }
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Algorithm::try_from(parsed.algorithm).is_ok()
        && parsed.version.is_none_or(|v| Version::try_from(v).is_ok())
        && parsed.salt.is_some()
        && parsed.hash.is_some()
        && Params::try_from(&parsed).is_ok()
}

fn validate_tls(required: bool, cert: Option<&[u8]>, key: Option<&[u8]>) -> Result<()> {
    match (cert, key) {
        (None, None) if !required => Ok(()),
        (Some(cert), Some(key)) => {
            let certs = CertificateDer::pem_slice_iter(cert)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| RestoreIdentityError::InvalidState)?;
            if certs.is_empty() {
                return Err(RestoreIdentityError::InvalidState);
            }
            let key = PrivateKeyDer::from_pem_slice(key)
                .map_err(|_| RestoreIdentityError::InvalidState)?;
            ServerConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|_| RestoreIdentityError::InvalidState)?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|_| RestoreIdentityError::InvalidState)?;
            Ok(())
        }
        _ => Err(RestoreIdentityError::InvalidState),
    }
}

struct PrivateBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Write for PrivateBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode_config(config: &Config) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = PrivateBuffer {
        bytes: Zeroizing::new(Vec::with_capacity(MAX_CONFIG)),
        limit: MAX_CONFIG,
    };
    serde_yaml::to_writer(&mut out, config).map_err(|_| RestoreIdentityError::Limit)?;
    Ok(out.bytes)
}
fn read_member(
    archive: &mut ValidatedRestore,
    path: &str,
    limit: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(index) = archive
        .members()
        .iter()
        .position(|member| member.path == path)
    else {
        return Ok(None);
    };
    let member = &archive.members()[index];
    if member.action != RestoreAction::Write || member.size > limit as u64 {
        return Err(RestoreIdentityError::Limit);
    }
    let mut out = PrivateBuffer {
        bytes: Zeroizing::new(Vec::with_capacity(member.size as usize)),
        limit,
    };
    archive.copy_file(index, &mut out)?;
    Ok(Some(out.bytes))
}

#[cfg(test)]
#[path = "restore_identity_tests.rs"]
mod tests;
