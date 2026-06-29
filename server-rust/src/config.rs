use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{AppError, Result};

const DEFAULT_CONFIG_PATH: &str = "/etc/kvm/server.yaml";
const DEFAULT_SECRET_PATH: &str = "/etc/kvm/session_secret";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub proto: String,
    pub host: String,
    pub port: Port,
    pub cert: Cert,
    pub logger: Logger,
    pub authentication: String,
    pub jwt: Jwt,
    pub stun: String,
    pub turn: Turn,
    pub security: Security,
    pub paths: Paths,
    pub compatibility_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Port {
    pub http: u16,
    pub https: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Cert {
    pub crt: String,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Logger {
    pub level: String,
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Jwt {
    pub secret_key: String,
    #[serde(alias = "secretKey")]
    pub secret_key_legacy: String,
    #[serde(alias = "refreshTokenDuration")]
    pub refresh_token_duration: u64,
    #[serde(alias = "revokeTokensOnLogout")]
    pub revoke_tokens_on_logout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Turn {
    #[serde(alias = "turnAddr")]
    pub turn_addr: String,
    #[serde(alias = "turnUser")]
    pub turn_user: String,
    #[serde(alias = "turnCred")]
    pub turn_cred: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Security {
    #[serde(alias = "loginLockoutDuration")]
    pub login_lockout_duration: u64,
    #[serde(alias = "loginMaxFailures")]
    pub login_max_failures: u32,
    pub require_csrf: bool,
    pub websocket_origin_check: bool,
    pub access_token_duration: u64,
    pub refresh_token_duration: u64,
    pub revoke_tokens_on_password_change: bool,
    pub allow_unsigned_updates: bool,
    pub allow_terminal: bool,
    pub allow_remote_image_download: bool,
    pub allow_auth_disable: bool,
    pub allow_default_admin: bool,
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Paths {
    pub account_file: PathBuf,
    pub session_secret_file: PathBuf,
    pub web_root: PathBuf,
    pub image_directory: PathBuf,
    pub update_cache_dir: PathBuf,
    pub system_update_public_key: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proto: "http".to_string(),
            host: "0.0.0.0".to_string(),
            port: Port::default(),
            cert: Cert::default(),
            logger: Logger::default(),
            authentication: "enable".to_string(),
            jwt: Jwt::default(),
            stun: "stun.l.google.com:19302".to_string(),
            turn: Turn::default(),
            security: Security::default(),
            paths: Paths::default(),
            compatibility_mode: false,
        }
    }
}

impl Default for Port {
    fn default() -> Self {
        Self {
            http: 80,
            https: 443,
        }
    }
}

impl Default for Cert {
    fn default() -> Self {
        Self {
            crt: "server.crt".to_string(),
            key: "server.key".to_string(),
        }
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: "stdout".to_string(),
        }
    }
}

impl Default for Jwt {
    fn default() -> Self {
        Self {
            secret_key: String::new(),
            secret_key_legacy: String::new(),
            refresh_token_duration: 2_678_400,
            revoke_tokens_on_logout: true,
        }
    }
}

impl Default for Turn {
    fn default() -> Self {
        Self {
            turn_addr: String::new(),
            turn_user: String::new(),
            turn_cred: String::new(),
        }
    }
}

impl Default for Security {
    fn default() -> Self {
        Self {
            login_lockout_duration: 600,
            login_max_failures: 5,
            require_csrf: true,
            websocket_origin_check: true,
            access_token_duration: 900,
            refresh_token_duration: 604_800,
            revoke_tokens_on_password_change: true,
            allow_unsigned_updates: false,
            allow_terminal: false,
            allow_remote_image_download: false,
            allow_auth_disable: false,
            allow_default_admin: false,
            allowed_origins: Vec::new(),
        }
    }
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            account_file: PathBuf::from("/etc/kvm/pwd"),
            session_secret_file: PathBuf::from(DEFAULT_SECRET_PATH),
            web_root: PathBuf::from("/kvmapp/server/web"),
            image_directory: PathBuf::from("/data"),
            update_cache_dir: PathBuf::from("/root/.kvmcache"),
            system_update_public_key: PathBuf::from("/etc/kvm/system-update-signing.pub.pem"),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let mut config = Self::read()?;
        config.ensure_session_secret()?;
        Ok(config)
    }

    pub fn read() -> Result<Self> {
        let path = std::env::var("NANOKVM_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH));
        let mut config = if path.exists() {
            let data = fs::read_to_string(&path)?;
            serde_yaml::from_str::<Config>(&data).map_err(|err| {
                AppError::Config(format!("failed to parse {}: {err}", path.display()))
            })?
        } else {
            Config::default()
        };
        config.normalize_legacy_fields();
        Ok(config)
    }

    pub fn write(&self) -> Result<()> {
        let path = std::env::var("NANOKVM_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH));
        let data = serde_yaml::to_string(self)
            .map_err(|err| AppError::Config(format!("failed to serialize config: {err}")))?;
        write_yaml_0600_atomic(&path, data.as_bytes())?;
        Ok(())
    }

    pub fn listen_addr(&self) -> Result<SocketAddr> {
        self.socket_addr(self.port.http)
    }

    pub fn https_listen_addr(&self) -> Result<SocketAddr> {
        self.socket_addr(self.port.https)
    }

    pub fn loopback_listen_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port.http))
    }

    pub fn needs_dedicated_loopback_listener(&self) -> bool {
        let host = self.host.trim().trim_matches(['[', ']']);
        if host.is_empty() {
            return false;
        }

        match host.parse::<IpAddr>() {
            Ok(ip) => !ip.is_loopback() && !ip.is_unspecified(),
            Err(_) => !host.eq_ignore_ascii_case("localhost"),
        }
    }

    fn socket_addr(&self, port: u16) -> Result<SocketAddr> {
        let ip: IpAddr = if self.host.is_empty() {
            "0.0.0.0"
        } else {
            self.host.as_str()
        }
        .parse()
        .map_err(|err| AppError::Config(format!("invalid host {}: {err}", self.host)))?;
        Ok(SocketAddr::new(ip, port))
    }

    pub fn auth_disabled(&self) -> bool {
        self.authentication == "disable" && self.security.allow_auth_disable
    }

    pub fn log_runtime_warnings(&self) {
        if self.authentication == "disable" {
            warn!("authentication is disabled in config");
        }
        if self.security.login_lockout_duration == 0 {
            warn!("login lockout is disabled");
        }
        if self.proto == "http" {
            warn!("HTTP without TLS is enabled");
        }
        if self.security.allow_terminal {
            warn!("web terminal is enabled");
        }
        if self.security.allow_remote_image_download {
            warn!("remote ISO download is enabled");
        }
        if self.security.allow_unsigned_updates {
            warn!("unsigned updates are allowed");
        }
        if self.security.allow_default_admin {
            warn!("legacy admin/admin bootstrap is enabled");
        }
    }

    fn normalize_legacy_fields(&mut self) {
        if self.jwt.secret_key.is_empty() && !self.jwt.secret_key_legacy.is_empty() {
            self.jwt.secret_key = self.jwt.secret_key_legacy.clone();
        }
    }

    fn ensure_session_secret(&mut self) -> Result<()> {
        if !self.jwt.secret_key.is_empty() {
            return Ok(());
        }

        if let Ok(secret) = fs::read_to_string(&self.paths.session_secret_file) {
            let secret = secret.trim().to_string();
            if !secret.is_empty() {
                self.jwt.secret_key = secret;
                return Ok(());
            }
        }

        let secret = generate_secret();
        write_secret_0600(&self.paths.session_secret_file, &secret)?;
        self.jwt.secret_key = secret;
        Ok(())
    }
}

fn generate_secret() -> String {
    let mut bytes = [0_u8; 64];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn write_secret_0600(path: &Path, secret: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(secret.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn write_yaml_0600_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(AppError::Config("empty config path".to_string()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Config("config path has no parent".to_string()))?;
    ensure_no_symlink_components(parent)?;
    fs::create_dir_all(parent)?;
    ensure_no_symlink_components(path)?;

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| AppError::Config("config path has invalid file name".to_string()))?;
    let tmp_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        random_tmp_suffix()
    ));

    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
        fs::rename(&tmp_path, path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        if let Ok(parent_dir) = fs::File::open(parent) {
            let _ = parent_dir.sync_all();
        }
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_result
}

fn ensure_no_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) => current.push(component.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(AppError::Config(
                    "config path cannot contain parent directory components".to_string(),
                ));
            }
            Component::Normal(value) => current.push(value),
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AppError::Config(format!(
                    "refusing to write config through symlink: {}",
                    current.display()
                )));
            }
            Ok(metadata) if metadata.file_type().is_fifo() || metadata.file_type().is_socket() => {
                return Err(AppError::Config(format!(
                    "refusing to write config through special file: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn random_tmp_suffix() -> String {
    let mut bytes = [0_u8; 8];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn default_disables_legacy_admin_bootstrap() {
        assert!(!Config::default().security.allow_default_admin);
    }

    #[test]
    fn dedicated_loopback_listener_matches_go_host_rules() {
        let mut config = Config::default();

        for host in ["", "0.0.0.0", "::", "127.0.0.1", "::1", "localhost"] {
            config.host = host.to_string();
            assert!(
                !config.needs_dedicated_loopback_listener(),
                "{host} should not need a dedicated loopback listener"
            );
        }

        for host in ["10.0.87.133", "192.168.1.10", "kvm-bd3e.local"] {
            config.host = host.to_string();
            assert!(
                config.needs_dedicated_loopback_listener(),
                "{host} should need a dedicated loopback listener"
            );
        }
    }

    #[test]
    fn config_write_uses_0600_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        write_yaml_0600_atomic(&path, b"proto: http\n").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_to_string(path).unwrap(), "proto: http\n");
    }

    #[test]
    fn config_write_rejects_symlink_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.yaml");
        let link = dir.path().join("server.yaml");
        fs::write(&target, b"proto: http\n").unwrap();
        symlink(&target, &link).unwrap();

        let err = write_yaml_0600_atomic(&link, b"proto: https\n").unwrap_err();
        assert!(err.to_string().contains("symlink"));
        assert_eq!(fs::read_to_string(target).unwrap(), "proto: http\n");
    }
}
