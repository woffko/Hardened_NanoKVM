use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
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
            allow_auth_disable: false,
            allow_default_admin: true,
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
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
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
        config.ensure_session_secret()?;
        Ok(config)
    }

    pub fn listen_addr(&self) -> Result<SocketAddr> {
        let ip: IpAddr = if self.host.is_empty() {
            "0.0.0.0"
        } else {
            self.host.as_str()
        }
        .parse()
        .map_err(|err| AppError::Config(format!("invalid host {}: {err}", self.host)))?;
        Ok(SocketAddr::new(ip, self.port.http))
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
