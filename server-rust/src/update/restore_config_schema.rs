//! Closed restore-only field inventory; normal Config parsing is unchanged.
//!
//! This streaming pass builds no generic YAML value tree and retains no secret
//! values. Config first checks types/defaults/duplicates using its own derive.
//! Newly added Config fields must be explicitly reviewed for restore support;
//! the all-known-fields capture fixture catches inventory drift.

use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error, IgnoredAny, MapAccess, Visitor};
use zeroize::Zeroizing;

pub(super) fn check(bytes: &[u8]) -> Result<(), serde_yaml::Error> {
    Section::Config.deserialize(serde_yaml::Deserializer::from_slice(bytes))
}

#[derive(Clone, Copy)]
enum Section {
    Config,
    Port,
    Cert,
    Logger,
    Jwt,
    Turn,
    Security,
    Paths,
}
impl Section {
    fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Config => &[
                "proto",
                "host",
                "port",
                "cert",
                "logger",
                "authentication",
                "jwt",
                "stun",
                "turn",
                "security",
                "paths",
                "compatibility_mode",
            ],
            Self::Port => &["http", "https"],
            Self::Cert => &["crt", "key"],
            Self::Logger => &["level", "file"],
            Self::Jwt => &[
                "secret_key",
                "secret_key_legacy",
                "secretKey",
                "refresh_token_duration",
                "refreshTokenDuration",
                "revoke_tokens_on_logout",
                "revokeTokensOnLogout",
            ],
            Self::Turn => &[
                "turn_addr",
                "turnAddr",
                "turn_user",
                "turnUser",
                "turn_cred",
                "turnCred",
            ],
            Self::Security => &[
                "login_lockout_duration",
                "loginLockoutDuration",
                "login_max_failures",
                "loginMaxFailures",
                "require_csrf",
                "websocket_origin_check",
                "access_token_duration",
                "refresh_token_duration",
                "revoke_tokens_on_password_change",
                "allow_unsigned_updates",
                "allow_raw_system_updates",
                "allow_terminal",
                "allow_remote_image_download",
                "allow_auth_disable",
                "allow_default_admin",
                "allowed_origins",
            ],
            Self::Paths => &[
                "account_file",
                "session_secret_file",
                "web_root",
                "image_directory",
                "update_cache_dir",
                "system_update_public_key",
            ],
        }
    }
    fn child(self, key: &str) -> Option<Self> {
        if !matches!(self, Self::Config) {
            return None;
        }
        match key {
            "port" => Some(Self::Port),
            "cert" => Some(Self::Cert),
            "logger" => Some(Self::Logger),
            "jwt" => Some(Self::Jwt),
            "turn" => Some(Self::Turn),
            "security" => Some(Self::Security),
            "paths" => Some(Self::Paths),
            _ => None,
        }
    }
}
impl<'de> DeserializeSeed<'de> for Section {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_struct("RestoreConfig", self.fields(), self)
    }
}
impl<'de> Visitor<'de> for Section {
    type Value = ();
    fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("a supported restore config mapping")
    }
    fn visit_unit<E: Error>(self) -> Result<(), E> {
        // Only admitted if the real Config derive already accepts this as its
        // defaults. This schema check does not broaden runtime YAML semantics.
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            let key = Zeroizing::new(key);
            if !self.fields().contains(&key.as_str()) {
                return Err(A::Error::custom("unsupported restore config field"));
            }
            if let Some(child) = self.child(&key) {
                map.next_value_seed(child)?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}
