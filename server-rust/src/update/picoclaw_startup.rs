//! Pure startup-default reconciliation shared by the API writer and the
//! broker's Startup job. No I/O, entropy or credential provisioning: callers
//! pass the gateway and internal tokens they already selected or planned, so a
//! crash/retry replays the same desired documents instead of new randomness.
use crate::{AppError, Result};
use serde_json::{Map as JsonMap, Value as JsonValue};

pub(crate) const GATEWAY_HOST: &str = "127.0.0.1";
pub(crate) const GATEWAY_PORT: u16 = 18790;
pub(crate) const READ_TIMEOUT_MS: i32 = 60_000;
pub(crate) const WRITE_TIMEOUT_MS: i32 = 10_000;
pub(crate) const PING_INTERVAL_MS: i32 = 30_000;
pub(crate) const INTERNAL_TOKEN_HEADER: &str = "X-NanoKVM-Internal-Token";
const MCP_URL: &str = "http://127.0.0.1:80/api/picoclaw/mcp";

/// Refuse shapes the defaults would otherwise overwrite or misread. Explicit
/// custom booleans are kept; only absent local-tool defaults are filled in.
pub(crate) fn check_local_policy(config: &JsonValue) -> Result<()> {
    for path in ["/agents", "/agents/defaults"] {
        if config.pointer(path).is_some_and(|value| !value.is_object()) {
            return Err(AppError::Config(
                "invalid picoclaw local tool policy".into(),
            ));
        }
    }
    for path in [
        "/agents/defaults/restrict_to_workspace",
        "/agents/defaults/allow_read_outside_workspace",
    ] {
        if config
            .pointer(path)
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(AppError::Config(
                "invalid picoclaw local tool policy".into(),
            ));
        }
    }
    if !config.is_object() {
        return Err(AppError::Internal(
            "picoclaw config root is not an object".into(),
        ));
    }
    Ok(())
}

/// The gateway token already in use: security settings, then the legacy
/// security location, then the config copy. `None` means the caller must
/// select one new token once and keep it for every retry of this change.
pub(crate) fn existing_gateway_token(
    config: &JsonValue,
    security: &serde_yaml::Value,
) -> Option<String> {
    let security_token = security
        .get("channel_list")
        .and_then(|channels| channels.get("pico"))
        .and_then(|pico| {
            pico.get("settings")
                .and_then(|settings| settings.get("token"))
                .or_else(|| pico.get("token"))
        })
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty());
    if let Some(token) = security_token {
        return Some(token.to_string());
    }
    config
        .pointer("/channel_list/pico/settings/token")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

/// Apply the fixed startup defaults to decoded documents. Unrelated and custom
/// fields are preserved; the result is a pure function of the inputs.
pub(crate) fn apply(
    config: &mut JsonValue,
    security: &mut serde_yaml::Value,
    gateway_token: &str,
    internal_token: &str,
) -> Result<()> {
    check_local_policy(config)?;
    set_security_gateway_token(security, gateway_token);
    let raw = config
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("picoclaw config root is not an object".into()))?;
    let defaults = ensure_object_path(raw, &["agents", "defaults"]);
    defaults
        .entry("restrict_to_workspace".to_string())
        .or_insert(JsonValue::Bool(true));
    defaults
        .entry("allow_read_outside_workspace".to_string())
        .or_insert(JsonValue::Bool(false));
    let gateway = ensure_object_path(raw, &["gateway"]);
    gateway.insert(
        "host".to_string(),
        JsonValue::String(GATEWAY_HOST.to_string()),
    );
    gateway.insert(
        "port".to_string(),
        JsonValue::Number(serde_json::Number::from(GATEWAY_PORT)),
    );
    let pico = ensure_object_path(raw, &["channel_list", "pico"]);
    pico.insert("type".to_string(), JsonValue::String("pico".to_string()));
    pico.insert("enabled".to_string(), JsonValue::Bool(true));
    let settings = ensure_object_path(raw, &["channel_list", "pico", "settings"]);
    settings.insert("allow_token_query".to_string(), JsonValue::Bool(false));
    for (name, milliseconds) in [
        ("ping_interval", PING_INTERVAL_MS),
        ("read_timeout", READ_TIMEOUT_MS),
        ("write_timeout", WRITE_TIMEOUT_MS),
    ] {
        settings.insert(
            name.to_string(),
            JsonValue::Number(serde_json::Number::from(milliseconds / 1000)),
        );
    }
    ensure_object_path(raw, &["tools", "mcp"]).insert("enabled".to_string(), JsonValue::Bool(true));
    let server = ensure_object_path(raw, &["tools", "mcp", "servers", "nanokvm"]);
    server.insert("enabled".to_string(), JsonValue::Bool(true));
    server.insert("type".to_string(), JsonValue::String("http".to_string()));
    server.insert("url".to_string(), JsonValue::String(MCP_URL.to_string()));
    ensure_object_path(raw, &["tools", "mcp", "servers", "nanokvm", "headers"]).insert(
        INTERNAL_TOKEN_HEADER.to_string(),
        JsonValue::String(internal_token.to_string()),
    );
    Ok(())
}

fn set_security_gateway_token(security: &mut serde_yaml::Value, token: &str) {
    let mut current = security;
    for key in ["channel_list", "pico", "settings"] {
        if !current.is_mapping() {
            *current = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        }
        let Some(mapping) = current.as_mapping_mut() else {
            return;
        };
        current = mapping
            .entry(serde_yaml::Value::String(key.to_string()))
            .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    }
    if !current.is_mapping() {
        *current = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    if let Some(settings) = current.as_mapping_mut() {
        settings.insert(
            serde_yaml::Value::String("token".to_string()),
            serde_yaml::Value::String(token.to_string()),
        );
    }
}

pub(crate) fn ensure_object_path<'a>(
    root: &'a mut JsonMap<String, JsonValue>,
    path: &[&str],
) -> &'a mut JsonMap<String, JsonValue> {
    let mut current = root;
    for key in path {
        let entry = current
            .entry((*key).to_string())
            .or_insert_with(|| JsonValue::Object(JsonMap::new()));
        if !entry.is_object() {
            *entry = JsonValue::Object(JsonMap::new());
        }
        current = entry.as_object_mut().expect("object path");
    }
    current
}

#[cfg(test)]
#[path = "picoclaw_startup_tests.rs"]
mod tests;
