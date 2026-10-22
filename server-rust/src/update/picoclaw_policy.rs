//! The local-tool policy of the PicoClaw runtime, which runs as root on the
//! NanoKVM. Pure: no I/O. Control of the connected computer goes through the
//! `nanokvm` MCP server and is untouched. What stays closed is the NanoKVM's
//! own shell, its hardware buses, local MCP commands and every file outside
//! the runtime's workspace.
use crate::{AppError, Result};
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::path::{Component, Path, PathBuf};

/// The MCP server the Startup job configures; the policy never disables it.
const NANOKVM_SERVER: &str = "nanokvm";
/// Tools that act on the NanoKVM itself rather than on the connected computer.
const DISABLED: [&str; 4] = ["exec", "serial", "spi", "i2c"];
/// Upstream serves these allowlists by raw host access outside the workspace.
const NO_PATHS: [&str; 2] = ["allow_read_paths", "allow_write_paths"];

fn malformed() -> AppError {
    AppError::Config("invalid picoclaw local tool policy".into())
}

/// The runtime's workspace in `home`: the only tree its file tools reach.
pub(crate) fn workspace_root(home: &Path) -> PathBuf {
    home.join("workspace")
}

// `path` names the workspace root or a directory below it: absolute, without
// `..`, compared by components. The pair and the token stay outside.
fn inside(path: &str, home: &Path) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        && path.starts_with(workspace_root(home))
}

fn object(value: Option<&JsonValue>) -> Result<Option<&JsonMap<String, JsonValue>>> {
    match value {
        None => Ok(None),
        Some(JsonValue::Object(map)) => Ok(Some(map)),
        Some(_) => Err(malformed()),
    }
}

fn flag(map: &JsonMap<String, JsonValue>, key: &str) -> Result<()> {
    match map.get(key) {
        None | Some(JsonValue::Bool(_)) => Ok(()),
        Some(_) => Err(malformed()),
    }
}

fn workspace(map: &JsonMap<String, JsonValue>, home: &Path) -> Result<()> {
    match map.get("workspace") {
        None => Ok(()),
        Some(JsonValue::String(path)) if inside(path, home) => Ok(()),
        Some(_) => Err(malformed()),
    }
}

// A server that upstream starts as a local command, not one it reaches over
// the network.
fn local_command(server: &JsonMap<String, JsonValue>) -> bool {
    server.get("type").and_then(JsonValue::as_str) == Some("stdio")
        || server
            .get("command")
            .and_then(JsonValue::as_str)
            .is_some_and(|command| !command.trim().is_empty())
}

/// What enforcement cannot repair: every shape at the policy's keys, and each
/// configured workspace, which must lie inside `<home>/workspace`.
pub(crate) fn validate(config: &JsonValue, home: &Path) -> Result<()> {
    let root = config.as_object().ok_or_else(malformed)?;
    if let Some(agents) = object(root.get("agents"))? {
        if let Some(defaults) = object(agents.get("defaults"))? {
            flag(defaults, "restrict_to_workspace")?;
            flag(defaults, "allow_read_outside_workspace")?;
            workspace(defaults, home)?;
        }
        match agents.get("list") {
            None => {}
            Some(JsonValue::Array(list)) => {
                for agent in list {
                    workspace(object(Some(agent))?.ok_or_else(malformed)?, home)?;
                }
            }
            Some(_) => return Err(malformed()),
        }
    }
    let Some(tools) = object(root.get("tools"))? else {
        return Ok(());
    };
    for name in DISABLED.into_iter().chain(["cron"]) {
        if let Some(tool) = object(tools.get(name))? {
            flag(tool, "enabled")?;
            flag(tool, "allow_command")?;
        }
    }
    for key in NO_PATHS {
        if !matches!(tools.get(key), None | Some(JsonValue::Array(_))) {
            return Err(malformed());
        }
    }
    if let Some(servers) = object(tools.get("mcp"))?
        .map(|mcp| object(mcp.get("servers")))
        .transpose()?
        .flatten()
    {
        for server in servers.values() {
            let server = object(Some(server))?.ok_or_else(malformed)?;
            flag(server, "enabled")?;
            for key in ["type", "command"] {
                if !matches!(server.get(key), None | Some(JsonValue::String(_))) {
                    return Err(malformed());
                }
            }
        }
    }
    Ok(())
}

/// Rewrite `config` to carry the policy, whatever explicit values it had.
/// Unrelated fields are kept; `validate` failures refuse before any change.
pub(crate) fn enforce(config: &mut JsonValue, home: &Path) -> Result<()> {
    validate(config, home)?;
    let root = config.as_object_mut().ok_or_else(malformed)?;
    let defaults = object_at(root, &["agents", "defaults"])?;
    defaults.insert("restrict_to_workspace".into(), JsonValue::Bool(true));
    defaults.insert(
        "allow_read_outside_workspace".into(),
        JsonValue::Bool(false),
    );
    if !defaults.contains_key("workspace") {
        let path = workspace_root(home);
        let path = path.to_str().ok_or_else(malformed)?;
        defaults.insert("workspace".into(), JsonValue::String(path.into()));
    }
    for name in DISABLED {
        object_at(root, &["tools", name])?.insert("enabled".into(), JsonValue::Bool(false));
    }
    object_at(root, &["tools", "cron"])?.insert("allow_command".into(), JsonValue::Bool(false));
    let tools = object_at(root, &["tools"])?;
    for key in NO_PATHS {
        if tools
            .get(key)
            .and_then(JsonValue::as_array)
            .is_some_and(|paths| !paths.is_empty())
        {
            tools.insert(key.into(), JsonValue::Array(Vec::new()));
        }
    }
    if let Some(servers) = tools
        .get_mut("mcp")
        .and_then(|mcp| mcp.get_mut("servers"))
        .and_then(JsonValue::as_object_mut)
    {
        for (name, server) in servers.iter_mut() {
            if let Some(server) = server.as_object_mut()
                && name != NANOKVM_SERVER
                && local_command(server)
            {
                server.insert("enabled".into(), JsonValue::Bool(false));
            }
        }
    }
    Ok(())
}

/// Ok only for a pair that already carries the policy, so it may be launched.
pub(crate) fn check(config: &JsonValue, home: &Path) -> Result<()> {
    let mut enforced = config.clone();
    enforce(&mut enforced, home)?;
    if enforced == *config {
        Ok(())
    } else {
        Err(AppError::Config(
            "picoclaw configuration lacks the local tool policy".into(),
        ))
    }
}

// The object at `path`, created when absent; any other shape refuses.
fn object_at<'a>(
    root: &'a mut JsonMap<String, JsonValue>,
    path: &[&str],
) -> Result<&'a mut JsonMap<String, JsonValue>> {
    let mut current = root;
    for key in path {
        current = current
            .entry((*key).to_string())
            .or_insert_with(|| JsonValue::Object(JsonMap::new()))
            .as_object_mut()
            .ok_or_else(malformed)?;
    }
    Ok(current)
}

#[cfg(test)]
#[path = "picoclaw_policy_tests.rs"]
mod tests;
