use axum::{Json, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::{fs, net::IpAddr, time::Duration};

use crate::{
    Result,
    error::ApiResponse,
    system::command::{self, AllowedCommand},
};

const TAILSCALE_PATH: &str = "/usr/bin/tailscale";
const TAILSCALED_PATH: &str = "/usr/sbin/tailscaled";
const TAILSCALE_STATUS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TailscaleState {
    NotInstall,
    NotRunning,
    NotLogin,
    Stopped,
    Running,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct GetTailscaleStatusRsp {
    pub state: TailscaleState,
    pub name: String,
    pub ip: String,
    pub account: String,
}

#[derive(Debug, Deserialize)]
struct RawTailscaleStatus {
    #[serde(rename = "BackendState")]
    backend_state: String,
    #[serde(rename = "Self", default)]
    self_node: RawTailscaleSelf,
    #[serde(rename = "CurrentTailnet", default)]
    current_tailnet: RawTailscaleTailnet,
}

#[derive(Debug, Default, Deserialize)]
struct RawTailscaleSelf {
    #[serde(rename = "HostName", default)]
    host_name: String,
    #[serde(rename = "TailscaleIPs", default)]
    tailscale_ips: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawTailscaleTailnet {
    #[serde(rename = "Name", default)]
    name: String,
}

pub async fn get_status() -> Result<impl IntoResponse> {
    if !is_installed() {
        return Ok(Json(ApiResponse::ok(not_installed_status())));
    }

    let output = command::run_allowed(
        AllowedCommand::Tailscale,
        ["status", "--json"],
        TAILSCALE_STATUS_TIMEOUT,
    )
    .await;

    let Ok(output) = output else {
        return Ok(Json(ApiResponse::ok(not_running_status())));
    };
    if output.status != 0 {
        return Ok(Json(ApiResponse::ok(not_running_status())));
    }

    match parse_status_output(&output.stdout) {
        Ok(status) => Ok(Json(ApiResponse::ok(status))),
        Err(err) => {
            tracing::warn!(error = %err, "failed to parse tailscale status");
            Ok(Json(ApiResponse::ok(not_running_status())))
        }
    }
}

fn is_installed() -> bool {
    fs::metadata(TAILSCALE_PATH)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
        && fs::metadata(TAILSCALED_PATH)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
}

fn parse_status_output(output: &[u8]) -> serde_json::Result<GetTailscaleStatusRsp> {
    let raw = String::from_utf8_lossy(output);
    let json_start = raw.find('{').unwrap_or(0);
    let status: RawTailscaleStatus = serde_json::from_str(&raw[json_start..])?;
    Ok(status_response(status))
}

fn status_response(status: RawTailscaleStatus) -> GetTailscaleStatusRsp {
    let state = match status.backend_state.as_str() {
        "NoState" | "Starting" => TailscaleState::NotRunning,
        "NeedsLogin" | "NeedsMachineAuth" | "InUseOtherUser" => TailscaleState::NotLogin,
        "Running" => TailscaleState::Running,
        "Stopped" => TailscaleState::Stopped,
        _ => TailscaleState::NotRunning,
    };

    GetTailscaleStatusRsp {
        state,
        name: status.self_node.host_name,
        ip: first_ipv4(&status.self_node.tailscale_ips).unwrap_or_default(),
        account: status.current_tailnet.name,
    }
}

fn first_ipv4(ips: &[String]) -> Option<String> {
    ips.iter().find_map(|ip| match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(ip) => Some(ip.to_string()),
        IpAddr::V6(_) => None,
    })
}

fn not_installed_status() -> GetTailscaleStatusRsp {
    empty_status(TailscaleState::NotInstall)
}

fn not_running_status() -> GetTailscaleStatusRsp {
    empty_status(TailscaleState::NotRunning)
}

fn empty_status(state: TailscaleState) -> GetTailscaleStatusRsp {
    GetTailscaleStatusRsp {
        state,
        name: String::new(),
        ip: String::new(),
        account: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prefixed_running_status() {
        let parsed = parse_status_output(
            br#"noise before json
{
  "BackendState": "Running",
  "Self": {
    "HostName": "kvm-bd3e",
    "TailscaleIPs": ["fd7a:115c:a1e0::1", "100.64.1.2"]
  },
  "CurrentTailnet": { "Name": "example.ts.net" }
}"#,
        )
        .unwrap();

        assert_eq!(parsed.state, TailscaleState::Running);
        assert_eq!(parsed.name, "kvm-bd3e");
        assert_eq!(parsed.ip, "100.64.1.2");
        assert_eq!(parsed.account, "example.ts.net");
    }

    #[test]
    fn maps_login_required_state() {
        let parsed = parse_status_output(br#"{"BackendState":"NeedsLogin"}"#).unwrap();

        assert_eq!(parsed.state, TailscaleState::NotLogin);
        assert_eq!(parsed.ip, "");
    }
}
