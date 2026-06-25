use axum::{Json, response::IntoResponse};
use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    AppError, Result,
    error::ApiResponse,
    system::command::{AllowedCommand, run_allowed},
};

const WOL_MAC_FILE: &str = "/etc/kvm/cache/wol";

const DNS_MODE_MANUAL: &str = "manual";
const DNS_MODE_DHCP: &str = "dhcp";
const DNS_CONFIG_DIR: &str = "/etc/kvm/network";
const DNS_MODE_FILE: &str = "/etc/kvm/network/dns.mode";
const DNS_SERVERS_FILE: &str = "/etc/kvm/network/dns.servers";
const BOOT_RESOLV_FILE: &str = "/boot/resolv.conf";
const BOOT_RESOLV_BACKUP: &str = "/boot/resolv.conf.manual.bak";
const ETC_RESOLV_FILE: &str = "/etc/resolv.conf";
const DHCP_RESOLV_FILE: &str = "/etc/resolv.conf.dhcp";
const TMP_RESOLV_FILE: &str = "/tmp/resolv.conf";
const UDHCPC_HOOK_FILE: &str = "/usr/share/udhcpc/default.script.d/99-nanokvm-dns";
const UDHCPC_DNS_HOOK: &str =
    include_str!("../../../server/service/network/scripts/99-nanokvm-dns");
const MAX_DNS_SERVERS: usize = 6;

#[derive(Debug, Deserialize)]
pub struct WolReq {
    pub mac: String,
}

#[derive(Debug, Deserialize)]
pub struct SetWolMacNameReq {
    pub mac: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct WolMacsRsp {
    pub macs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DnsRsp {
    pub mode: String,
    pub servers: Vec<String>,
    pub effective: Vec<String>,
    pub dhcp: Vec<String>,
    pub info: DnsInfo,
}

#[derive(Debug, Deserialize)]
pub struct SetDnsReq {
    pub mode: String,
    #[serde(default)]
    pub servers: Vec<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct DnsInfo {
    pub interface: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub address: String,
    #[serde(rename = "subnetMask")]
    pub subnet_mask: String,
    pub gateway: String,
    #[serde(rename = "searchDomains")]
    pub search_domains: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct ResolvConfig {
    servers: Vec<String>,
    search_domains: Vec<String>,
}

pub async fn wake_on_lan(Json(req): Json<WolReq>) -> Result<impl IntoResponse> {
    let mac = parse_mac(&req.mac)?;
    let output = run_allowed(
        AllowedCommand::EtherWake,
        ["-b", mac.as_str()],
        Duration::from_secs(5),
    )
    .await?;
    if output.status != 0 {
        return Err(AppError::Internal(command_error(
            "wake on lan failed",
            output,
        )));
    }

    if let Err(err) = save_mac(&mac) {
        tracing::warn!(error = %err, "failed to persist WOL MAC");
    }

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_wol_macs() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(WolMacsRsp {
        macs: read_wol_macs().unwrap_or_default(),
    })))
}

pub async fn delete_wol_mac(Json(req): Json<WolReq>) -> Result<impl IntoResponse> {
    let mac = parse_mac(&req.mac)?;
    let macs = read_wol_macs().unwrap_or_default();
    let mut next = Vec::new();

    for line in macs {
        let Some((item_mac, item_name)) = split_wol_mac_line(&line) else {
            continue;
        };
        let normalized = parse_mac(&item_mac).unwrap_or(item_mac);
        if normalized != mac {
            next.push(format_wol_mac_line(&normalized, &item_name));
        }
    }

    write_wol_macs(&next)?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn set_wol_mac_name(Json(req): Json<SetWolMacNameReq>) -> Result<impl IntoResponse> {
    let mac = parse_mac(&req.mac)?;
    let name = sanitize_wol_mac_name(&req.name);
    if name.is_empty() {
        return Err(AppError::BadRequest("invalid arguments".to_string()));
    }

    let macs = read_wol_macs()?;
    let mut next = Vec::new();
    let mut found = false;

    for line in macs {
        let Some((item_mac, item_name)) = split_wol_mac_line(&line) else {
            continue;
        };
        let normalized = parse_mac(&item_mac).unwrap_or(item_mac);
        if normalized == mac {
            next.push(format_wol_mac_line(&normalized, &name));
            found = true;
        } else {
            next.push(format_wol_mac_line(&normalized, &item_name));
        }
    }

    if !found {
        return Err(AppError::BadRequest("write failed".to_string()));
    }

    write_wol_macs(&next)?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_dns() -> Result<impl IntoResponse> {
    let mode = current_dns_mode();
    let mut servers = read_manual_dns_servers();
    if servers.is_empty() {
        servers = parse_resolv_conf(BOOT_RESOLV_FILE).unwrap_or_default();
    }
    if servers.is_empty() {
        servers = parse_resolv_conf(BOOT_RESOLV_BACKUP).unwrap_or_default();
    }

    let effective = parse_resolv_conf(ETC_RESOLV_FILE).unwrap_or_default();
    let dhcp_config = read_dhcp_resolv_config(can_fallback_effective_for_dhcp())
        .unwrap_or_else(|_| ResolvConfig::default());

    Ok(Json(ApiResponse::ok(DnsRsp {
        mode,
        servers,
        effective,
        dhcp: dhcp_config.servers,
        info: get_dns_info(),
    })))
}

pub async fn set_dns(Json(req): Json<SetDnsReq>) -> Result<impl IntoResponse> {
    match req.mode.as_str() {
        DNS_MODE_MANUAL => set_manual_dns(&req.servers)?,
        DNS_MODE_DHCP => set_dhcp_dns()?,
        _ => return Err(AppError::BadRequest("invalid dns mode".to_string())),
    }

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

fn parse_mac(value: &str) -> Result<String> {
    let mac = value
        .trim()
        .to_ascii_uppercase()
        .replace(['-', ':', '.'], "");
    if mac.len() != 12 || !mac.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid MAC address".to_string()));
    }

    let mut out = String::with_capacity(17);
    for index in (0..12).step_by(2) {
        if index > 0 {
            out.push(':');
        }
        out.push_str(&mac[index..index + 2]);
    }
    Ok(out)
}

fn save_mac(mac: &str) -> Result<()> {
    if is_mac_saved(mac) {
        return Ok(());
    }

    let mut macs = read_wol_macs().unwrap_or_default();
    macs.push(mac.to_string());
    write_wol_macs(&macs)
}

fn is_mac_saved(mac: &str) -> bool {
    read_wol_macs()
        .unwrap_or_default()
        .iter()
        .filter_map(|line| split_wol_mac_line(line))
        .filter_map(|(item_mac, _)| parse_mac(&item_mac).ok())
        .any(|item_mac| item_mac == mac)
}

fn read_wol_macs() -> Result<Vec<String>> {
    let content = match fs::read_to_string(WOL_MAC_FILE) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };

    Ok(content
        .lines()
        .filter_map(split_wol_mac_line)
        .map(|(mac, name)| format_wol_mac_line(&mac, &name))
        .collect())
}

fn write_wol_macs(macs: &[String]) -> Result<()> {
    let mut data = String::new();
    if !macs.is_empty() {
        data.push_str(&macs.join("\n"));
        data.push('\n');
    }
    write_file(Path::new(WOL_MAC_FILE), data.as_bytes(), 0o644)
}

fn split_wol_mac_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.splitn(2, char::is_whitespace);
    let mac = parts.next()?.to_string();
    let name = parts.next().unwrap_or("").trim().to_string();
    Some((mac, name))
}

fn format_wol_mac_line(mac: &str, name: &str) -> String {
    if name.is_empty() {
        mac.to_string()
    } else {
        format!("{mac} {name}")
    }
}

fn sanitize_wol_mac_name(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn set_manual_dns(servers: &[String]) -> Result<()> {
    let normalized = validate_dns_servers(servers)?;
    if normalized.is_empty() {
        return Err(AppError::BadRequest("dns servers are required".to_string()));
    }

    if current_dns_mode() == DNS_MODE_DHCP {
        if let Err(err) = refresh_dhcp_resolv_cache_from_effective() {
            tracing::warn!(error = %err, "failed to refresh DHCP DNS cache before manual mode");
        }
    }

    fs::create_dir_all(DNS_CONFIG_DIR)?;
    write_dns_mode(DNS_MODE_MANUAL)?;
    write_file(
        Path::new(DNS_SERVERS_FILE),
        format!("{}\n", normalized.join("\n")).as_bytes(),
        0o644,
    )?;
    render_resolv_conf(BOOT_RESOLV_FILE, &normalized)?;
    render_resolv_conf(ETC_RESOLV_FILE, &normalized)?;
    install_udhcpc_dns_hook()
}

fn set_dhcp_dns() -> Result<()> {
    let dhcp_config = read_dhcp_resolv_config(can_fallback_effective_for_dhcp())?;
    if dhcp_config.servers.is_empty() {
        return Err(AppError::BadRequest(
            "no dhcp dns is currently available".to_string(),
        ));
    }

    fs::create_dir_all(DNS_CONFIG_DIR)?;
    render_resolv_config(DHCP_RESOLV_FILE, &dhcp_config)?;
    write_dns_mode(DNS_MODE_DHCP)?;
    preserve_manual_dns_servers()?;
    backup_and_remove_boot_resolv()?;
    render_resolv_config(ETC_RESOLV_FILE, &dhcp_config)?;
    install_udhcpc_dns_hook()
}

fn current_dns_mode() -> String {
    read_raw_dns_mode().unwrap_or_else(default_dns_mode)
}

fn read_raw_dns_mode() -> Option<String> {
    let mode = fs::read_to_string(DNS_MODE_FILE).ok()?;
    match mode.trim() {
        DNS_MODE_MANUAL => Some(DNS_MODE_MANUAL.to_string()),
        DNS_MODE_DHCP => Some(DNS_MODE_DHCP.to_string()),
        _ => None,
    }
}

fn can_fallback_effective_for_dhcp() -> bool {
    match read_raw_dns_mode().as_deref() {
        Some(DNS_MODE_DHCP) => true,
        Some(DNS_MODE_MANUAL) => false,
        _ => !Path::new(BOOT_RESOLV_FILE).exists(),
    }
}

fn default_dns_mode() -> String {
    if Path::new(BOOT_RESOLV_FILE).exists() {
        DNS_MODE_MANUAL
    } else {
        DNS_MODE_DHCP
    }
    .to_string()
}

fn write_dns_mode(mode: &str) -> Result<()> {
    write_file(
        Path::new(DNS_MODE_FILE),
        format!("{mode}\n").as_bytes(),
        0o644,
    )
}

fn read_manual_dns_servers() -> Vec<String> {
    parse_plain_dns_servers(DNS_SERVERS_FILE).unwrap_or_default()
}

fn preserve_manual_dns_servers() -> Result<()> {
    if !read_manual_dns_servers().is_empty() {
        return Ok(());
    }

    let mut servers = parse_resolv_conf(BOOT_RESOLV_FILE).unwrap_or_default();
    if servers.is_empty() {
        servers = parse_resolv_conf(BOOT_RESOLV_BACKUP).unwrap_or_default();
    }
    if servers.is_empty() {
        return Ok(());
    }

    write_file(
        Path::new(DNS_SERVERS_FILE),
        format!("{}\n", servers.join("\n")).as_bytes(),
        0o644,
    )
}

fn parse_plain_dns_servers(path: &str) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    normalize_dns_servers(content.lines())
}

fn read_dhcp_resolv_config(allow_effective_fallback: bool) -> Result<ResolvConfig> {
    let dhcp_result = parse_resolv_config(DHCP_RESOLV_FILE);
    if let Ok(config) = &dhcp_result {
        if !config.servers.is_empty() {
            return Ok(config.clone());
        }
    }

    let tmp_result = parse_resolv_config(TMP_RESOLV_FILE);
    if let Ok(config) = &tmp_result {
        if !config.servers.is_empty() {
            return Ok(config.clone());
        }
    }

    if allow_effective_fallback {
        let effective_result = parse_resolv_config(ETC_RESOLV_FILE);
        if let Ok(config) = effective_result {
            if !config.servers.is_empty() {
                return Ok(config);
            }
        }
    }

    if let Err(err) = dhcp_result {
        if !is_not_found(&err) {
            return Err(err);
        }
    }
    if let Err(err) = tmp_result {
        if !is_not_found(&err) {
            return Err(err);
        }
    }

    Ok(ResolvConfig::default())
}

fn refresh_dhcp_resolv_cache_from_effective() -> Result<()> {
    let mut config = match parse_resolv_config(ETC_RESOLV_FILE) {
        Ok(config) => config,
        Err(AppError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if config.servers.is_empty() {
        return Ok(());
    }
    if config.search_domains.is_empty() {
        config.search_domains = parse_resolv_config(DHCP_RESOLV_FILE)
            .map(|cached| cached.search_domains)
            .unwrap_or_default();
    }

    render_resolv_config(DHCP_RESOLV_FILE, &config)
}

fn parse_resolv_conf(path: &str) -> Result<Vec<String>> {
    Ok(parse_resolv_config(path)?.servers)
}

fn parse_resolv_config(path: &str) -> Result<ResolvConfig> {
    let content = fs::read_to_string(path)?;
    parse_resolv_config_content(&content)
}

fn parse_resolv_config_content(content: &str) -> Result<ResolvConfig> {
    let mut servers = Vec::new();
    let mut search_domains = Vec::new();

    for line in content.lines() {
        let line = strip_inline_comment(line);
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }

        match fields[0] {
            "nameserver" => servers.push(fields[1].to_string()),
            "search" => search_domains.extend(fields[1..].iter().map(|value| value.to_string())),
            "domain" => search_domains.push(fields[1].to_string()),
            _ => {}
        }
    }

    Ok(ResolvConfig {
        servers: normalize_dns_servers(servers.iter().map(String::as_str))?,
        search_domains: normalize_search_domains(search_domains.iter().map(String::as_str)),
    })
}

fn get_dns_info() -> DnsInfo {
    let (mut iface_name, gateway) = get_default_ipv4_route();
    if iface_name.is_empty() {
        iface_name = get_fallback_ipv4_interface();
    }

    let dhcp_config = read_dhcp_resolv_config(can_fallback_effective_for_dhcp())
        .unwrap_or_else(|_| ResolvConfig::default());

    let mut info = DnsInfo {
        interface: iface_name.clone(),
        gateway,
        search_domains: dhcp_config.search_domains,
        ..DnsInfo::default()
    };

    if iface_name.is_empty() {
        return info;
    }

    info.kind = dns_interface_type(&iface_name)
        .unwrap_or_default()
        .to_string();
    if let Some((address, mask)) = get_ipv4_address_info(&iface_name) {
        info.address = address;
        info.subnet_mask = mask;
    }

    info
}

fn get_default_ipv4_route() -> (String, String) {
    let Ok(content) = fs::read_to_string("/proc/net/route") else {
        return (String::new(), String::new());
    };

    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[1] != "00000000" {
            continue;
        }

        return (
            fields[0].to_string(),
            parse_route_gateway(fields[2]).unwrap_or_default(),
        );
    }

    (String::new(), String::new())
}

fn parse_route_gateway(value: &str) -> Option<String> {
    let gateway = u32::from_str_radix(value, 16).ok()?;
    if gateway == 0 {
        return None;
    }
    Some(
        Ipv4Addr::new(
            (gateway & 0xff) as u8,
            ((gateway >> 8) & 0xff) as u8,
            ((gateway >> 16) & 0xff) as u8,
            ((gateway >> 24) & 0xff) as u8,
        )
        .to_string(),
    )
}

fn get_fallback_ipv4_interface() -> String {
    let Ok(addrs) = getifaddrs() else {
        return String::new();
    };
    let mut seen = HashSet::new();

    for iface in addrs {
        if !seen.insert(iface.interface_name.clone()) {
            continue;
        }
        if !iface.flags.contains(InterfaceFlags::IFF_UP) {
            continue;
        }
        if dns_interface_type(&iface.interface_name).is_none() {
            continue;
        }
        if get_ipv4_address_info(&iface.interface_name).is_some() {
            return iface.interface_name;
        }
    }

    String::new()
}

fn dns_interface_type(name: &str) -> Option<&'static str> {
    if name.starts_with("eth") || name.starts_with("en") {
        Some("Wired")
    } else if name.starts_with("wlan") || name.starts_with("wl") {
        Some("Wireless")
    } else {
        None
    }
}

fn get_ipv4_address_info(name: &str) -> Option<(String, String)> {
    let addrs = getifaddrs().ok()?;
    for iface in addrs {
        if iface.interface_name != name {
            continue;
        }

        let Some(address) = iface
            .address
            .and_then(|address| address.as_sockaddr_in().cloned())
        else {
            continue;
        };
        let Some(mask) = iface
            .netmask
            .and_then(|mask| mask.as_sockaddr_in().cloned())
        else {
            continue;
        };
        let address = address.ip();
        let mask = mask.ip();
        let prefix = u32::from(mask).count_ones();
        return Some((format!("{address}/{prefix}"), mask.to_string()));
    }

    None
}

fn render_resolv_conf(path: &str, servers: &[String]) -> Result<()> {
    render_resolv_config(
        path,
        &ResolvConfig {
            servers: servers.to_vec(),
            search_domains: Vec::new(),
        },
    )
}

fn render_resolv_config(path: &str, config: &ResolvConfig) -> Result<()> {
    let servers = validate_dns_servers(&config.servers)?;
    if servers.is_empty() {
        return Err(AppError::BadRequest("dns servers are required".to_string()));
    }

    let mut content = String::new();
    let search_domains = normalize_search_domains(config.search_domains.iter().map(String::as_str));
    if !search_domains.is_empty() {
        content.push_str("search ");
        content.push_str(&search_domains.join(" "));
        content.push('\n');
    }
    for server in servers {
        content.push_str("nameserver ");
        content.push_str(&server);
        content.push('\n');
    }

    write_file(Path::new(path), content.as_bytes(), 0o644)
}

fn validate_dns_servers<S, I>(servers: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let normalized = normalize_dns_servers(servers)?;
    if normalized.len() > MAX_DNS_SERVERS {
        return Err(AppError::BadRequest("too many dns servers".to_string()));
    }

    Ok(normalized)
}

fn normalize_dns_servers<S, I>(servers: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for server in servers {
        let server = normalize_dns_server(server.as_ref());
        if server.is_empty() {
            continue;
        }

        let ip: IpAddr = server
            .parse()
            .map_err(|_| AppError::BadRequest(format!("invalid dns server: {server}")))?;
        let server = ip.to_string();
        if seen.insert(server.clone()) {
            normalized.push(server);
        }
    }

    Ok(normalized)
}

fn normalize_search_domains<'a, I>(domains: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for domain in domains {
        let domain = domain.trim();
        if domain.is_empty() {
            continue;
        }
        if seen.insert(domain.to_string()) {
            normalized.push(domain.to_string());
        }
    }

    normalized
}

fn normalize_dns_server(server: &str) -> String {
    strip_inline_comment(server)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

fn strip_inline_comment(value: &str) -> &str {
    value.split_once('#').map(|(head, _)| head).unwrap_or(value)
}

fn backup_and_remove_boot_resolv() -> Result<()> {
    let data = match fs::read(BOOT_RESOLV_FILE) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    write_file(Path::new(BOOT_RESOLV_BACKUP), &data, 0o644)?;
    remove_file_if_exists(BOOT_RESOLV_FILE)
}

fn install_udhcpc_dns_hook() -> Result<()> {
    write_file(
        Path::new(UDHCPC_HOOK_FILE),
        UDHCPC_DNS_HOOK.as_bytes(),
        0o755,
    )
}

fn write_file(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp = tmp_path_for(path);
    fs::write(&tmp, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_file_name(format!(".{filename}.{}.{}.tmp", std::process::id(), stamp))
}

fn remove_file_if_exists(path: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn is_not_found(err: &AppError) -> bool {
    matches!(err, AppError::Io(io) if io.kind() == std::io::ErrorKind::NotFound)
}

fn command_error(message: &str, output: crate::system::command::CommandOutput) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stderr.trim();
    if !detail.is_empty() {
        format!("{message}: {detail}")
    } else {
        let detail = stdout.trim();
        if detail.is_empty() {
            message.to_string()
        } else {
            format!("{message}: {detail}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mac_formats() {
        assert_eq!(parse_mac("aa-bb.cc:dd-eeff").unwrap(), "AA:BB:CC:DD:EE:FF");
        assert!(parse_mac("AA:BB:CC:DD:EE:FG").is_err());
        assert!(parse_mac("AA:BB:CC:DD:EE").is_err());
    }

    #[test]
    fn sanitizes_wol_names() {
        assert_eq!(sanitize_wol_mac_name("  office   pc  "), "office pc");
        assert_eq!(format_wol_mac_line("AA:BB", ""), "AA:BB");
        assert_eq!(format_wol_mac_line("AA:BB", "host"), "AA:BB host");
    }

    #[test]
    fn parses_resolv_config() {
        let config = parse_resolv_config_content(
            "search lan example\nnameserver 1.1.1.1 # cloudflare\nnameserver 2606:4700:4700::1111\n",
        )
        .unwrap();
        assert_eq!(config.servers, vec!["1.1.1.1", "2606:4700:4700::1111"]);
        assert_eq!(config.search_domains, vec!["lan", "example"]);
    }

    #[test]
    fn rejects_invalid_dns_servers() {
        assert!(normalize_dns_servers(["1.1.1.1", "1.1.1.1"]).is_ok());
        assert!(normalize_dns_servers(["999.1.1.1"]).is_err());
    }

    #[test]
    fn parses_little_endian_route_gateway() {
        assert_eq!(
            parse_route_gateway("0100570A").as_deref(),
            Some("10.87.0.1")
        );
        assert_eq!(parse_route_gateway("00000000"), None);
    }
}
