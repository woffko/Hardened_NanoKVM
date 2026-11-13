use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const OUTPUT_PATH: &str = "/run/nanokvm-hwmon-state.json";
const DEFAULT_INTERVAL_SECS: u64 = 5;
const KNOWN_INTERFACES: &[&str] = &["eth0", "wlan0", "usb0", "tailscale0", "lo"];

#[derive(Debug, Serialize)]
struct Snapshot {
    schema: &'static str,
    generated_at_unix_ms: u128,
    interfaces: BTreeMap<String, InterfaceSnapshot>,
    network: NetworkSnapshot,
    usb: UsbSnapshot,
    hdmi: HdmiSnapshot,
    stream: StreamSnapshot,
    markers: MarkerSnapshot,
}

#[derive(Debug, Default, Serialize)]
struct InterfaceSnapshot {
    exists: bool,
    flags_up: bool,
    flags_running: bool,
    operstate: Option<String>,
    carrier: Option<String>,
    mac: Option<String>,
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

#[derive(Debug, Serialize)]
struct NetworkSnapshot {
    interfaces: BTreeMap<String, NetworkInterfaceSnapshot>,
    default_routes: Vec<DefaultRouteSnapshot>,
}

#[derive(Debug, Serialize)]
struct NetworkInterfaceSnapshot {
    exists: bool,
    up: bool,
    running: bool,
    carrier: bool,
    route_state: i8,
    route_state_label: &'static str,
    primary_ipv4: Option<String>,
    primary_ipv6: Option<String>,
    has_default_ipv4_route: bool,
    default_ipv4_gateway: Option<String>,
    has_default_ipv6_route: bool,
    default_ipv6_gateway: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DefaultRouteSnapshot {
    family: &'static str,
    interface: String,
    gateway: Option<String>,
    metric: Option<u32>,
    flags: Option<String>,
}

#[derive(Debug, Serialize)]
struct UsbSnapshot {
    udc_state: Option<String>,
    hid_enabled: bool,
    mass_storage_enabled: bool,
    rndis_enabled: bool,
}

#[derive(Debug, Serialize)]
struct HdmiSnapshot {
    active: Option<bool>,
    vi_fps: Option<String>,
    vi_dbg_line: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
}

#[derive(Debug, Serialize)]
struct StreamSnapshot {
    #[serde(rename = "type")]
    stream_type: Option<String>,
    now_fps: Option<u32>,
    fps: Option<u32>,
    qlty: Option<u32>,
    gop: Option<u32>,
    res: Option<u32>,
    state: Option<u32>,
    width: Option<u32>,
    height: Option<u32>,
}

#[derive(Debug, Serialize)]
struct MarkerSnapshot {
    oled_exists: bool,
    frame_detect_marker: bool,
    watchdog_enabled: bool,
    watchdog_temp: bool,
    wifi_exists: bool,
    wifi_ap_mode: bool,
    h264_safe_mode: bool,
}

fn main() {
    let once = env::args().any(|arg| arg == "--once");
    let interval = env::var("NANOKVM_HWMON_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(1, 300))
        .unwrap_or(DEFAULT_INTERVAL_SECS);

    loop {
        if let Err(err) = write_snapshot(OUTPUT_PATH) {
            eprintln!("failed to write hwmon snapshot: {err}");
        }
        if once {
            break;
        }
        thread::sleep(Duration::from_secs(interval));
    }
}

fn write_snapshot(path: &str) -> io::Result<()> {
    let snapshot = collect_snapshot();
    let data = serde_json::to_vec_pretty(&snapshot)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    write_replacing(Path::new(path), &data)
}

/// Replace `path` through a fresh temporary file beside it. The runtime
/// destination is under protected `/run`; the temporary file is created
/// exclusively without following links: a planted file or link is never
/// written through. The rename replaces a link at `path`; it never follows it.
fn write_replacing(path: &Path, data: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid snapshot path"))?;
    let mut random = [0_u8; 8];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(io::Error::other)?;
    let temp = path.with_file_name(format!(".{name}.{:016x}.tmp", u64::from_le_bytes(random)));
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temp)?;
        file.write_all(data)?;
        fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written
}

fn collect_snapshot() -> Snapshot {
    let interfaces = collect_interfaces();
    let default_routes = collect_default_routes();
    let network = collect_network(&interfaces, default_routes);

    Snapshot {
        schema: "nanokvm-hwmon/v1",
        generated_at_unix_ms: unix_ms(),
        interfaces,
        network,
        usb: collect_usb(),
        hdmi: collect_hdmi(),
        stream: collect_stream(),
        markers: collect_markers(),
    }
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn collect_interfaces() -> BTreeMap<String, InterfaceSnapshot> {
    let mut names = BTreeSet::new();
    for name in KNOWN_INTERFACES {
        names.insert((*name).to_string());
    }
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                names.insert(name.to_string());
            }
        }
    }

    let mut interfaces = BTreeMap::new();
    for name in names {
        let sysfs = Path::new("/sys/class/net").join(&name);
        interfaces.insert(
            name.clone(),
            InterfaceSnapshot {
                exists: sysfs.exists(),
                operstate: read_trimmed(sysfs.join("operstate")),
                carrier: read_trimmed(sysfs.join("carrier")),
                mac: read_trimmed(sysfs.join("address")),
                ..InterfaceSnapshot::default()
            },
        );
    }

    if let Ok(addrs) = getifaddrs() {
        for iface in addrs {
            let entry = interfaces.entry(iface.interface_name.clone()).or_default();
            entry.exists = true;
            entry.flags_up |= iface.flags.contains(InterfaceFlags::IFF_UP);
            entry.flags_running |= iface.flags.contains(InterfaceFlags::IFF_RUNNING);

            let Some(address) = iface.address else {
                continue;
            };
            if let Some(ipv4) = address.as_sockaddr_in().map(|addr| addr.ip()) {
                push_unique(&mut entry.ipv4, ipv4.to_string());
            } else if let Some(ipv6) = address.as_sockaddr_in6().map(|addr| addr.ip()) {
                push_unique(&mut entry.ipv6, ipv6.to_string());
            }
        }
    }

    interfaces
}

fn collect_network(
    interfaces: &BTreeMap<String, InterfaceSnapshot>,
    default_routes: Vec<DefaultRouteSnapshot>,
) -> NetworkSnapshot {
    let mut normalized = BTreeMap::new();

    for name in ["eth0", "wlan0", "usb0", "tailscale0"] {
        let interface = interfaces.get(name);
        let default_ipv4_route = default_routes
            .iter()
            .find(|route| route.family == "ipv4" && route.interface == name);
        let default_ipv6_route = default_routes
            .iter()
            .find(|route| route.family == "ipv6" && route.interface == name);

        let exists = interface.map(|iface| iface.exists).unwrap_or_default();
        let up = interface.map(|iface| iface.flags_up).unwrap_or_default();
        let running = interface
            .map(|iface| iface.flags_running)
            .unwrap_or_default();
        let carrier = interface
            .and_then(|iface| iface.carrier.as_deref())
            .map(|carrier| carrier == "1")
            .unwrap_or(running);
        let primary_ipv4 = interface.and_then(|iface| iface.ipv4.first().cloned());
        let primary_ipv6 = interface.and_then(|iface| iface.ipv6.first().cloned());
        let has_address = primary_ipv4.is_some() || primary_ipv6.is_some();
        let has_default_route = default_ipv4_route.is_some() || default_ipv6_route.is_some();
        let link_ready = running || carrier;
        let (route_state, route_state_label) =
            route_state(exists, link_ready, has_address, has_default_route);

        normalized.insert(
            name.to_string(),
            NetworkInterfaceSnapshot {
                exists,
                up,
                running,
                carrier,
                route_state,
                route_state_label,
                primary_ipv4,
                primary_ipv6,
                has_default_ipv4_route: default_ipv4_route.is_some(),
                default_ipv4_gateway: default_ipv4_route.and_then(|route| route.gateway.clone()),
                has_default_ipv6_route: default_ipv6_route.is_some(),
                default_ipv6_gateway: default_ipv6_route.and_then(|route| route.gateway.clone()),
            },
        );
    }

    NetworkSnapshot {
        interfaces: normalized,
        default_routes,
    }
}

fn route_state(
    exists: bool,
    link_ready: bool,
    has_address: bool,
    has_default_route: bool,
) -> (i8, &'static str) {
    if !exists {
        return (-2, "missing");
    }
    if !link_ready {
        return (0, "down");
    }
    if !has_address {
        return (1, "link");
    }
    if has_default_route {
        return (3, "routed");
    }
    (2, "addressed")
}

fn collect_default_routes() -> Vec<DefaultRouteSnapshot> {
    let mut routes = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/net/route") {
        routes.extend(parse_ipv4_default_routes(&content));
    }
    if let Ok(content) = fs::read_to_string("/proc/net/ipv6_route") {
        routes.extend(parse_ipv6_default_routes(&content));
    }
    routes
}

fn parse_ipv4_default_routes(content: &str) -> Vec<DefaultRouteSnapshot> {
    content
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8 || fields[1] != "00000000" {
                return None;
            }
            Some(DefaultRouteSnapshot {
                family: "ipv4",
                interface: fields[0].to_string(),
                gateway: parse_ipv4_route_gateway(fields[2]),
                metric: fields[6].parse().ok(),
                flags: Some(fields[3].to_string()),
            })
        })
        .collect()
}

fn parse_ipv6_default_routes(content: &str) -> Vec<DefaultRouteSnapshot> {
    content
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10
                || fields[0] != "00000000000000000000000000000000"
                || fields[1] != "00"
            {
                return None;
            }
            let interface = fields[9].to_string();
            let gateway = parse_ipv6_route_gateway(fields[4]);
            let metric = u32::from_str_radix(fields[5], 16).ok();
            if interface == "lo" && gateway.is_none() {
                return None;
            }
            if metric == Some(u32::MAX) {
                return None;
            }
            Some(DefaultRouteSnapshot {
                family: "ipv6",
                interface,
                gateway,
                metric,
                flags: Some(fields[8].to_string()),
            })
        })
        .collect()
}

fn parse_ipv4_route_gateway(value: &str) -> Option<String> {
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

fn parse_ipv6_route_gateway(value: &str) -> Option<String> {
    if value.len() != 32 || value == "00000000000000000000000000000000" {
        return None;
    }

    let mut segments = [0_u16; 8];
    for (index, segment) in segments.iter_mut().enumerate() {
        let start = index * 4;
        *segment = u16::from_str_radix(&value[start..start + 4], 16).ok()?;
    }
    Some(
        Ipv6Addr::new(
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        )
        .to_string(),
    )
}

fn collect_usb() -> UsbSnapshot {
    let config = Path::new("/sys/kernel/config/usb_gadget/g0/configs/c.1");
    let entries = dir_names(config);
    UsbSnapshot {
        udc_state: read_trimmed("/sys/class/udc/4340000.usb/state"),
        hid_enabled: entries.iter().any(|name| name.starts_with("hid.")),
        mass_storage_enabled: entries.iter().any(|name| name == "mass_storage.disk0"),
        rndis_enabled: entries.iter().any(|name| name == "rndis.usb0"),
    }
}

fn collect_hdmi() -> HdmiSnapshot {
    let vi_dbg = fs::read_to_string("/proc/cvitek/vi_dbg").ok();
    let vi_dbg_line = vi_dbg
        .as_deref()
        .and_then(|content| content.lines().find(|line| line.contains("VIFPS")))
        .map(str::trim)
        .map(str::to_string);
    let vi_fps = vi_dbg_line.as_deref().and_then(parse_vi_fps);
    let active = vi_fps
        .as_deref()
        .and_then(|value| value.parse::<f64>().ok())
        .map(|fps| fps > 0.0);

    HdmiSnapshot {
        active,
        vi_fps,
        vi_dbg_line,
        width: read_u32("/kvmapp/kvm/width"),
        height: read_u32("/kvmapp/kvm/height"),
    }
}

fn collect_stream() -> StreamSnapshot {
    StreamSnapshot {
        stream_type: read_trimmed("/kvmapp/kvm/type"),
        now_fps: read_u32("/kvmapp/kvm/now_fps"),
        fps: read_u32("/kvmapp/kvm/fps"),
        qlty: read_u32("/kvmapp/kvm/qlty"),
        gop: read_u32("/kvmapp/kvm/gop"),
        res: read_u32("/kvmapp/kvm/res"),
        state: read_u32("/kvmapp/kvm/state"),
        width: read_u32("/kvmapp/kvm/width"),
        height: read_u32("/kvmapp/kvm/height"),
    }
}

fn collect_markers() -> MarkerSnapshot {
    MarkerSnapshot {
        oled_exists: Path::new("/etc/kvm/oled_exist").exists(),
        frame_detect_marker: Path::new("/etc/kvm/frame_detact").exists(),
        watchdog_enabled: Path::new("/etc/kvm/watchdog").exists(),
        watchdog_temp: Path::new("/run/nanokvm-vision-watchdog").exists(),
        wifi_exists: Path::new("/etc/kvm/wifi_exist").exists(),
        wifi_ap_mode: Path::new("/run/nanokvm-wifiap").exists(),
        h264_safe_mode: Path::new("/etc/kvm/h264_safe_mode").exists(),
    }
}

fn parse_vi_fps(line: &str) -> Option<String> {
    line.split_whitespace().nth(2).map(str::to_string)
}

fn read_trimmed<P: AsRef<Path>>(path: P) -> Option<String> {
    let value = fs::read_to_string(path).ok()?;
    let value = value.trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn read_u32(path: &str) -> Option<u32> {
    read_trimmed(path)?.parse().ok()
}

fn dir_names(path: &Path) -> Vec<String> {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.flatten())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .collect()
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_snapshot_never_writes_through_a_planted_link() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nanokvm-hwmon-state.json");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"unrelated").unwrap();
        // RC12 used a predictable "<path>.<pid>.tmp" and followed links.
        symlink(
            &victim,
            dir.path().join(format!(
                "nanokvm-hwmon-state.json.{}.tmp",
                std::process::id()
            )),
        )
        .unwrap();
        symlink(&victim, &path).unwrap();
        super::write_replacing(&path, b"{}").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"unrelated");
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let leftovers = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|entry| {
                let name = entry.as_ref().unwrap().file_name();
                name.to_string_lossy().ends_with(".tmp") && name.to_string_lossy().starts_with('.')
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    use super::{
        parse_ipv4_default_routes, parse_ipv4_route_gateway, parse_ipv6_default_routes,
        parse_ipv6_route_gateway, parse_vi_fps, route_state,
    };

    #[test]
    fn parses_vi_fps_from_vendor_line() {
        assert_eq!(parse_vi_fps("VIFPS\t\t\t:  60"), Some("60".to_string()));
        assert_eq!(parse_vi_fps("VIFPS : 59.94"), Some("59.94".to_string()));
        assert_eq!(parse_vi_fps("too-short"), None);
    }

    #[test]
    fn parses_little_endian_ipv4_gateway() {
        assert_eq!(
            parse_ipv4_route_gateway("0557000A").as_deref(),
            Some("10.0.87.5")
        );
        assert_eq!(parse_ipv4_route_gateway("00000000"), None);
    }

    #[test]
    fn parses_default_ipv4_routes() {
        let routes = parse_ipv4_default_routes(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
             eth0 00000000 0557000A 0003 0 0 10 00000000 0 0 0\n\
             eth0 0057000A 00000000 0001 0 0 0 00FFFFFF 0 0 0\n",
        );

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].family, "ipv4");
        assert_eq!(routes[0].interface, "eth0");
        assert_eq!(routes[0].gateway.as_deref(), Some("10.0.87.5"));
        assert_eq!(routes[0].metric, Some(10));
    }

    #[test]
    fn parses_ipv6_route_gateway() {
        assert_eq!(
            parse_ipv6_route_gateway("fe800000000000000000000000000001").as_deref(),
            Some("fe80::1")
        );
        assert_eq!(
            parse_ipv6_route_gateway("00000000000000000000000000000000"),
            None
        );
    }

    #[test]
    fn parses_default_ipv6_routes() {
        let routes = parse_ipv6_default_routes(
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
             fe800000000000000000000000000001 00000400 00000000 00000000 00000003 eth0\n\
             fd001234abcd00010000000000000000 40 00000000000000000000000000000000 00 \
             00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0\n\
             00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
             00000000000000000000000000000000 ffffffff 00000000 00000000 00200200 lo\n",
        );

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].family, "ipv6");
        assert_eq!(routes[0].interface, "eth0");
        assert_eq!(routes[0].gateway.as_deref(), Some("fe80::1"));
        assert_eq!(routes[0].metric, Some(1024));
    }

    #[test]
    fn route_state_matches_legacy_display_levels_without_ping() {
        assert_eq!(route_state(false, false, false, false), (-2, "missing"));
        assert_eq!(route_state(true, false, false, false), (0, "down"));
        assert_eq!(route_state(true, true, false, false), (1, "link"));
        assert_eq!(route_state(true, true, true, false), (2, "addressed"));
        assert_eq!(route_state(true, true, true, true), (3, "routed"));
    }
}
