//! Closed restore schema. File contents never select privileged destinations.

pub(super) const REQUIRED: &[&str] = &[
    "etc/passwd",
    "etc/group",
    "etc/shadow",
    "etc/hostname",
    "etc/kvm/pwd",
];

pub(super) const FIXED: &[&str] = &[
    "etc/gshadow",
    "etc/hosts",
    "etc/machine-id",
    "device_key",
    "etc/kvm/session_secret",
    "etc/kvm/server.yaml",
    "etc/kvm/server.crt",
    "etc/kvm/server.key",
    "etc/kvm/backend",
    "etc/kvm/shortcuts.json",
    "etc/kvm/leader-key",
    "etc/kvm/web-title",
    "etc/kvm/oled_sleep",
    "etc/kvm/mouse-jiggler",
    "etc/kvm/firewall.json",
    "etc/kvm/syslog.json",
    "etc/kvm/time.json",
    "etc/kvm/network/dns.mode",
    "etc/kvm/network/dns.servers",
    "etc/kvm/wifi.ssid",
    "etc/kvm/wifi.pass",
    "etc/kvm/GOMEMLIMIT",
    "etc/kvm/cache/wol",
    "etc/ssh/sshd_config",
    "etc/ssh/ssh_config",
    "etc/ssh/moduli",
    "etc/ssh/ssh_host_rsa_key",
    "etc/ssh/ssh_host_rsa_key.pub",
    "etc/ssh/ssh_host_ed25519_key",
    "etc/ssh/ssh_host_ed25519_key.pub",
    "etc/ssh/ssh_host_ecdsa_key",
    "etc/ssh/ssh_host_ecdsa_key.pub",
    "etc/dropbear/dropbear_rsa_host_key",
    "etc/dropbear/dropbear_ecdsa_host_key",
    "etc/dropbear/dropbear_ed25519_host_key",
    "root/.ssh/authorized_keys",
    "root/.ssh/known_hosts",
    "root/.ssh/config",
    "root/.ssh/id_rsa",
    "root/.ssh/id_rsa.pub",
    "root/.ssh/id_ed25519",
    "root/.ssh/id_ed25519.pub",
    "root/.ssh/id_ecdsa",
    "root/.ssh/id_ecdsa.pub",
    "root/.picoclaw/config.json",
    "root/.picoclaw/.security.yml",
    "var/lib/tailscale/tailscaled.state",
    "kvmapp/kvm/ap.ssid",
    "kvmapp/kvm/ap.pass",
    "kvmapp/kvm/type",
    "kvmapp/kvm/fps",
    "kvmapp/kvm/qlty",
    "kvmapp/kvm/gop",
    "kvmapp/kvm/res",
    "mnt/data/sensor_cfg.ini.LT",
    "mnt/data/sensor_cfg.ini.OA",
    "mnt/data/sensor_cfg.ini.SC035",
    "mnt/data/sensor_cfg.ini.alpha",
    "mnt/data/sensor_cfg.ini.beta",
];

// Absence is meaningful for these settings. A snapshot has exactly one write
// or absent record for each, so signed-image defaults cannot silently enable a
// device/function the user disabled. No identity/trust path can be deleted.
pub(super) const PRESENCE: &[&str] = &[
    "boot/eth.nodhcp",
    "boot/eth.mac",
    "boot/eth.ipv6.mode",
    "boot/eth.ipv6",
    "boot/resolv.conf",
    "boot/resolv.conf.manual.bak",
    "boot/hostname",
    "boot/hostname.prefix",
    "boot/usb.vid",
    "boot/usb.pid",
    "boot/usb.wakeup",
    "boot/usb.notwakeup",
    "boot/usb.ncm",
    "boot/usb.rndis0",
    "boot/usb.disk0",
    "boot/disable_hid",
    "boot/BIOS",
    "boot/wifi.ssid",
    "boot/wifi.pass",
    "boot/wifi.nodhcp",
    "boot/start_ssh_once",
    "boot/logo.ico",
    "etc/kvm/ssh_stop",
    "etc/kvm/hdmi_disable",
    "etc/kvm/h264_safe_mode",
    "etc/kvm/preview_updates",
    "etc/kvm/rust_hwmon_enabled",
    "etc/kvm/watchdog",
];

pub(super) const TREES: &[&str] = &[
    "etc/kvm/scripts",
    "etc/kvm/autostart",
    "root/.picoclaw/workspace",
    "etc/ssh/sshd_config.d",
    "etc/ssh/ssh_config.d",
];

pub(super) fn allowed(path: &str) -> bool {
    if REQUIRED.contains(&path) || FIXED.contains(&path) || PRESENCE.contains(&path) {
        return true;
    }
    for root in ["etc/kvm/scripts/", "etc/kvm/autostart/"] {
        if let Some(name) = path.strip_prefix(root) {
            return !name.is_empty()
                && !name.contains('/')
                && !name.starts_with('.')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        }
    }
    for root in ["etc/ssh/sshd_config.d/", "etc/ssh/ssh_config.d/"] {
        if let Some(name) = path.strip_prefix(root) {
            return !name.contains('/')
                && name.ends_with(".conf")
                && !name.starts_with('.')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        }
    }
    if let Some(relative) = path.strip_prefix("root/.picoclaw/workspace/") {
        // Shipped control profile/skill are regenerated from the signed app.
        return relative != "AGENT.md"
            && relative != "skills/kvm-control"
            && !relative.starts_with("skills/kvm-control/");
    }
    false
}

pub(super) fn mode(path: &str) -> u32 {
    match path {
        "etc/passwd" | "etc/group" | "etc/hostname" | "etc/hosts" | "etc/machine-id" => 0o644,
        _ => 0o600,
    }
}
