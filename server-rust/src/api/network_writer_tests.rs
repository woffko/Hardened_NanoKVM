use super::*;

// The address of one AP client, for direct calls of the unauthenticated handlers.
fn ap_client() -> ConnectInfo<ClientAddr> {
    ConnectInfo(ClientAddr("192.168.4.100:40000".parse().unwrap()))
}
use crate::{config::Config, update::state_writers::StateWriters};
use std::{
    fs::File,
    os::unix::fs::PermissionsExt,
    sync::Arc,
    task::{Context, Poll, Waker},
};

const LIMIT: Duration = Duration::from_secs(5);
const MAC: &str = "02:00:00:00:00:01";
const OTHER_MAC: &str = "02:00:00:00:00:02";

fn path(root: &Path, fixed: &str) -> PathBuf {
    root.join(fixed.trim_start_matches('/'))
}

fn put(root: &Path, fixed: &str, data: &str) {
    let file = path(root, fixed);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, data).unwrap();
}

fn read(root: &Path, fixed: &str) -> String {
    fs::read_to_string(path(root, fixed)).unwrap()
}

async fn fixture() -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.paths.account_file = dir.path().join("pwd");
    config.paths.session_secret_file = dir.path().join("session_secret");
    let mut state = AppState::new(config).await.unwrap();
    state.writers = Arc::new(StateWriters::for_test_config(
        File::open(dir.path()).unwrap(),
        dir.path().join("server.yaml"),
    ));
    put(dir.path(), WIFI_EXIST_FILE, "fixture");
    const SCRIPT: &[u8] = b"#!/bin/sh\nd=${0%/*}\ntag=${0##*/}\nprintf '%s\n' \"$*\" >> \"$d/$tag.args\"\necho started > \"$d/$tag.started\"\nif [ -f \"$d/$tag.block\" ]; then\n while [ ! -f \"$d/$tag.release\" ]; do sleep 0.01; done\nfi\nif [ -f \"$d/$tag.fail\" ]; then exit 1; fi\nif [ -f \"$d/$tag.after-resolv\" ]; then cp \"$d/$tag.after-resolv\" \"$d/etc/resolv.conf\" || exit 1; fi\nexit 0\n";
    for name in ["network-eth", "network-wifi", "network-wol"] {
        let file = dir.path().join(name);
        fs::write(&file, SCRIPT).unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o700)).unwrap();
    }
    (dir, state)
}

fn dns_request(mode: &str) -> SetDnsReq {
    SetDnsReq {
        mode: mode.into(),
        servers: vec!["192.0.2.53".into(), "2001:db8::53".into()],
        interface: Some("eth0".into()),
        address: Some("192.0.2.10/24".into()),
        subnet_mask: None,
        gateway: Some("192.0.2.1".into()),
    }
}

fn ipv6_request(mode: &str) -> SetIpv6Req {
    SetIpv6Req {
        mode: mode.into(),
        interface: Some("eth0".into()),
        address: Some("2001:db8::10/64".into()),
        prefix: None,
        gateway: Some("fe80::1".into()),
    }
}

fn wifi_request() -> ConnectWifiReq {
    ConnectWifiReq {
        ssid: "fixture network".into(),
        password: "fixture-only-password".into(),
    }
}

fn ap_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-ap-key", "fixture-only-ap-key".parse().unwrap());
    headers
}

async fn wait_file(file: &Path) {
    tokio::time::timeout(LIMIT, async {
        while !file.exists() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}

fn assert_no_commands(root: &Path) {
    for name in ["network-eth", "network-wifi", "network-wol"] {
        assert!(!root.join(format!("{name}.args")).exists());
    }
}

#[tokio::test]
async fn lost_manual_dns_reply_retains_files_restart_and_final_resolver_rewrite() {
    let (dir, state) = fixture().await;
    put(dir.path(), ETC_RESOLV_FILE, "nameserver 198.51.100.53\n");
    fs::write(
        dir.path().join("network-eth.after-resolv"),
        b"nameserver 192.0.2.1\n",
    )
    .unwrap();
    let mut request = Box::pin(set_dns(State(state.clone()), Json(dns_request("manual"))));
    assert!(matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(request);
    drop(state.writers.drain(LIMIT).await.unwrap());
    assert_eq!(read(dir.path(), DNS_MODE_FILE), "manual\n");
    assert_eq!(
        read(dir.path(), DNS_SERVERS_FILE),
        "192.0.2.53\n2001:db8::53\n"
    );
    assert_eq!(
        read(dir.path(), BOOT_ETH_NODHCP_FILE),
        "192.0.2.10/24 192.0.2.1\n"
    );
    let selected = "nameserver 192.0.2.53\nnameserver 2001:db8::53\n";
    assert_eq!(read(dir.path(), BOOT_RESOLV_FILE), selected);
    assert_eq!(read(dir.path(), ETC_RESOLV_FILE), selected);
    assert_eq!(
        read(dir.path(), DHCP_RESOLV_FILE),
        "nameserver 198.51.100.53\n"
    );
    assert_eq!(read(dir.path(), UDHCPC_HOOK_FILE), UDHCPC_DNS_HOOK);
    assert_eq!(
        fs::metadata(path(dir.path(), UDHCPC_HOOK_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("network-eth.args")).unwrap(),
        "restart\n"
    );
}

#[tokio::test]
async fn lost_dhcp_reply_keeps_backup_and_post_restart_resolver_publication() {
    let (dir, state) = fixture().await;
    put(dir.path(), BOOT_RESOLV_FILE, "nameserver 192.0.2.53\n");
    put(
        dir.path(),
        BOOT_ETH_NODHCP_FILE,
        "192.0.2.10/24 192.0.2.1\n",
    );
    put(
        dir.path(),
        TMP_RESOLV_FILE,
        "search lab.invalid\nnameserver 198.51.100.53\n",
    );
    let mut request = Box::pin(set_dns(State(state.clone()), Json(dns_request("dhcp"))));
    assert!(matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(request);
    drop(state.writers.drain(LIMIT).await.unwrap());
    assert_eq!(read(dir.path(), DNS_MODE_FILE), "dhcp\n");
    assert_eq!(read(dir.path(), DNS_SERVERS_FILE), "192.0.2.53\n");
    assert_eq!(
        read(dir.path(), BOOT_RESOLV_BACKUP),
        "nameserver 192.0.2.53\n"
    );
    assert!(!path(dir.path(), BOOT_RESOLV_FILE).exists());
    assert!(!path(dir.path(), BOOT_ETH_NODHCP_FILE).exists());
    assert_eq!(
        read(dir.path(), DHCP_RESOLV_FILE),
        "search lab.invalid\nnameserver 198.51.100.53\n"
    );
    assert_eq!(
        read(dir.path(), ETC_RESOLV_FILE),
        read(dir.path(), DHCP_RESOLV_FILE)
    );
}

#[tokio::test]
async fn ipv6_manual_cancel_and_mode_changes_keep_full_service_chain_owned() {
    let (dir, state) = fixture().await;
    let mut request = Box::pin(set_ipv6(State(state.clone()), Json(ipv6_request("manual"))));
    assert!(matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(request);
    drop(state.writers.drain(LIMIT).await.unwrap());
    assert_eq!(
        read(dir.path(), IPV6_CONFIG_FILE),
        "2001:db8::10/64 fe80::1\n"
    );
    assert_eq!(read(dir.path(), IPV6_MODE_FILE), "manual\n");
    // Capability probing is rooted as well; no host DHCPv6 executable is used.
    assert!(matches!(
        set_ipv6(State(state.clone()), Json(ipv6_request("dhcpv6"))).await,
        Err(AppError::BadRequest(_))
    ));
    assert_eq!(read(dir.path(), IPV6_MODE_FILE), "manual\n");
    put(dir.path(), DHCPV6_SCRIPT_FILE, "fixture");
    put(dir.path(), DHCPV6_CLIENT_PATHS[0], "fixture");
    for mode in ["dhcpv6", "slaac", "disabled"] {
        set_ipv6(State(state.clone()), Json(ipv6_request(mode)))
            .await
            .unwrap();
        assert_eq!(read(dir.path(), IPV6_MODE_FILE), format!("{mode}\n"));
        assert!(!path(dir.path(), IPV6_CONFIG_FILE).exists());
    }
    assert_eq!(
        fs::read_to_string(dir.path().join("network-eth.args")).unwrap(),
        "restart\nrestart\nrestart\nrestart\n"
    );
}

#[tokio::test]
async fn lost_wifi_reply_keeps_credentials_marker_removal_and_restart_owned() {
    let (dir, state) = fixture().await;
    put(dir.path(), WIFI_CONNECT_FILE, "old request");
    let mut request = Box::pin(connect_wifi(State(state.clone()), Json(wifi_request())));
    assert!(matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(request);
    drop(state.writers.drain(LIMIT).await.unwrap());
    assert_eq!(read(dir.path(), WIFI_SSID_FILE), "fixture network");
    assert_eq!(
        read(dir.path(), WIFI_PASSWORD_FILE),
        "fixture-only-password"
    );
    for fixed in [WIFI_SSID_FILE, WIFI_PASSWORD_FILE] {
        assert_eq!(
            fs::metadata(path(dir.path(), fixed))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(!path(dir.path(), WIFI_CONNECT_FILE).exists());
    assert_eq!(
        fs::read_to_string(dir.path().join("network-wifi.args")).unwrap(),
        "restart\n"
    );
}

#[tokio::test]
async fn disconnect_cancellation_does_not_drop_stop_or_post_stop_file_cleanup() {
    let (dir, state) = fixture().await;
    put(dir.path(), WIFI_SSID_FILE, "old network");
    put(dir.path(), WIFI_PASSWORD_FILE, "old fixture password");
    fs::write(dir.path().join("network-wifi.block"), b"fixture").unwrap();
    let running = state.clone();
    let request = tokio::spawn(async move { disconnect_wifi(State(running)).await.map(|_| ()) });
    wait_file(&dir.path().join("network-wifi.started")).await;
    assert_eq!(read(dir.path(), WIFI_SSID_FILE), "old network");
    assert!(matches!(
        set_dns(State(state.clone()), Json(dns_request("dhcp"))).await,
        Err(AppError::Conflict(_))
    ));
    request.abort();
    assert!(request.await.err().unwrap().is_cancelled());
    assert!(
        state
            .writers
            .drain(Duration::from_millis(30))
            .await
            .is_err()
    );
    fs::write(dir.path().join("network-wifi.release"), b"fixture").unwrap();
    drop(state.writers.drain(LIMIT).await.unwrap());
    assert!(!path(dir.path(), WIFI_SSID_FILE).exists());
    assert!(!path(dir.path(), WIFI_PASSWORD_FILE).exists());
    assert_eq!(
        fs::read_to_string(dir.path().join("network-wifi.args")).unwrap(),
        "stop\n"
    );
}

#[tokio::test]
async fn ap_publication_survives_reply_loss_but_does_not_claim_native_completion() {
    let (dir, state) = fixture().await;
    put(dir.path(), WIFI_AP_MODE_FILE, "fixture");
    put(dir.path(), WIFI_AP_PASS_FILE, "fixture-only-ap-key\n");
    let mut request = Box::pin(connect_wifi_no_auth(
        State(state.clone()),
        ap_client(),
        ap_headers(),
        Json(wifi_request()),
    ));
    assert!(matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(request);
    drop(state.writers.drain(LIMIT).await.unwrap());
    assert_eq!(read(dir.path(), WIFI_SSID_FILE), "fixture network");
    assert_eq!(
        read(dir.path(), WIFI_PASSWORD_FILE),
        "fixture-only-password"
    );
    assert!(path(dir.path(), WIFI_CONNECT_FILE).exists());
    assert!(!path(dir.path(), WIFI_STATE_FILE).exists());
    assert_no_commands(dir.path());
}

#[tokio::test]
async fn ap_wrong_key_or_mode_never_publishes_credentials_or_marker() {
    let (dir, state) = fixture().await;
    assert!(matches!(
        connect_wifi_no_auth(
            State(state.clone()),
            ap_client(),
            ap_headers(),
            Json(wifi_request())
        )
        .await,
        Err(AppError::BadRequest(_))
    ));
    put(dir.path(), WIFI_AP_MODE_FILE, "fixture");
    put(dir.path(), WIFI_AP_PASS_FILE, "fixture-only-ap-key\n");
    let response = connect_wifi_no_auth(
        State(state.clone()),
        ap_client(),
        HeaderMap::new(),
        Json(wifi_request()),
    )
    .await
    .unwrap()
    .into_response();
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
        -4
    );
    assert!(!path(dir.path(), WIFI_SSID_FILE).exists());
    assert!(!path(dir.path(), WIFI_PASSWORD_FILE).exists());
    assert!(!path(dir.path(), WIFI_CONNECT_FILE).exists());
    assert_no_commands(dir.path());
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn paused_network_mutators_cannot_publish_or_start_service_commands() {
    let (dir, state) = fixture().await;
    let barrier = state.writers.drain(LIMIT).await.unwrap();
    assert!(matches!(
        set_dns(State(state.clone()), Json(dns_request("manual"))).await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        set_ipv6(State(state.clone()), Json(ipv6_request("manual"))).await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        connect_wifi(State(state.clone()), Json(wifi_request())).await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        disconnect_wifi(State(state.clone())).await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        connect_wifi_no_auth(
            State(state.clone()),
            ap_client(),
            ap_headers(),
            Json(wifi_request())
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        delete_wol_mac(State(state.clone()), Json(WolReq { mac: MAC.into() })).await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        set_wol_mac_name(
            State(state.clone()),
            Json(SetWolMacNameReq {
                mac: MAC.into(),
                name: "fixture".into()
            })
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    for fixed in [
        DNS_MODE_FILE,
        IPV6_MODE_FILE,
        WIFI_SSID_FILE,
        WIFI_PASSWORD_FILE,
        WIFI_CONNECT_FILE,
        WOL_MAC_FILE,
    ] {
        assert!(!path(dir.path(), fixed).exists());
    }
    assert_no_commands(dir.path());
    drop(barrier);
}

#[tokio::test]
async fn wol_target_action_still_works_while_local_history_is_paused() {
    let (dir, state) = fixture().await;
    let barrier = state.writers.drain(LIMIT).await.unwrap();
    dispatch_wol(
        state.clone(),
        MAC.into(),
        AllowedCommand::CustomForTest(dir.path().join("network-wol")),
    )
    .await
    .unwrap();
    assert_eq!(
        fs::read_to_string(dir.path().join("network-wol.args")).unwrap(),
        format!("-b {MAC}\n")
    );
    assert!(!path(dir.path(), WOL_MAC_FILE).exists());
    drop(barrier);
    dispatch_wol(
        state.clone(),
        MAC.into(),
        AllowedCommand::CustomForTest(dir.path().join("network-wol")),
    )
    .await
    .unwrap();
    assert_eq!(read(dir.path(), WOL_MAC_FILE), format!("{MAC}\n"));
}

#[tokio::test]
async fn wol_history_serialization_conflicts_and_retry_preserve_other_entries() {
    let (dir, state) = fixture().await;
    put(
        dir.path(),
        WOL_MAC_FILE,
        &format!("{MAC} old\n{OTHER_MAC} keep\n"),
    );
    fs::write(dir.path().join("network-eth.block"), b"fixture").unwrap();
    let running = state.clone();
    let request = tokio::spawn(async move {
        set_dns(State(running), Json(dns_request("dhcp")))
            .await
            .map(|_| ())
    });
    wait_file(&dir.path().join("network-eth.started")).await;
    assert!(matches!(
        set_wol_mac_name(
            State(state.clone()),
            Json(SetWolMacNameReq {
                mac: MAC.into(),
                name: "new name".into()
            })
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        delete_wol_mac(
            State(state.clone()),
            Json(WolReq {
                mac: OTHER_MAC.into()
            })
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    // Target action is independent; its busy optional cache does not overwrite history.
    dispatch_wol(
        state.clone(),
        OTHER_MAC.into(),
        AllowedCommand::CustomForTest(dir.path().join("network-wol")),
    )
    .await
    .unwrap();
    assert_eq!(
        read(dir.path(), WOL_MAC_FILE),
        format!("{MAC} old\n{OTHER_MAC} keep\n")
    );
    fs::write(dir.path().join("network-eth.release"), b"fixture").unwrap();
    request.await.unwrap().unwrap();
    set_wol_mac_name(
        State(state.clone()),
        Json(SetWolMacNameReq {
            mac: MAC.into(),
            name: "new   name\n".into(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        read(dir.path(), WOL_MAC_FILE),
        format!("{MAC} new name\n{OTHER_MAC} keep\n")
    );
    delete_wol_mac(
        State(state.clone()),
        Json(WolReq {
            mac: OTHER_MAC.into(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(read(dir.path(), WOL_MAC_FILE), format!("{MAC} new name\n"));
    dispatch_wol(
        state.clone(),
        MAC.into(),
        AllowedCommand::CustomForTest(dir.path().join("network-wol")),
    )
    .await
    .unwrap();
    assert_eq!(read(dir.path(), WOL_MAC_FILE), format!("{MAC} new name\n"));
}

#[tokio::test]
async fn wol_command_failure_and_unreadable_history_do_not_clobber_cache() {
    let (dir, state) = fixture().await;
    fs::write(dir.path().join("network-wol.fail"), b"fixture").unwrap();
    assert!(
        dispatch_wol(
            state.clone(),
            MAC.into(),
            AllowedCommand::CustomForTest(dir.path().join("network-wol"))
        )
        .await
        .is_err()
    );
    assert!(!path(dir.path(), WOL_MAC_FILE).exists());
    fs::remove_file(dir.path().join("network-wol.fail")).unwrap();
    fs::create_dir_all(path(dir.path(), WOL_MAC_FILE)).unwrap();
    put(dir.path(), "/etc/kvm/cache/wol/keep", "fixture");
    assert!(
        delete_wol_mac(State(state.clone()), Json(WolReq { mac: MAC.into() }))
            .await
            .is_err()
    );
    dispatch_wol(
        state.clone(),
        MAC.into(),
        AllowedCommand::CustomForTest(dir.path().join("network-wol")),
    )
    .await
    .unwrap();
    assert_eq!(read(dir.path(), "/etc/kvm/cache/wol/keep"), "fixture");
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn lost_wol_edit_replies_still_finish_the_serial_read_modify_write() {
    let (dir, state) = fixture().await;
    put(
        dir.path(),
        WOL_MAC_FILE,
        &format!("{MAC} old\n{OTHER_MAC} keep\n"),
    );
    let mut rename = Box::pin(set_wol_mac_name(
        State(state.clone()),
        Json(SetWolMacNameReq {
            mac: MAC.into(),
            name: "new name".into(),
        }),
    ));
    assert!(matches!(
        rename
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(rename);
    drop(state.writers.drain(LIMIT).await.unwrap());
    assert_eq!(
        read(dir.path(), WOL_MAC_FILE),
        format!("{MAC} new name\n{OTHER_MAC} keep\n")
    );
    let mut delete = Box::pin(delete_wol_mac(
        State(state.clone()),
        Json(WolReq {
            mac: OTHER_MAC.into(),
        }),
    ));
    assert!(matches!(
        delete
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(delete);
    drop(state.writers.drain(LIMIT).await.unwrap());
    assert_eq!(read(dir.path(), WOL_MAC_FILE), format!("{MAC} new name\n"));
    assert_no_commands(dir.path());
}

#[tokio::test]
async fn invalid_network_inputs_never_write_settings_or_start_services() {
    let (dir, state) = fixture().await;
    let mut dns = dns_request("manual");
    dns.servers = vec!["not a DNS address".into()];
    assert!(matches!(
        set_dns(State(state.clone()), Json(dns)).await,
        Err(AppError::BadRequest(_))
    ));
    assert!(matches!(
        set_dns(State(state.clone()), Json(dns_request("invalid"))).await,
        Err(AppError::BadRequest(_))
    ));
    let mut ipv6 = ipv6_request("manual");
    ipv6.address = Some("fe80::10/64".into());
    assert!(matches!(
        set_ipv6(State(state.clone()), Json(ipv6)).await,
        Err(AppError::BadRequest(_))
    ));
    let mut wifi = wifi_request();
    wifi.ssid = "bad\nssid".into();
    assert!(matches!(
        connect_wifi(State(state.clone()), Json(wifi)).await,
        Err(AppError::BadRequest(_))
    ));
    for fixed in [
        DNS_MODE_FILE,
        IPV6_MODE_FILE,
        WIFI_SSID_FILE,
        WIFI_PASSWORD_FILE,
    ] {
        assert!(!path(dir.path(), fixed).exists());
    }
    assert_no_commands(dir.path());
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn publication_error_remains_partial_but_does_not_start_service_or_leak_owner() {
    let (dir, state) = fixture().await;
    fs::create_dir_all(path(dir.path(), BOOT_ETH_NODHCP_FILE)).unwrap();
    assert!(
        set_dns(State(state.clone()), Json(dns_request("manual")))
            .await
            .is_err()
    );
    assert_eq!(read(dir.path(), DNS_MODE_FILE), "manual\n");
    assert_eq!(
        read(dir.path(), DNS_SERVERS_FILE),
        "192.0.2.53\n2001:db8::53\n"
    );
    assert_no_commands(dir.path());
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn wifi_stop_failure_preserves_credentials_and_releases_owned_work() {
    let (dir, state) = fixture().await;
    put(dir.path(), WIFI_SSID_FILE, "old network");
    put(dir.path(), WIFI_PASSWORD_FILE, "old fixture password");
    fs::write(dir.path().join("network-wifi.fail"), b"fixture").unwrap();
    assert!(disconnect_wifi(State(state.clone())).await.is_err());
    assert_eq!(read(dir.path(), WIFI_SSID_FILE), "old network");
    assert_eq!(read(dir.path(), WIFI_PASSWORD_FILE), "old fixture password");
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn missing_network_fixture_commands_never_fall_back_to_real_services() {
    let (dir, state) = fixture().await;
    for name in ["network-eth", "network-wifi"] {
        fs::remove_file(dir.path().join(name)).unwrap();
    }
    assert!(
        set_dns(State(state.clone()), Json(dns_request("dhcp")))
            .await
            .is_err()
    );
    assert!(
        set_ipv6(State(state.clone()), Json(ipv6_request("slaac")))
            .await
            .is_err()
    );
    assert!(
        connect_wifi(State(state.clone()), Json(wifi_request()))
            .await
            .is_err()
    );
    assert!(disconnect_wifi(State(state.clone())).await.is_err());
    assert_no_commands(dir.path());
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn ap_marker_failure_does_not_turn_partial_publication_into_success() {
    let (dir, state) = fixture().await;
    put(dir.path(), WIFI_AP_MODE_FILE, "fixture");
    put(dir.path(), WIFI_AP_PASS_FILE, "fixture-only-ap-key\n");
    fs::create_dir_all(path(dir.path(), WIFI_CONNECT_FILE)).unwrap();
    assert!(
        connect_wifi_no_auth(
            State(state.clone()),
            ap_client(),
            ap_headers(),
            Json(wifi_request())
        )
        .await
        .is_err()
    );
    assert_eq!(read(dir.path(), WIFI_SSID_FILE), "fixture network");
    assert_eq!(
        read(dir.path(), WIFI_PASSWORD_FILE),
        "fixture-only-password"
    );
    assert_no_commands(dir.path());
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[test]
fn a_secret_is_written_with_its_final_mode_over_a_readable_file() {
    let dir = tempfile::tempdir().unwrap();
    let target = path(dir.path(), WIFI_PASSWORD_FILE);
    put(dir.path(), WIFI_PASSWORD_FILE, "old");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    write_file(&target, b"new secret", 0o600).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"new secret");
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    let names: Vec<_> = fs::read_dir(target.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        [target.file_name().unwrap()],
        "a temporary file stayed"
    );
}

#[test]
fn the_setup_access_point_flag_is_only_where_root_writes() {
    assert!(WIFI_AP_MODE_FILE.starts_with("/run/"));
}
