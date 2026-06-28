use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware::{from_fn, from_fn_with_state},
    routing::{delete, get, post},
};
use tower_http::{services::ServeDir, trace::TraceLayer};

use crate::{
    api::{
        account, application, autostart, compatibility, download, hid, network, picoclaw, script,
        storage, stream, tailscale, vm, webrtc_stream,
    },
    http::middleware::{picoclaw_internal, protected},
    security::headers::security_headers,
    state::AppState,
    ws::hid as hid_ws,
};

pub fn build(state: AppState) -> Router {
    let protected_routes = Router::new()
        .route("/api/auth/logout", post(account::logout))
        .route("/api/auth/account", get(account::get_account))
        .route(
            "/api/auth/password",
            get(account::is_password_updated).post(account::change_password),
        )
        .route("/api/ws", get(hid_ws::connect))
        .route("/api/application/version", get(application::get_version))
        .route("/api/application/update", post(application::update))
        .route(
            "/api/application/update/offline",
            post(application::offline_update).layer(DefaultBodyLimit::max(128 * 1024 * 1024)),
        )
        .route(
            "/api/application/preview",
            get(application::get_preview).post(application::set_preview),
        )
        .route("/api/vm/info", get(vm::get_info))
        .route("/api/vm/hardware", get(vm::get_hardware))
        .route(
            "/api/vm/hostname",
            get(vm::get_hostname).post(vm::set_hostname),
        )
        .route("/api/vm/gpio", get(vm::get_gpio).post(vm::set_gpio))
        .route("/api/vm/screen", post(vm::set_screen))
        .route(
            "/api/vm/web-title",
            get(vm::get_web_title).post(vm::set_web_title),
        )
        .route(
            "/api/vm/device/virtual",
            get(vm::get_virtual_device).post(vm::update_virtual_device),
        )
        .route("/api/vm/oled", get(vm::get_oled).post(vm::set_oled))
        .route("/api/vm/hdmi", get(vm::get_hdmi_state))
        .route("/api/vm/hdmi/reset", post(vm::reset_hdmi))
        .route("/api/vm/hdmi/enable", post(vm::enable_hdmi))
        .route("/api/vm/hdmi/disable", post(vm::disable_hdmi))
        .route("/api/vm/ssh", get(vm::get_ssh_state))
        .route("/api/vm/ssh/enable", post(vm::enable_ssh))
        .route("/api/vm/ssh/disable", post(vm::disable_ssh))
        .route("/api/vm/mdns", get(vm::get_mdns_state))
        .route("/api/vm/mdns/enable", post(vm::enable_mdns))
        .route("/api/vm/mdns/disable", post(vm::disable_mdns))
        .route("/api/vm/system/reboot", post(vm::reboot))
        .route("/api/vm/terminal", get(vm::terminal))
        .route("/api/vm/terminal/unlock", post(vm::unlock_terminal))
        .route(
            "/api/vm/terminal/enabled",
            get(vm::get_terminal_enabled).post(vm::set_terminal_enabled),
        )
        .route(
            "/api/vm/session-lock",
            get(vm::get_session_lock).post(vm::set_session_lock),
        )
        .route(
            "/api/vm/memory/limit",
            get(vm::get_memory_limit).post(vm::set_memory_limit),
        )
        .route("/api/vm/swap", get(vm::get_swap).post(vm::set_swap))
        .route(
            "/api/vm/mouse-jiggler",
            get(vm::get_mouse_jiggler).post(vm::set_mouse_jiggler),
        )
        .route("/api/vm/mouse-jiggler/", post(vm::set_mouse_jiggler))
        .route("/api/vm/tls", post(vm::set_tls))
        .route("/api/vm/autostart", get(autostart::get_autostart))
        .route(
            "/api/vm/autostart/{name}",
            get(autostart::get_autostart_content)
                .post(autostart::upload_autostart)
                .delete(autostart::delete_autostart)
                .layer(DefaultBodyLimit::max(autostart::MAX_AUTOSTART_BYTES + 1024)),
        )
        .route(
            "/api/vm/script",
            get(script::get_scripts).delete(script::delete_script),
        )
        .route(
            "/api/vm/script/upload",
            post(script::upload_script)
                .layer(DefaultBodyLimit::max(script::MAX_SCRIPT_BYTES + 1024)),
        )
        .route("/api/vm/script/run", post(script::run_script))
        .route("/api/stream/mjpeg", get(stream::mjpeg_stream))
        .route("/api/stream/h264", get(webrtc_stream::h264_webrtc_stream))
        .route("/api/stream/h264/direct", get(stream::h264_direct_stream))
        .route(
            "/api/stream/mjpeg/detect",
            post(stream::update_frame_detect),
        )
        .route(
            "/api/stream/mjpeg/detect/stop",
            post(stream::stop_frame_detect),
        )
        .route("/api/storage/image", get(storage::get_images))
        .route(
            "/api/storage/image/mounted",
            get(storage::get_mounted_image),
        )
        .route("/api/storage/image/mount", post(storage::mount_image))
        .route("/api/storage/cdrom", get(storage::get_cdrom))
        .route("/api/storage/image/delete", post(storage::delete_image))
        .route("/api/network/wol", post(network::wake_on_lan))
        .route(
            "/api/network/wol/mac",
            get(network::get_wol_macs).delete(network::delete_wol_mac),
        )
        .route("/api/network/wol/mac/name", post(network::set_wol_mac_name))
        .route(
            "/api/network/dns",
            get(network::get_dns).post(network::set_dns),
        )
        .route("/api/network/wifi", get(network::get_wifi))
        .route("/api/network/wifi/connect", post(network::connect_wifi))
        .route(
            "/api/network/wifi/disconnect",
            post(network::disconnect_wifi),
        )
        .route("/api/download/image", post(download::download_image))
        .route("/api/download/image/status", get(download::status_image))
        .route("/api/download/image/enabled", get(download::image_enabled))
        .route(
            "/api/download/image/remote/enabled",
            get(download::get_remote_image_download_enabled)
                .post(download::set_remote_image_download_enabled),
        )
        .route(
            "/api/extensions/tailscale/status",
            get(tailscale::get_status),
        )
        .route("/api/hid/shortcuts", get(hid::get_shortcuts))
        .route("/api/hid/reset", post(hid::reset_hid))
        .route(
            "/api/hid/shortcut",
            post(hid::add_shortcut).delete(hid::delete_shortcut),
        )
        .route(
            "/api/hid/shortcut/leader-key",
            get(hid::get_leader_key).post(hid::set_leader_key),
        )
        .route("/api/hid/mode", get(hid::get_mode).post(hid::set_mode))
        .route("/api/hid/paste", post(hid::paste))
        .route(
            "/api/download/file",
            post(download::upload_image_file).layer(DefaultBodyLimit::max(
                download::MAX_UPLOAD_BYTES + 1024 * 1024,
            )),
        )
        .merge(compatibility_routes())
        .route_layer(from_fn_with_state(state.clone(), protected));

    Router::new()
        .route("/api/health", get(compatibility::health))
        .route("/api/auth/login", post(account::login))
        .route(
            "/api/auth/setup",
            get(account::get_setup_state).post(account::setup_first_account),
        )
        .route("/api/network/wifi", post(network::connect_wifi_no_auth))
        .route("/api/network/wifi/verify", post(network::verify_ap_login))
        .merge(picoclaw_loopback_routes())
        .merge(protected_routes)
        .fallback_service(ServeDir::new(state.config.paths.web_root.clone()))
        .with_state(state)
        .layer(from_fn_with_state((), security_headers))
        .layer(TraceLayer::new_for_http())
}

fn compatibility_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/extensions/tailscale/install",
            post(tailscale::install),
        )
        .route(
            "/api/extensions/tailscale/uninstall",
            post(tailscale::uninstall),
        )
        .route("/api/extensions/tailscale/up", post(tailscale::up))
        .route("/api/extensions/tailscale/down", post(tailscale::down))
        .route("/api/extensions/tailscale/login", post(tailscale::login))
        .route("/api/extensions/tailscale/logout", post(tailscale::logout))
        .route("/api/extensions/tailscale/start", post(tailscale::start))
        .route("/api/extensions/tailscale/stop", post(tailscale::stop))
        .route(
            "/api/extensions/tailscale/restart",
            post(tailscale::restart),
        )
        .route(
            "/api/picoclaw/model/config",
            post(picoclaw::update_model_config),
        )
        .route(
            "/api/picoclaw/agent/profile",
            post(picoclaw::update_agent_profile),
        )
        .route("/api/picoclaw/sessions", get(picoclaw::list_sessions))
        .route(
            "/api/picoclaw/sessions/{id}",
            get(picoclaw::get_session).delete(picoclaw::delete_session),
        )
        .route(
            "/api/picoclaw/runtime/status",
            get(picoclaw::get_runtime_status),
        )
        .route(
            "/api/picoclaw/runtime/session",
            delete(picoclaw::release_runtime_session),
        )
        .route(
            "/api/picoclaw/runtime/install",
            post(picoclaw::install_runtime),
        )
        .route(
            "/api/picoclaw/runtime/uninstall",
            post(picoclaw::uninstall_runtime),
        )
        .route("/api/picoclaw/runtime/start", post(picoclaw::start_runtime))
        .route("/api/picoclaw/runtime/stop", post(picoclaw::stop_runtime))
        .route("/api/picoclaw/gateway/ws", get(picoclaw::gateway_ws))
}

pub fn picoclaw_loopback_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/picoclaw/runtime/session",
            get(picoclaw::get_runtime_session),
        )
        .route("/api/picoclaw/screenshot", get(picoclaw::screenshot))
        .route("/api/picoclaw/actions", post(picoclaw::actions))
        .route("/api/picoclaw/mcp", post(picoclaw::mcp))
        .route("/api/picoclaw/load-image", post(picoclaw::load_image))
        .route_layer(from_fn(picoclaw_internal))
}
