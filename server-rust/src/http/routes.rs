use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{delete, get, post},
};
use tower_http::{services::ServeDir, trace::TraceLayer};

use crate::{
    api::{account, application, compatibility, storage, stream, vm},
    http::middleware::protected,
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
        .route("/api/vm/screen", post(vm::set_screen))
        .route(
            "/api/vm/web-title",
            get(vm::get_web_title).post(vm::set_web_title),
        )
        .route("/api/stream/mjpeg", get(stream::mjpeg_stream))
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
        .merge(compatibility_routes())
        .route_layer(from_fn_with_state(state.clone(), protected));

    Router::new()
        .route("/api/health", get(compatibility::health))
        .route("/api/auth/login", post(account::login))
        .route("/api/auth/setup", post(account::setup_first_account))
        .route("/api/network/wifi", post(compatibility::not_implemented))
        .route(
            "/api/network/wifi/verify",
            post(compatibility::not_implemented),
        )
        .merge(protected_routes)
        .fallback_service(ServeDir::new(state.config.paths.web_root.clone()))
        .with_state(state)
        .layer(from_fn_with_state((), security_headers))
        .layer(TraceLayer::new_for_http())
}

fn compatibility_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/application/update",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/application/update/offline",
            post(compatibility::not_implemented),
        )
        .route("/api/hid/paste", post(compatibility::not_implemented))
        .route("/api/hid/shortcuts", get(compatibility::not_implemented))
        .route(
            "/api/hid/shortcut",
            post(compatibility::not_implemented).delete(compatibility::not_implemented),
        )
        .route(
            "/api/hid/shortcut/leader-key",
            get(compatibility::not_implemented).post(compatibility::not_implemented),
        )
        .route(
            "/api/hid/mode",
            get(compatibility::not_implemented).post(compatibility::not_implemented),
        )
        .route("/api/hid/reset", post(compatibility::not_implemented))
        .route("/api/stream/h264", get(compatibility::not_implemented))
        .route(
            "/api/stream/h264/direct",
            get(compatibility::not_implemented),
        )
        .route("/api/download/image", post(compatibility::not_implemented))
        .route(
            "/api/download/image/status",
            get(compatibility::not_implemented),
        )
        .route(
            "/api/download/image/enabled",
            get(compatibility::not_implemented),
        )
        .route("/api/download/file", post(compatibility::not_implemented))
        .route("/api/network/wol", post(compatibility::not_implemented))
        .route(
            "/api/network/wol/mac",
            get(compatibility::not_implemented).delete(compatibility::not_implemented),
        )
        .route(
            "/api/network/wol/mac/name",
            post(compatibility::not_implemented),
        )
        .route("/api/network/wifi", get(compatibility::not_implemented))
        .route(
            "/api/network/wifi/connect",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/network/wifi/disconnect",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/network/dns",
            get(compatibility::not_implemented).post(compatibility::not_implemented),
        )
        .route(
            "/api/vm/gpio",
            get(compatibility::not_implemented).post(compatibility::not_implemented),
        )
        .route("/api/vm/terminal", get(compatibility::not_implemented))
        .route(
            "/api/vm/script",
            get(compatibility::not_implemented).delete(compatibility::not_implemented),
        )
        .route(
            "/api/vm/script/upload",
            post(compatibility::not_implemented),
        )
        .route("/api/vm/script/run", post(compatibility::not_implemented))
        .route(
            "/api/vm/device/virtual",
            get(compatibility::not_implemented).post(compatibility::not_implemented),
        )
        .route(
            "/api/vm/memory/limit",
            get(compatibility::not_implemented).post(compatibility::not_implemented),
        )
        .route(
            "/api/vm/oled",
            get(compatibility::not_implemented).post(compatibility::not_implemented),
        )
        .route("/api/vm/hdmi", get(compatibility::not_implemented))
        .route("/api/vm/hdmi/reset", post(compatibility::not_implemented))
        .route("/api/vm/hdmi/enable", post(compatibility::not_implemented))
        .route("/api/vm/hdmi/disable", post(compatibility::not_implemented))
        .route("/api/vm/ssh", get(compatibility::not_implemented))
        .route("/api/vm/ssh/enable", post(compatibility::not_implemented))
        .route("/api/vm/ssh/disable", post(compatibility::not_implemented))
        .route(
            "/api/vm/swap",
            get(compatibility::not_implemented).post(compatibility::not_implemented),
        )
        .route("/api/vm/mouse-jiggler", get(compatibility::not_implemented))
        .route(
            "/api/vm/mouse-jiggler/",
            post(compatibility::not_implemented),
        )
        .route("/api/vm/mdns", get(compatibility::not_implemented))
        .route("/api/vm/mdns/enable", post(compatibility::not_implemented))
        .route("/api/vm/mdns/disable", post(compatibility::not_implemented))
        .route("/api/vm/tls", post(compatibility::not_implemented))
        .route("/api/vm/autostart", get(compatibility::not_implemented))
        .route(
            "/api/vm/autostart/{name}",
            get(compatibility::not_implemented)
                .post(compatibility::not_implemented)
                .delete(compatibility::not_implemented),
        )
        .route(
            "/api/vm/system/reboot",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/extensions/tailscale/install",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/extensions/tailscale/uninstall",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/extensions/tailscale/status",
            get(compatibility::not_implemented),
        )
        .route(
            "/api/extensions/tailscale/up",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/extensions/tailscale/down",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/extensions/tailscale/login",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/extensions/tailscale/logout",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/extensions/tailscale/start",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/extensions/tailscale/stop",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/extensions/tailscale/restart",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/picoclaw/model/config",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/picoclaw/agent/profile",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/picoclaw/sessions",
            get(compatibility::not_implemented),
        )
        .route(
            "/api/picoclaw/sessions/{id}",
            get(compatibility::not_implemented).delete(compatibility::not_implemented),
        )
        .route(
            "/api/picoclaw/runtime/status",
            get(compatibility::not_implemented),
        )
        .route(
            "/api/picoclaw/runtime/session",
            delete(compatibility::not_implemented),
        )
        .route(
            "/api/picoclaw/runtime/install",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/picoclaw/runtime/uninstall",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/picoclaw/runtime/start",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/picoclaw/runtime/stop",
            post(compatibility::not_implemented),
        )
        .route(
            "/api/picoclaw/gateway/ws",
            get(compatibility::not_implemented),
        )
}
