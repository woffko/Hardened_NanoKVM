use axum::{
    extract::State,
    http::{HeaderMap, Uri, header},
    response::Redirect,
};
use nanokvm_rust_server::{
    config::Config,
    ffi::kvm,
    http::{
        routes,
        tls::{self, ClientAddr},
    },
    state::AppState,
};
use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    tls::install_crypto_provider();

    let config = Config::load()?;
    config.log_runtime_warnings();
    install_runtime_boot_scripts();
    initialize_kvm();

    if config.proto == "https" {
        run_https(config).await?;
    } else {
        run_http(config).await?;
    }

    Ok(())
}

fn install_runtime_boot_scripts() {
    for (src, dst) in [
        ("/kvmapp/system/init.d/S03usbdev", "/etc/init.d/S03usbdev"),
        ("/kvmapp/system/init.d/S30eth", "/etc/init.d/S30eth"),
        ("/kvmapp/system/init.d/S95nanokvm", "/etc/init.d/S95nanokvm"),
    ] {
        match install_runtime_boot_script(Path::new(src), Path::new(dst)) {
            Ok(true) => info!(source = src, target = dst, "installed runtime boot script"),
            Ok(false) => {}
            Err(err) => warn!(
                source = src,
                target = dst,
                error = %err,
                "failed to install runtime boot script"
            ),
        }
    }
}

fn install_runtime_boot_script(src: &Path, dst: &Path) -> io::Result<bool> {
    if !src.is_file() {
        return Ok(false);
    }

    if let Ok(meta) = fs::symlink_metadata(dst) {
        if !meta.file_type().is_file() {
            return Err(io::Error::other("target exists but is not a regular file"));
        }
        if fs::read(src)? == fs::read(dst)? {
            fs::set_permissions(dst, fs::Permissions::from_mode(0o755))?;
            return Ok(false);
        }
    }

    let temp = temp_boot_script_path(dst)?;
    fs::copy(src, &temp)?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o755))?;
    fs::rename(&temp, dst)?;
    Ok(true)
}

fn temp_boot_script_path(dst: &Path) -> io::Result<PathBuf> {
    let file_name = dst
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("target has invalid file name"))?;
    Ok(dst.with_file_name(format!(".{file_name}.tmp")))
}

fn initialize_kvm() {
    match kvm::init() {
        Ok(()) => info!("initialized NanoKVM video backend"),
        Err(err) => warn!(error = ?err, "NanoKVM video backend initialization failed"),
    }
}

async fn run_http(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let addr = config.listen_addr()?;
    let state = AppState::new(config).await?;

    if state.config.needs_dedicated_loopback_listener() {
        spawn_http_listener(
            state.config.loopback_listen_addr(),
            routes::build(state.clone()),
            "starting dedicated loopback HTTP listener",
        )
        .await?;
    }

    let app = routes::build(state).into_make_service_with_connect_info::<ClientAddr>();
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "starting NanoKVM Rust backend");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_https(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let http_addr = config.listen_addr()?;
    let https_addr = config.https_listen_addr()?;
    let tls_config = tls::load_server_config(&config.cert.crt, &config.cert.key)?;
    let state = AppState::new(config).await?;

    if state.config.needs_dedicated_loopback_listener() {
        spawn_http_listener(
            state.config.loopback_listen_addr(),
            https_redirect_app(state.clone()),
            "starting dedicated loopback HTTP to HTTPS redirect listener",
        )
        .await?;
    }

    spawn_http_listener(
        http_addr,
        https_redirect_app(state.clone()),
        "starting HTTP to HTTPS redirect listener",
    )
    .await?;

    let app = routes::build(state).into_make_service_with_connect_info::<ClientAddr>();
    let listener = TcpListener::bind(https_addr).await?;
    let tls_listener = tls::TlsListener::new(listener, tls_config);
    info!(addr = %https_addr, "starting NanoKVM Rust HTTPS backend");
    axum::serve(tls_listener, app).await?;
    Ok(())
}

async fn spawn_http_listener(
    addr: std::net::SocketAddr,
    app: axum::Router,
    message: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    tokio::spawn(async move {
        let service = app.into_make_service_with_connect_info::<ClientAddr>();
        info!(%addr, "{message}");
        if let Err(err) = axum::serve(listener, service).await {
            warn!(%addr, error = ?err, "HTTP listener stopped");
        }
    });
    Ok(())
}

fn https_redirect_app(state: AppState) -> axum::Router {
    routes::picoclaw_loopback_routes()
        .fallback(redirect_to_https)
        .with_state(state)
}

async fn redirect_to_https(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Redirect {
    let https_port = state.config.port.https;
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    let target = format!(
        "https://{}{}",
        redirect_host(host, https_port),
        uri.path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
    );
    Redirect::temporary(&target)
}

fn redirect_host(request_host: &str, https_port: u16) -> String {
    let host = host_without_port(request_host);

    if https_port == 443 {
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host
        }
    } else if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{https_port}")
    } else {
        format!("{host}:{https_port}")
    }
}

fn host_without_port(request_host: &str) -> String {
    if let Some(rest) = request_host.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host.to_string();
        }
    }

    if let Some((host, port)) = request_host.rsplit_once(':') {
        if !host.contains(':') && port.chars().all(|ch| ch.is_ascii_digit()) {
            return host.to_string();
        }
    }

    request_host.to_string()
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

#[cfg(test)]
mod tests {
    use super::redirect_host;

    #[test]
    fn redirect_host_replaces_http_port() {
        assert_eq!(redirect_host("10.0.87.133:80", 443), "10.0.87.133");
        assert_eq!(redirect_host("10.0.87.133:80", 8443), "10.0.87.133:8443");
    }

    #[test]
    fn redirect_host_handles_ipv6() {
        assert_eq!(redirect_host("[::1]:80", 443), "[::1]");
        assert_eq!(redirect_host("[::1]:80", 8443), "[::1]:8443");
    }
}
