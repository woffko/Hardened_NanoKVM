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
    system::media,
    update::{app_trial::Startup, keys::install_bundled_update_trust, state_writers::StateWriters},
};
use rand_core::{OsRng, RngCore};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process,
};
use tokio::{
    net::TcpListener,
    time::{self, Duration},
};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

const BOOT_INIT_SCRIPTS: &[&str] = &[
    "S00kmod",
    "S01fs",
    "S01syslogd",
    "S02apprecover",
    "S02klogd",
    "S03usbdev",
    "S15kvmhwd",
    "S30eth",
    "S30wifi",
    "S40firewall",
    "S49ntp",
    "S50avahi-daemon",
    "S50sshd",
    "S80dnsmasq",
    "S95nanokvm",
];
const KVM_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(4);
const BUNDLED_UPDATE_TRUST_DIR: &str = "/kvmapp/system/keys";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::hint::black_box(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/support-abi-nanokvm-rust-server.binding"
    )));
    // Retain complete framing, not only optimized references to the payload
    // suffixes. Future catalog inspection is read-only, not install authority.
    let _ = std::hint::black_box(nanokvm_rust_server::update::app_bootstrap::BOOT_SCRIPT_FRAMES);
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let startup = match args.as_slice() {
        [] => None,
        [mode] if mode == "--app-trial" => Some(Startup::adopt_stdin()?),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: NanoKVM-Server [--app-trial]",
            )
            .into());
        }
    };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(startup))
}

async fn run(startup: Option<Startup>) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    tls::install_crypto_provider();

    #[cfg(all(target_arch = "riscv64", feature = "linked-libkvm"))]
    {
        nanokvm_rust_server::update::restore_job::PinnedSshHelper::check_embedded()?;
        let _ = nanokvm_rust_server::update::app_bootstrap::embedded_recovery()?;
        nanokvm_rust_server::native_owner::embedded::check_embedded()?;
    }

    if let Some(startup) = startup {
        let config = startup.configuration()?;
        config.log_runtime_warnings();
        #[cfg(all(target_arch = "riscv64", feature = "linked-libkvm"))]
        nanokvm_rust_server::update::app_bootstrap::check_trial_support(&startup)?;
        return serve_config(config, Some(startup)).await;
    }

    nanokvm_rust_server::api::storage::secure_existing_storage()?;
    media::secure_device_mounts().await?;
    let config = Config::load()?;
    config.log_runtime_warnings();
    #[cfg(all(target_arch = "riscv64", feature = "linked-libkvm"))]
    let boot_support = match nanokvm_rust_server::update::native_bootstrap::prepare_boot_support() {
        Ok(support) => Some(support),
        Err(error) => {
            // Do not install new fail-closed gates before their static helper
            // exists. Preserve management for diagnosis; app install rechecks.
            warn!(%error, "independent update/native support unavailable; boot publication withheld");
            None
        }
    };
    #[cfg(not(all(target_arch = "riscv64", feature = "linked-libkvm")))]
    let boot_support: Option<nanokvm_rust_server::update::native_bootstrap::BootSupport> = None;
    install_runtime_boot_scripts(boot_support.is_some())?;
    drop(boot_support);
    let migration = media::prepare_and_migrate(Path::new("/data"), Path::new(media::MEDIA_ROOT))?;
    if migration.moved > 0 || migration.collisions > 0 {
        info!(
            moved = migration.moved,
            collisions = migration.collisions,
            "prepared isolated media storage; colliding legacy originals retained in /data"
        );
    }
    install_runtime_update_trust(&config);
    initialize_kvm();
    nanokvm_rust_server::ws::hid::start_persisted_mouse_jiggler();

    serve_config(config, None).await
}

async fn serve_config(
    config: Config,
    startup: Option<Startup>,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.proto == "https" {
        run_https(config, startup).await
    } else {
        run_http(config, startup).await
    }
}

struct TrialVideo;
impl Drop for TrialVideo {
    fn drop(&mut self) {
        let _ = kvm::shutdown();
    }
}

async fn authorize_trial(
    startup: Option<Startup>,
) -> Result<Option<TrialVideo>, Box<dyn std::error::Error>> {
    let Some(startup) = startup else {
        return Ok(None);
    };
    kvm::init()?;
    let video = TrialVideo;
    tokio::task::spawn_blocking(move || startup.ready_and_wait_commit()).await??;
    Ok(Some(video))
}

fn install_runtime_update_trust(config: &Config) {
    match install_bundled_update_trust(
        &StateWriters::default(),
        Path::new(BUNDLED_UPDATE_TRUST_DIR),
        &config.paths.system_update_public_key,
    ) {
        Ok(0) => {}
        Ok(changed) => info!(changed, "installed bundled system update trust"),
        Err(err) => warn!(error = %err, "failed to install bundled system update trust"),
    }
}

fn install_shutdown_signal_handler(state: AppState) {
    tokio::spawn(async move {
        shutdown_signal().await;
        warn!("shutdown signal received; stopping WebRTC owners");
        if let Err(err) = state.stop_webrtc().await {
            warn!(error = ?err, "WebRTC cleanup uncertain; skipping video deinit");
            process::exit(1);
        }
        // Other transports/native owners still have their separate shutdown
        // gates. WebRTC must never retain capture work across this deinit.

        match time::timeout(
            KVM_SHUTDOWN_TIMEOUT,
            tokio::task::spawn_blocking(kvm::shutdown),
        )
        .await
        {
            Ok(Ok(Ok(()))) => info!("deinitialized NanoKVM video backend"),
            Ok(Ok(Err(err))) => warn!(error = ?err, "NanoKVM video backend deinit failed"),
            Ok(Err(err)) => warn!(error = ?err, "NanoKVM video backend deinit task failed"),
            Err(_) => warn!("NanoKVM video backend deinit timed out"),
        }

        process::exit(0);
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            warn!(error = ?err, "failed to listen for Ctrl-C");
        }
    };

    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(err) => warn!(error = ?err, "failed to listen for SIGTERM"),
            }
        };

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

fn install_runtime_boot_scripts(independent_ready: bool) -> io::Result<()> {
    for script in BOOT_INIT_SCRIPTS {
        let src = Path::new("/kvmapp/system/init.d").join(script);
        let dst = Path::new("/etc/init.d").join(script);
        let result = match nanokvm_rust_server::update::app_bootstrap::BOOT_SCRIPTS
            .iter()
            .find(|(name, _)| name == script)
        {
            Some((_, bytes)) if independent_ready => install_runtime_boot_script_bytes(bytes, &dst),
            Some(_) => continue,
            None => install_runtime_boot_script(&src, &dst),
        };
        match result {
            Ok(true) => info!(
                source = %src.display(),
                target = %dst.display(),
                "installed runtime boot script"
            ),
            Ok(false) => {}
            Err(err) => {
                return Err(io::Error::other(format!(
                    "cannot install required boot script {script}: {err}"
                )));
            }
        }
    }
    Ok(())
}

fn install_runtime_boot_script(src: &Path, dst: &Path) -> io::Result<bool> {
    if !fs::symlink_metadata(src)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "required bundled boot script missing",
        ));
    }

    let bytes = fs::read(src)?;
    install_runtime_boot_script_bytes(&bytes, dst)
}

fn install_runtime_boot_script_bytes(bytes: &[u8], dst: &Path) -> io::Result<bool> {
    if let Ok(meta) = fs::symlink_metadata(dst) {
        if !meta.file_type().is_file() {
            return Err(io::Error::other("target exists but is not a regular file"));
        }
        if bytes == fs::read(dst)? {
            fs::set_permissions(dst, fs::Permissions::from_mode(0o755))?;
            return Ok(false);
        }
    }

    let temp = temp_boot_script_path(dst)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&temp)?;
    let result = (|| {
        file.write_all(bytes)?;
        // This FD is a fresh exclusive inode, never an existing script repair.
        file.set_permissions(fs::Permissions::from_mode(0o755))?;
        file.sync_all()?;
        fs::rename(&temp, dst)?;
        fs::File::open(
            dst.parent()
                .ok_or_else(|| io::Error::other("boot script has no parent"))?,
        )?
        .sync_all()?;
        Ok(true)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn temp_boot_script_path(dst: &Path) -> io::Result<PathBuf> {
    let file_name = dst
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("target has invalid file name"))?;
    let suffix = OsRng.next_u64();
    Ok(dst.with_file_name(format!(".{file_name}.{suffix:016x}.tmp")))
}

fn initialize_kvm() {
    match kvm::init() {
        Ok(()) => info!("initialized NanoKVM video backend"),
        Err(err) => warn!(error = ?err, "NanoKVM video backend initialization failed"),
    }
}

async fn run_http(
    config: Config,
    startup: Option<Startup>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = config.listen_addr()?;
    let state = match &startup {
        Some(startup) => AppState::new_trial(config, startup)?,
        None => AppState::new(config).await?,
    };

    let loopback = if state.config.needs_dedicated_loopback_listener() {
        Some((
            TcpListener::bind(state.config.loopback_listen_addr()).await?,
            routes::build(state.clone()),
        ))
    } else {
        None
    };

    let app = routes::build(state.clone()).into_make_service_with_connect_info::<ClientAddr>();
    let listener = TcpListener::bind(addr).await?;
    install_shutdown_signal_handler(state);
    let _trial_video = authorize_trial(startup).await?;
    if let Some((listener, app)) = loopback {
        spawn_bound_http(listener, app, "starting dedicated loopback HTTP listener");
    }
    info!(%addr, "starting NanoKVM Rust backend");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_https(
    config: Config,
    startup: Option<Startup>,
) -> Result<(), Box<dyn std::error::Error>> {
    let http_addr = config.listen_addr()?;
    let https_addr = config.https_listen_addr()?;
    let tls_config = match &startup {
        Some(startup) => startup.tls_configuration(&config)?,
        None => tls::load_server_config(&config.cert.crt, &config.cert.key)?,
    };
    let state = match &startup {
        Some(startup) => AppState::new_trial(config, startup)?,
        None => AppState::new(config).await?,
    };

    let loopback = if state.config.needs_dedicated_loopback_listener() {
        Some((
            TcpListener::bind(state.config.loopback_listen_addr()).await?,
            https_redirect_app(state.clone()),
        ))
    } else {
        None
    };

    let http_listener = TcpListener::bind(http_addr).await?;
    let redirect = https_redirect_app(state.clone());

    let app = routes::build(state.clone()).into_make_service_with_connect_info::<ClientAddr>();
    let listener = TcpListener::bind(https_addr).await?;
    let tls_listener = tls::TlsListener::new(listener, tls_config);
    install_shutdown_signal_handler(state);
    let _trial_video = authorize_trial(startup).await?;
    if let Some((listener, app)) = loopback {
        spawn_bound_http(
            listener,
            app,
            "starting dedicated loopback HTTP to HTTPS redirect listener",
        );
    }
    spawn_bound_http(
        http_listener,
        redirect,
        "starting HTTP to HTTPS redirect listener",
    );
    info!(addr = %https_addr, "starting NanoKVM Rust HTTPS backend");
    axum::serve(tls_listener, app).await?;
    Ok(())
}

fn spawn_bound_http(listener: TcpListener, app: axum::Router, message: &'static str) {
    tokio::spawn(async move {
        let service = app.into_make_service_with_connect_info::<ClientAddr>();
        info!("{message}");
        if let Err(err) = axum::serve(listener, service).await {
            warn!(error = ?err, "HTTP listener stopped");
        }
    });
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

#[cfg(all(test, feature = "sandbox-test-fixture", target_arch = "x86_64"))]
#[path = "app_trial_startup_tests.rs"]
mod app_trial_startup_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn compiled_boot_script_mode_child_fixture() {
        let Ok(root) = std::env::var("NANOKVM_BOOT_SCRIPT_MODE_FIXTURE") else {
            return;
        };
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o777));
        let path = Path::new(&root).join("S02apprecover");
        let bytes = nanokvm_rust_server::update::app_bootstrap::BOOT_SCRIPTS[0].1;
        assert!(install_runtime_boot_script_bytes(bytes, &path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        println!("compiled-boot-mode-fixture-ran");
    }

    #[test]
    fn compiled_boot_script_publication_ignores_parent_umask() {
        let root = tempfile::tempdir().unwrap();
        let output = process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::compiled_boot_script_mode_child_fixture",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_BOOT_SCRIPT_MODE_FIXTURE", root.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("running 1 test")
                && text.contains("1 passed; 0 failed")
                && text.contains("compiled-boot-mode-fixture-ran"),
            "{text}"
        );
    }

    #[test]
    fn boot_script_install_is_idempotent_and_preserves_old_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source");
        let dst = dir.path().join("S03usbdev");
        let old_temp = dir.path().join(".S03usbdev.tmp");
        fs::write(&src, b"new script\n").unwrap();
        fs::write(&dst, b"old script\n").unwrap();
        fs::write(&old_temp, b"unrelated\n").unwrap();
        assert!(install_runtime_boot_script(&src, &dst).unwrap());
        assert_eq!(fs::read(&dst).unwrap(), b"new script\n");
        assert!(!install_runtime_boot_script(&src, &dst).unwrap());
        assert_eq!(fs::read(&old_temp).unwrap(), b"unrelated\n");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[test]
    fn boot_script_install_rejects_missing_or_symlinked_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source");
        let dst = dir.path().join("target");
        assert!(install_runtime_boot_script(&src, &dst).is_err());
        fs::write(&src, b"script\n").unwrap();
        let alias = dir.path().join("alias");
        symlink(&src, &alias).unwrap();
        assert!(install_runtime_boot_script(&alias, &dst).is_err());
        symlink(&src, &dst).unwrap();
        assert!(install_runtime_boot_script(&src, &dst).is_err());
        assert_eq!(fs::read(&src).unwrap(), b"script\n");
    }

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
