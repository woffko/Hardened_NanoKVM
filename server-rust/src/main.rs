use std::net::SocketAddr;

use nanokvm_rust_server::{config::Config, http::routes, state::AppState};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let config = Config::load()?;
    config.log_runtime_warnings();

    let addr = config.listen_addr()?;
    let state = AppState::new(config).await?;
    let app = routes::build(state).into_make_service_with_connect_info::<SocketAddr>();

    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "starting NanoKVM Rust backend");
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}
