mod handlers;
mod relay;
mod state;

use anyhow::Result;
use axum::Router;
use rdg_core::config::ServerConfig;
use rdg_core::db::{DbProvider, SqliteProvider};
use state::AppState;
use std::net::SocketAddr;
use std::sync::{Arc, Once};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    install_crypto_provider();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,rdg_server=debug,rdg_core=debug")),
        )
        .init();

    // Load config (from file or defaults)
    let config = load_config()?;
    tracing::info!(
        "Starting RDG Gateway on {}:{}",
        config.listen_addr,
        config.listen_port
    );

    // Initialize database
    let db = SqliteProvider::new(&config.database.url).await?;
    db.migrate().await?;
    tracing::info!("Database initialized");

    // Build app state
    let app_state = Arc::new(AppState::new(config.clone(), Arc::new(db)));

    // Build router
    let app = Router::new()
        .merge(handlers::routes())
        .with_state(app_state.clone());

    // TLS configuration
    let addr = SocketAddr::new(config.listen_addr.parse()?, config.listen_port);

    let tls_config = build_tls_config(&config).await?;

    tracing::info!("Listening on https://{}", addr);

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

fn install_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn load_config() -> Result<ServerConfig> {
    // Try loading from config file, fall back to defaults
    let config_path =
        std::env::var("RDG_CONFIG").unwrap_or_else(|_| "rdg-gateway.toml".to_string());
    if std::path::Path::new(&config_path).exists() {
        let content = std::fs::read_to_string(&config_path)?;
        let config: ServerConfig = toml::from_str(&content)?;
        Ok(config)
    } else {
        tracing::info!("No config file found, using defaults");
        Ok(ServerConfig::default())
    }
}

async fn build_tls_config(config: &ServerConfig) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use axum_server::tls_rustls::RustlsConfig;

    if let (Some(cert_path), Some(key_path)) = (&config.tls.cert_path, &config.tls.key_path) {
        let tls = RustlsConfig::from_pem_file(cert_path, key_path).await?;
        Ok(tls)
    } else if config.tls.auto_generate {
        tracing::info!(
            "Generating self-signed TLS certificate for {}",
            config.server_name
        );
        let cert = rcgen::generate_simple_self_signed(vec![
            config.server_name.clone(),
            config.listen_addr.clone(),
        ])?;

        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let tls = RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes()).await?;
        Ok(tls)
    } else {
        anyhow::bail!("TLS not configured: provide cert/key paths or enable auto_generate");
    }
}
