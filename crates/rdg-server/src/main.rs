mod handlers;
mod relay;
mod state;
mod tui;

use anyhow::Result;
use axum::Router;
use clap::{Parser, Subcommand};
use rdg_core::config::ServerConfig;
use rdg_core::db::{DbProvider, SqliteProvider};
use state::AppState;
use std::net::SocketAddr;
use std::sync::{Arc, Once};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "rdg-server", about = "Lightweight RD Gateway server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the RD Gateway server (default)
    Serve {
        /// Path to configuration file
        #[arg(short, long, default_value = "rdg-gateway.toml")]
        config: String,
        /// Additional Subject Alternative Name for the self-signed certificate (repeatable)
        #[arg(long = "san", value_name = "NAME")]
        san_names: Vec<String>,
        /// Path to TLS certificate PEM file (overrides config)
        #[arg(long, value_name = "PATH")]
        tls_cert: Option<String>,
        /// Path to TLS private key PEM file (overrides config)
        #[arg(long, value_name = "PATH")]
        tls_key: Option<String>,
    },
    /// Launch the TUI for database management
    Manage {
        /// Path to configuration file
        #[arg(short, long, default_value = "rdg-gateway.toml")]
        config: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Serve {
        config: std::env::var("RDG_CONFIG").unwrap_or_else(|_| "rdg-gateway.toml".to_string()),
        san_names: Vec::new(),
        tls_cert: None,
        tls_key: None,
    }) {
        Command::Serve { config, san_names, tls_cert, tls_key } => {
            run_serve(&config, san_names, tls_cert, tls_key).await
        }
        Command::Manage { config } => {
            let cfg = load_config(&config)?;
            tui::run_manage(cfg, config).await
        }
    }
}

async fn run_serve(config_path: &str, cli_sans: Vec<String>, tls_cert: Option<String>, tls_key: Option<String>) -> Result<()> {
    install_crypto_provider();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,rdg_server=debug,rdg_core=debug")),
        )
        .init();

    let mut config = load_config(config_path)?;

    // Apply CLI overrides
    if let Some(cert) = tls_cert {
        config.tls.cert_path = Some(cert.into());
    }
    if let Some(key) = tls_key {
        config.tls.key_path = Some(key.into());
    }
    if !cli_sans.is_empty() {
        let existing = config.tls.san_names.get_or_insert_with(Vec::new);
        for san in cli_sans {
            if !existing.contains(&san) {
                existing.push(san);
            }
        }
    }

    tracing::info!(
        "Starting RDG Gateway on {}:{}",
        config.listen_addr,
        config.listen_port
    );

    let db = SqliteProvider::new(&config.database.url).await?;
    db.migrate().await?;
    tracing::info!("Database initialized");

    let app_state = Arc::new(AppState::new(config.clone(), Arc::new(db)));

    let app = Router::new()
        .merge(handlers::routes())
        .with_state(app_state.clone());

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

fn load_config(config_path: &str) -> Result<ServerConfig> {
    if std::path::Path::new(config_path).exists() {
        let content = std::fs::read_to_string(config_path)?;
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
        // Collect all useful SANs: server_name + all non-loopback local IPs
        let mut san_names = vec![config.server_name.clone()];
        if let Ok(hostname) = std::env::var("COMPUTERNAME") {
            if hostname != config.server_name && !san_names.contains(&hostname) {
                san_names.push(hostname);
            }
        }
        // Add all local IPv4 addresses
        if let Ok(addrs) = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| { s.connect("8.8.8.8:80")?; s.local_addr() })
        {
            san_names.push(addrs.ip().to_string());
        }
        // Also enumerate all interfaces
        for iface in netdev::get_interfaces() {
            for addr in &iface.ipv4 {
                let ip = addr.addr().to_string();
                if !ip.starts_with("127.") && !san_names.contains(&ip) {
                    san_names.push(ip);
                }
            }
        }
        san_names.push("localhost".to_string());

        // Merge custom SANs from config
        if let Some(custom_sans) = &config.tls.san_names {
            for san in custom_sans {
                if !san_names.contains(san) {
                    san_names.push(san.clone());
                }
            }
        }

        tracing::info!(
            "Generating self-signed TLS certificate for SANs: {:?}",
            san_names
        );
        let cert = rcgen::generate_simple_self_signed(san_names)?;

        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let tls = RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes()).await?;
        Ok(tls)
    } else {
        anyhow::bail!("TLS not configured: provide cert/key paths or enable auto_generate");
    }
}
