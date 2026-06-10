mod handlers;
mod metrics;
mod relay;
mod state;
mod telemetry;
mod tui;

use anyhow::Result;
use axum::Router;
use clap::{Parser, Subcommand};
use rdg_core::config::ServerConfig;
use rdg_core::db::{DbProvider, SqliteProvider};
use state::AppState;
use std::net::SocketAddr;
use std::sync::{Arc, Once};

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
        /// Also serve the web UI portal on the same port
        #[arg(long)]
        with_webui: bool,
    },
    /// Run the web UI portal standalone (HTTP, no TLS)
    #[command(name = "webui")]
    WebUi {
        /// Path to configuration file
        #[arg(short, long, default_value = "rdg-gateway.toml")]
        config: String,
        /// Port to serve the web UI on
        #[arg(long, default_value = "8080")]
        port: u16,
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
        with_webui: false,
    }) {
        Command::Serve { config, san_names, tls_cert, tls_key, with_webui } => {
            run_serve(&config, san_names, tls_cert, tls_key, with_webui).await
        }
        Command::WebUi { config, port } => {
            run_webui(&config, port).await
        }
        Command::Manage { config } => {
            let cfg = load_config(&config)?;
            tui::run_manage(cfg, config).await
        }
    }
}

async fn run_serve(config_path: &str, cli_sans: Vec<String>, tls_cert: Option<String>, tls_key: Option<String>, with_webui: bool) -> Result<()> {
    install_crypto_provider();

    let mut config = load_config(config_path)?;

    // Initialize telemetry (must come after config load so we know the endpoint)
    telemetry::init(&config.telemetry)?;

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

    let db_arc: Arc<dyn rdg_core::db::DbProvider> = Arc::new(db);
    let app_state = Arc::new(AppState::new(config.clone(), db_arc.clone()));

    let mut app = Router::new()
        .merge(handlers::routes())
        .with_state(app_state.clone());

    if with_webui {
        app = app.merge(handlers::webui::routes().with_state(app_state.clone()));
        tracing::info!("Web UI portal enabled at /portal/");
    }

    let addr = SocketAddr::new(config.listen_addr.parse()?, config.listen_port);
    let tls_config = build_tls_config(&config, &*db_arc).await?;

    tracing::info!("Listening on https://{}", addr);

    let server = axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>());

    // Run server with graceful shutdown on Ctrl+C
    tokio::select! {
        result = server => { result?; }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutting down...");
        }
    }

    telemetry::shutdown();
    Ok(())
}

async fn run_webui(config_path: &str, port: u16) -> Result<()> {
    let config = load_config(config_path)?;
    telemetry::init(&config.telemetry)?;

    tracing::info!("Starting Web UI portal on http://0.0.0.0:{}", port);

    let db = SqliteProvider::new(&config.database.url).await?;
    db.migrate().await?;
    tracing::info!("Database initialized");

    let db_arc: Arc<dyn rdg_core::db::DbProvider> = Arc::new(db);
    let app_state = Arc::new(AppState::new(config, db_arc));

    let app = handlers::webui::routes().with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!("Web UI listening on http://{}", addr);

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.ok(); })
        .await?;

    telemetry::shutdown();
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

async fn build_tls_config(config: &ServerConfig, db: &dyn rdg_core::db::DbProvider) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use axum_server::tls_rustls::RustlsConfig;
    use rdg_core::db::models::CertificateInfo;
    use sha2::{Sha256, Digest};

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

        // Check if we have a persisted certificate with matching SANs
        let cert_dir = std::path::Path::new("certs");
        let cert_file = cert_dir.join("gateway.crt");
        let key_file = cert_dir.join("gateway.key");

        if let Ok(Some(existing)) = db.get_certificate().await {
            let existing_sans: Vec<String> = serde_json::from_str(&existing.san_names)
                .unwrap_or_default();
            let mut sorted_existing = existing_sans.clone();
            sorted_existing.sort();
            let mut sorted_desired = san_names.clone();
            sorted_desired.sort();

            if sorted_existing == sorted_desired && cert_file.exists() && key_file.exists() {
                tracing::info!(
                    "Reusing persisted self-signed certificate (thumbprint: {})",
                    &existing.thumbprint[..16]
                );
                let tls = RustlsConfig::from_pem_file(&cert_file, &key_file).await?;
                return Ok(tls);
            }
        }

        // Generate new self-signed certificate
        tracing::info!(
            "Generating self-signed TLS certificate for SANs: {:?}",
            san_names
        );
        let cert = rcgen::generate_simple_self_signed(san_names.clone())?;

        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        // Persist to disk
        std::fs::create_dir_all(cert_dir)?;
        std::fs::write(&cert_file, &cert_pem)?;
        std::fs::write(&key_file, &key_pem)?;
        tracing::info!("Certificate persisted to {}", cert_dir.display());

        // Compute thumbprint (SHA-256 of DER)
        let cert_der = cert.cert.der();
        let thumbprint = {
            let mut hasher = Sha256::new();
            hasher.update(cert_der);
            let hash = hasher.finalize();
            hash.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
        };

        // Parse validity dates from the certificate
        let not_before = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let not_after = (chrono::Utc::now() + chrono::Duration::days(365))
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string();

        // Save to database
        let cert_info = CertificateInfo {
            id: 0,
            thumbprint: thumbprint.clone(),
            subject: format!("CN={}", config.server_name),
            san_names: serde_json::to_string(&san_names)?,
            not_before,
            not_after,
            cert_path: cert_file.display().to_string(),
            key_path: key_file.display().to_string(),
            auto_generated: true,
            created_at: String::new(),
        };
        if let Err(e) = db.save_certificate(&cert_info).await {
            tracing::warn!("Failed to save certificate to database: {}", e);
        }

        let tls = RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes()).await?;
        Ok(tls)
    } else {
        anyhow::bail!("TLS not configured: provide cert/key paths or enable auto_generate");
    }
}
