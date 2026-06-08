use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub tls: TlsConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub server_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    /// If true and no cert/key paths given, generate self-signed
    pub auto_generate: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuthConfig {
    /// Kerberos SPN (e.g. "HTTP/gateway.domain.com"). Auto-derived from server_name if not set.
    pub spn: Option<String>,
    /// Path to keytab file (Linux/macOS). Not needed on domain-joined Windows.
    pub keytab_path: Option<PathBuf>,
    /// If true, accept any NTLM Type3 without validation (open mode for testing)
    #[serde(default)]
    pub open_mode: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 443,
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
                auto_generate: true,
            },
            database: DatabaseConfig {
                url: "sqlite://rdg-gateway.db?mode=rwc".to_string(),
            },
            auth: AuthConfig::default(),
            server_name: hostname(),
        }
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "RDG-GATEWAY".to_string())
}
