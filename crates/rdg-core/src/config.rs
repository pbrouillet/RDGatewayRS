use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub tls: TlsConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub server_name: String,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    /// If true and no cert/key paths given, generate self-signed
    pub auto_generate: bool,
    /// Additional Subject Alternative Names for the self-signed certificate
    #[serde(default)]
    pub san_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AuthConfig {
    /// Kerberos SPN (e.g. "HTTP/gateway.domain.com"). Auto-derived from server_name if not set.
    pub spn: Option<String>,
    /// Path to keytab file (Linux/macOS). Not needed on domain-joined Windows.
    pub keytab_path: Option<PathBuf>,
    /// If true, accept any NTLM Type3 without validation (open mode for testing)
    #[serde(default)]
    pub open_mode: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// OTLP gRPC endpoint (e.g. "http://localhost:4317")
    pub otlp_endpoint: Option<String>,
    /// Service name reported to OpenTelemetry
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// Whether telemetry export is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_service_name() -> String {
    "rdg-gateway".to_string()
}

fn default_enabled() -> bool {
    true
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            service_name: default_service_name(),
            enabled: true,
        }
    }
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
                san_names: None,
            },
            database: DatabaseConfig {
                url: "sqlite://rdg-gateway.db?mode=rwc".to_string(),
            },
            auth: AuthConfig::default(),
            server_name: hostname(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "RDG-GATEWAY".to_string())
}
