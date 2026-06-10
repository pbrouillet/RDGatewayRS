use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub nt_hash: Vec<u8>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Group {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserGroup {
    pub user_id: i64,
    pub group_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AclRule {
    pub id: i64,
    pub priority: i32,
    pub user_id: Option<i64>,
    pub group_id: Option<i64>,
    pub target_host: Option<String>,
    pub target_port: Option<i32>,
    pub action: String, // "allow" or "deny"
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub client_ip: String,
    pub target_host: Option<String>,
    pub target_port: Option<i32>,
    pub connected_at: String,
    pub disconnected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CertificateInfo {
    pub id: i64,
    pub thumbprint: String,
    pub subject: String,
    pub san_names: String, // JSON array
    pub not_before: String,
    pub not_after: String,
    pub cert_path: String,
    pub key_path: String,
    pub auto_generated: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Connection {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub port: i32,
    pub description: Option<String>,
    pub icon: String,
    pub created_at: String,
    pub updated_at: String,
}
