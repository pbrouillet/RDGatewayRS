use crate::db::models::{AclRule, CertificateInfo, Group, Session, User};
use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("migration error: {0}")]
    Migration(String),
}

#[async_trait]
pub trait DbProvider: Send + Sync {
    /// Run database migrations
    async fn migrate(&self) -> Result<(), DbError>;

    // --- Users ---
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, DbError>;
    async fn create_user(&self, username: &str, nt_hash: &[u8]) -> Result<User, DbError>;
    async fn list_users(&self) -> Result<Vec<User>, DbError>;
    async fn set_user_enabled(&self, user_id: i64, enabled: bool) -> Result<(), DbError>;

    // --- Groups ---
    async fn get_user_groups(&self, user_id: i64) -> Result<Vec<Group>, DbError>;
    async fn create_group(&self, name: &str) -> Result<Group, DbError>;
    async fn list_groups(&self) -> Result<Vec<Group>, DbError>;
    async fn add_user_to_group(&self, user_id: i64, group_id: i64) -> Result<(), DbError>;

    // --- ACL ---
    async fn get_acl_rules(&self) -> Result<Vec<AclRule>, DbError>;
    async fn create_acl_rule(&self, rule: &AclRule) -> Result<AclRule, DbError>;
    async fn delete_acl_rule(&self, rule_id: i64) -> Result<(), DbError>;

    // --- Sessions ---
    async fn create_session(&self, session: &Session) -> Result<(), DbError>;
    async fn end_session(&self, session_id: &str) -> Result<(), DbError>;
    async fn get_active_sessions(&self) -> Result<Vec<Session>, DbError>;

    // --- Certificates ---
    async fn get_certificate(&self) -> Result<Option<CertificateInfo>, DbError>;
    async fn save_certificate(&self, cert: &CertificateInfo) -> Result<(), DbError>;
}

// Re-export for convenience
pub use async_trait::async_trait as provider_trait;
