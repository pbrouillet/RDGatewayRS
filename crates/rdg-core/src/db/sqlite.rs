use super::models::{AclRule, Group, Session, User};
use super::provider::{DbError, DbProvider};
use async_trait::async_trait;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

pub struct SqliteProvider {
    pool: SqlitePool,
}

impl SqliteProvider {
    pub async fn new(database_url: &str) -> Result<Self, DbError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[async_trait]
impl DbProvider for SqliteProvider {
    async fn migrate(&self) -> Result<(), DbError> {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                nt_hash BLOB NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_groups (
                user_id INTEGER NOT NULL REFERENCES users(id),
                group_id INTEGER NOT NULL REFERENCES groups(id),
                PRIMARY KEY (user_id, group_id)
            );
            CREATE TABLE IF NOT EXISTS acl_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                priority INTEGER NOT NULL DEFAULT 0,
                user_id INTEGER REFERENCES users(id),
                group_id INTEGER REFERENCES groups(id),
                target_host TEXT,
                target_port INTEGER,
                action TEXT NOT NULL CHECK(action IN ('allow', 'deny')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                client_ip TEXT NOT NULL,
                target_host TEXT,
                target_port INTEGER,
                connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                disconnected_at TIMESTAMP
            );",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, DbError> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, username, nt_hash, enabled FROM users WHERE username = ? COLLATE NOCASE",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    async fn create_user(&self, username: &str, nt_hash: &[u8]) -> Result<User, DbError> {
        let result = sqlx::query("INSERT INTO users (username, nt_hash) VALUES (?, ?)")
            .bind(username)
            .bind(nt_hash)
            .execute(&self.pool)
            .await?;

        Ok(User {
            id: result.last_insert_rowid(),
            username: username.to_string(),
            nt_hash: nt_hash.to_vec(),
            enabled: true,
        })
    }

    async fn list_users(&self) -> Result<Vec<User>, DbError> {
        let users = sqlx::query_as::<_, User>("SELECT id, username, nt_hash, enabled FROM users")
            .fetch_all(&self.pool)
            .await?;
        Ok(users)
    }

    async fn set_user_enabled(&self, user_id: i64, enabled: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE users SET enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_user_groups(&self, user_id: i64) -> Result<Vec<Group>, DbError> {
        let groups = sqlx::query_as::<_, Group>(
            "SELECT g.id, g.name FROM groups g INNER JOIN user_groups ug ON g.id = ug.group_id WHERE ug.user_id = ?",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(groups)
    }

    async fn create_group(&self, name: &str) -> Result<Group, DbError> {
        let result = sqlx::query("INSERT INTO groups (name) VALUES (?)")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(Group {
            id: result.last_insert_rowid(),
            name: name.to_string(),
        })
    }

    async fn list_groups(&self) -> Result<Vec<Group>, DbError> {
        let groups = sqlx::query_as::<_, Group>("SELECT id, name FROM groups")
            .fetch_all(&self.pool)
            .await?;
        Ok(groups)
    }

    async fn add_user_to_group(&self, user_id: i64, group_id: i64) -> Result<(), DbError> {
        sqlx::query("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)")
            .bind(user_id)
            .bind(group_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_acl_rules(&self) -> Result<Vec<AclRule>, DbError> {
        let rules = sqlx::query_as::<_, AclRule>(
            "SELECT id, priority, user_id, group_id, target_host, target_port, action FROM acl_rules ORDER BY priority DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rules)
    }

    async fn create_acl_rule(&self, rule: &AclRule) -> Result<AclRule, DbError> {
        let result = sqlx::query(
            "INSERT INTO acl_rules (priority, user_id, group_id, target_host, target_port, action) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(rule.priority)
        .bind(rule.user_id)
        .bind(rule.group_id)
        .bind(&rule.target_host)
        .bind(rule.target_port)
        .bind(&rule.action)
        .execute(&self.pool)
        .await?;

        let mut new_rule = rule.clone();
        new_rule.id = result.last_insert_rowid();
        Ok(new_rule)
    }

    async fn delete_acl_rule(&self, rule_id: i64) -> Result<(), DbError> {
        sqlx::query("DELETE FROM acl_rules WHERE id = ?")
            .bind(rule_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_session(&self, session: &Session) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, client_ip, target_host, target_port) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&session.id)
        .bind(session.user_id)
        .bind(&session.client_ip)
        .bind(&session.target_host)
        .bind(session.target_port)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn end_session(&self, session_id: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE sessions SET disconnected_at = CURRENT_TIMESTAMP WHERE id = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_active_sessions(&self) -> Result<Vec<Session>, DbError> {
        let sessions = sqlx::query_as::<_, Session>(
            "SELECT id, user_id, client_ip, target_host, target_port, connected_at, disconnected_at FROM sessions WHERE disconnected_at IS NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(sessions)
    }
}
