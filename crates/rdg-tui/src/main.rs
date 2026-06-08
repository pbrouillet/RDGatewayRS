mod app;
mod ui;

use anyhow::Result;
use app::App;
use rdg_core::config::ServerConfig;
use rdg_core::db::{DbProvider, SqliteProvider};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let config = load_config()?;
    let db = SqliteProvider::new(&config.database.url).await?;
    db.migrate().await?;

    let mut app = App::new(Arc::new(db));
    app.load_all().await?;
    app.run().await
}

fn load_config() -> Result<ServerConfig> {
    let config_path =
        std::env::var("RDG_CONFIG").unwrap_or_else(|_| "rdg-gateway.toml".to_string());
    if std::path::Path::new(&config_path).exists() {
        let content = std::fs::read_to_string(&config_path)?;
        let config: ServerConfig = toml::from_str(&content)?;
        Ok(config)
    } else {
        Ok(ServerConfig::default())
    }
}
