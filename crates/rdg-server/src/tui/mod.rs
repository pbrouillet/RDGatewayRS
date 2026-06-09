pub mod app;
mod ui;

use anyhow::Result;
use app::App;
use rdg_core::config::ServerConfig;
use rdg_core::db::{DbProvider, SqliteProvider};
use std::sync::Arc;

pub async fn run_manage(config: ServerConfig, config_path: String) -> Result<()> {
    let db = SqliteProvider::new(&config.database.url).await?;
    db.migrate().await?;

    let mut app = App::new(Arc::new(db), config, config_path);
    app.load_all().await?;
    app.run().await
}
