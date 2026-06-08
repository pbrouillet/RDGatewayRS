use rdg_core::config::ServerConfig;
use rdg_core::db::DbProvider;
use std::sync::Arc;

pub struct AppState {
    pub config: ServerConfig,
    pub db: Arc<dyn DbProvider>,
}

impl AppState {
    pub fn new(config: ServerConfig, db: Arc<dyn DbProvider>) -> Self {
        Self { config, db }
    }
}
