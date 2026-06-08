pub mod health;
pub mod rpch;
pub mod websocket;

use crate::state::AppState;
use axum::Router;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .merge(health::routes())
        .merge(websocket::routes())
        .merge(rpch::routes())
}
