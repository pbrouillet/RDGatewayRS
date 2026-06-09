pub mod health;
pub mod rpch;
pub mod websocket;

use crate::metrics;
use crate::state::AppState;
use axum::{
    Router,
    middleware::{self, Next},
    extract::Request,
    response::Response,
};
use std::sync::Arc;
use tracing::info;

async fn log_requests(req: Request, next: Next) -> Response {
    metrics::get().requests_total.add(1, &[]);
    info!(
        "→ {} {} (from {:?})",
        req.method(),
        req.uri(),
        req.headers().get("host").map(|h| h.to_str().unwrap_or("?"))
    );
    next.run(req).await
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .merge(health::routes())
        .merge(websocket::routes())
        .merge(rpch::routes())
        .layer(middleware::from_fn(log_requests))
}
