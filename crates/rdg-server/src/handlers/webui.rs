//! Web UI handler: REST API for connections, .rdp file generation, and embedded SPA.

use crate::handlers::auth;
use crate::state::AppState;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use rdg_core::db::models::Connection;
use rust_embed::Embed;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Embed)]
#[folder = "../../webui/dist"]
struct WebUiAssets;

/// API + static file routes for the web UI portal.
pub fn routes() -> Router<Arc<AppState>> {
    // Protected API routes (require session cookie)
    let api_routes = Router::new()
        .route("/api/connections", get(list_connections))
        .route("/api/connections", post(create_connection))
        .route("/api/connections/{id}", get(get_connection))
        .route("/api/connections/{id}", put(update_connection))
        .route("/api/connections/{id}", delete(delete_connection))
        .route("/api/connections/{id}/rdp", get(download_rdp));

    // Portal SPA (public — needs to load login page)
    let portal_routes = Router::new()
        .route("/portal/{*path}", get(serve_portal))
        .route("/portal", get(serve_portal_index))
        .route("/portal/", get(serve_portal_index));

    api_routes.merge(portal_routes)
}

/// Validate session cookie from request headers. Returns 401 if invalid.
fn check_session(headers: &axum::http::HeaderMap, state: &AppState) -> Result<i64, StatusCode> {
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok());
    auth::validate_session_cookie(cookie_header, state).ok_or(StatusCode::UNAUTHORIZED)
}

// --- REST API handlers ---

async fn list_connections(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<Connection>>, StatusCode> {
    check_session(&headers, &state)?;
    state
        .db
        .list_connections()
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Deserialize)]
struct ConnectionInput {
    name: String,
    host: String,
    port: Option<i32>,
    description: Option<String>,
    icon: Option<String>,
}

async fn create_connection(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(input): Json<ConnectionInput>,
) -> Result<(StatusCode, Json<Connection>), StatusCode> {
    check_session(&headers, &state)?;
    let conn = state
        .db
        .create_connection(
            &input.name,
            &input.host,
            input.port.unwrap_or(3389),
            input.description.as_deref(),
            input.icon.as_deref().unwrap_or("Desktop"),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::CREATED, Json(conn)))
}

async fn get_connection(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Connection>, StatusCode> {
    check_session(&headers, &state)?;
    state
        .db
        .get_connection(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn update_connection(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<ConnectionInput>,
) -> Result<StatusCode, StatusCode> {
    check_session(&headers, &state)?;
    state
        .db
        .update_connection(
            id,
            &input.name,
            &input.host,
            input.port.unwrap_or(3389),
            input.description.as_deref(),
            input.icon.as_deref().unwrap_or("Desktop"),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_connection(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    check_session(&headers, &state)?;
    state
        .db
        .delete_connection(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

// --- .rdp file generation ---

async fn download_rdp(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<i64>,
) -> Result<Response, StatusCode> {
    check_session(&headers, &state)?;
    let conn = state
        .db
        .get_connection(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let gateway_host = state
        .config
        .webui
        .gateway_url
        .clone()
        .unwrap_or_else(|| {
            format!("{}:{}", state.config.server_name, state.config.listen_port)
        });

    let rdp_content = format!(
        "full address:s:{host}:{port}\r\n\
         server port:i:{port}\r\n\
         use redirection server name:i:1\r\n\
         alternate full address:s:{host}\r\n\
         gatewayhostname:s:{gateway}\r\n\
         gatewayusagemethod:i:1\r\n\
         gatewayprofileusagemethod:i:1\r\n\
         gatewayaccesstoken:s:\r\n\
         gatewaybrokeringtype:i:0\r\n\
         prompt for credentials:i:1\r\n\
         authentication level:i:2\r\n",
        host = conn.host,
        port = conn.port,
        gateway = gateway_host,
    );

    let filename = format!("{}.rdp", conn.name.replace(' ', "_"));

    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/x-rdp")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from(rdp_content))
        .unwrap())
}

// --- Static file serving (embedded SPA) ---

async fn serve_portal_index() -> Response {
    serve_embedded_file("index.html")
}

async fn serve_portal(Path(path): Path<String>) -> Response {
    // Try exact file first, then fall back to index.html for SPA routing
    let file_path = path.trim_start_matches('/');
    if let Some(_file) = WebUiAssets::get(file_path) {
        return serve_embedded_file(file_path);
    }
    // SPA fallback
    serve_embedded_file("index.html")
}

fn serve_embedded_file(path: &str) -> Response {
    match WebUiAssets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            Response::builder()
                .header(header::CONTENT_TYPE, mime)
                .header(header::CACHE_CONTROL, "public, max-age=3600")
                .body(Body::from(file.data.to_vec()))
                .unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not found"))
            .unwrap(),
    }
}
