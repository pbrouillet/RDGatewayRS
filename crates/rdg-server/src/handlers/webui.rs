//! Web UI handler: REST API for connections, .rdp file generation, WebSocket relay, and embedded SPA.

use crate::state::AppState;
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket},
        Path, Query, State, WebSocketUpgrade,
    },
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use futures::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use rdg_core::db::models::Connection;
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Embed)]
#[folder = "../../webui/dist"]
struct WebUiAssets;

/// API + static file routes for the web UI portal.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // REST API
        .route("/api/connections", get(list_connections))
        .route("/api/connections", post(create_connection))
        .route("/api/connections/{id}", get(get_connection))
        .route("/api/connections/{id}", put(update_connection))
        .route("/api/connections/{id}", delete(delete_connection))
        .route("/api/connections/{id}/rdp", get(download_rdp))
        .route("/api/connections/{id}/session", post(create_session_token))
        .route("/api/connections/{id}/ws", get(ws_relay))
        // Portal SPA (catch-all for client-side routing)
        .route("/portal/{*path}", get(serve_portal))
        .route("/portal", get(serve_portal_index))
        .route("/portal/", get(serve_portal_index))
}

// --- REST API handlers ---

async fn list_connections(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Connection>>, StatusCode> {
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
    Json(input): Json<ConnectionInput>,
) -> Result<(StatusCode, Json<Connection>), StatusCode> {
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
    Path(id): Path<i64>,
) -> Result<Json<Connection>, StatusCode> {
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
    Path(id): Path<i64>,
    Json(input): Json<ConnectionInput>,
) -> Result<StatusCode, StatusCode> {
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
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    state
        .db
        .delete_connection(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Session token + WebSocket relay ---

type HmacSha256 = Hmac<Sha256>;

/// Token payload: connection_id + issued_at (Unix seconds)
const TOKEN_TTL_SECS: u64 = 300; // 5 minutes

fn token_secret(state: &AppState) -> Vec<u8> {
    // Derive a signing key from the server name (stable per instance)
    format!("rdg-webui-session:{}", state.config.server_name)
        .into_bytes()
}

fn sign_token(connection_id: i64, issued_at: u64, secret: &[u8]) -> String {
    let payload = format!("{}:{}", connection_id, issued_at);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(payload.as_bytes());
    let sig = mac.finalize().into_bytes();
    use base64::Engine;
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
    format!("{}.{}", payload, sig_b64)
}

fn validate_token(token: &str, expected_connection_id: i64, secret: &[u8]) -> bool {
    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return false;
    }
    let (sig_b64, payload) = (parts[0], parts[1]);

    // Verify signature
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(payload.as_bytes());
    use base64::Engine;
    let sig = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig_b64) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if mac.verify_slice(&sig).is_err() {
        return false;
    }

    // Parse and validate payload
    let fields: Vec<&str> = payload.split(':').collect();
    if fields.len() != 2 {
        return false;
    }
    let conn_id: i64 = match fields[0].parse() {
        Ok(id) => id,
        Err(_) => return false,
    };
    let issued_at: u64 = match fields[1].parse() {
        Ok(t) => t,
        Err(_) => return false,
    };

    if conn_id != expected_connection_id {
        return false;
    }

    // Check TTL
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now.saturating_sub(issued_at) > TOKEN_TTL_SECS {
        return false;
    }

    true
}

#[derive(Serialize)]
struct SessionTokenResponse {
    token: String,
    expires_in: u64,
}

async fn create_session_token(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<SessionTokenResponse>, StatusCode> {
    // Verify the connection exists
    state
        .db
        .get_connection(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secret = token_secret(&state);
    let token = sign_token(id, now, &secret);

    Ok(Json(SessionTokenResponse {
        token,
        expires_in: TOKEN_TTL_SECS,
    }))
}

#[derive(Deserialize)]
struct WsQueryParams {
    token: Option<String>,
}

async fn ws_relay(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(params): Query<WsQueryParams>,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    // Validate session token
    let token = params.token.ok_or(StatusCode::UNAUTHORIZED)?;
    let secret = token_secret(&state);
    if !validate_token(&token, id, &secret) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let conn = state
        .db
        .get_connection(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(ws.on_upgrade(move |socket| handle_ws_relay(socket, conn)))
}

async fn handle_ws_relay(ws: WebSocket, conn: Connection) {
    let target = format!("{}:{}", conn.host, conn.port);
    tracing::info!("WebSocket relay: connecting to {}", target);

    // TCP connect with 5-second timeout
    let tcp = match tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(&target),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            tracing::error!("WebSocket relay: failed to connect to {}: {}", target, e);
            let (mut sink, _) = ws.split();
            let _ = sink
                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: 1011,
                    reason: format!("Failed to connect: {}", e).into(),
                })))
                .await;
            return;
        }
        Err(_) => {
            tracing::error!("WebSocket relay: timeout connecting to {}", target);
            let (mut sink, _) = ws.split();
            let _ = sink
                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: 1011,
                    reason: "Connection timed out".into(),
                })))
                .await;
            return;
        }
    };

    tracing::info!("WebSocket relay: connected to {}", target);

    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let (mut ws_sink, mut ws_stream) = ws.split();

    // WS → TCP: forward binary messages from browser to RDP target
    let ws_to_tcp = async {
        while let Some(msg) = ws_stream.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    if tcp_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {} // ignore text/ping/pong
            }
        }
        let _ = tcp_write.shutdown().await;
    };

    // TCP → WS: forward RDP target responses to browser
    let tcp_to_ws = async {
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if ws_sink
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = ws_sink.close().await;
    };

    // Run both directions; stop when either ends
    tokio::select! {
        _ = ws_to_tcp => {},
        _ = tcp_to_ws => {},
    }

    tracing::info!("WebSocket relay: session ended for {}", target);
}

// --- .rdp file generation ---

async fn download_rdp(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Response, StatusCode> {
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
