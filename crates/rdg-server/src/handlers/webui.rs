//! Web UI handler: REST API for connections, .rdp file generation, WebSocket relay, and embedded SPA.

use crate::state::AppState;
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket},
        Path, State, WebSocketUpgrade,
    },
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use futures::{SinkExt, StreamExt};
use rdg_core::db::models::Connection;
use rust_embed::Embed;
use serde::Deserialize;
use std::sync::Arc;
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

// --- WebSocket relay (browser ↔ TCP to RDP target) ---

async fn ws_relay(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
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

    let tcp = match TcpStream::connect(&target).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::error!("WebSocket relay: failed to connect to {}: {}", target, e);
            let (mut sink, _) = ws.split();
            let _ = sink
                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: 1011,
                    reason: format!("Failed to connect to target: {}", e).into(),
                })))
                .await;
            return;
        }
    };

    tracing::info!("WebSocket relay: connected to {}", target);

    let (tcp_read, tcp_write) = tcp.into_split();
    let (ws_sink, ws_stream) = ws.split();

    let ws_sink = Arc::new(tokio::sync::Mutex::new(ws_sink));
    let tcp_write = Arc::new(tokio::sync::Mutex::new(tcp_write));

    // WS → TCP: forward binary messages from browser to RDP target
    let tcp_write_clone = tcp_write.clone();
    let ws_to_tcp = async {
        let mut stream = ws_stream;
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    use tokio::io::AsyncWriteExt;
                    let mut writer = tcp_write_clone.lock().await;
                    if writer.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {} // ignore text/ping/pong
            }
        }
    };

    // TCP → WS: forward RDP target responses to browser
    let ws_sink_clone = ws_sink.clone();
    let tcp_to_ws = async {
        use tokio::io::AsyncReadExt;
        let mut reader = tcp_read;
        let mut buf = vec![0u8; 16384];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let mut sink = ws_sink_clone.lock().await;
                    if sink.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    // Run both directions concurrently; stop when either ends
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
