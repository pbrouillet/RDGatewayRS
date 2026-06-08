//! WebSocket transport handler for FreeRDP clients.
//!
//! FreeRDP uses the custom HTTP method `RDG_OUT_DATA` (not GET) to
//! `/remoteDesktopGateway/`. The NTLM auth exchange happens first,
//! then the connection upgrades to WebSocket.
//!
//! Flow:
//! 1. Client sends RDG_OUT_DATA with no auth → 401 (bare Negotiate)
//! 2. Client sends RDG_OUT_DATA with Type1 → 401 + Negotiate <Type2>
//! 3. Client sends RDG_OUT_DATA with Type3 + WS upgrade headers → 101
//! 4. Binary WebSocket frames carry TSG messages

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use base64::Engine;
use futures::stream::StreamExt;
use futures::SinkExt;
use rdg_core::auth::NtlmAuthContext;
use rdg_core::session::GatewaySession;
use rdg_proto::messages::{self, TsgMessage};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, warn};

use crate::state::AppState;

/// Per-connection NTLM challenge state, keyed by client address.
/// In production, this should be keyed by TCP connection ID.
type ChallengeStore = Arc<Mutex<HashMap<SocketAddr, NtlmAuthContext>>>;

pub fn routes() -> Router<Arc<AppState>> {
    let challenges: ChallengeStore = Arc::new(Mutex::new(HashMap::new()));
    Router::new()
        .route("/remoteDesktopGateway/", any(rdg_handler))
        .layer(axum::Extension(challenges))
}

/// Main handler that processes the NTLM auth flow and WebSocket upgrade.
/// Accepts any HTTP method (GET, RDG_OUT_DATA, etc.)
async fn rdg_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::Extension(challenges): axum::Extension<ChallengeStore>,
    req: Request<Body>,
) -> Response {
    let headers = req.headers().clone();
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    debug!("RDG request from {} method={} auth={}", addr, req.method(), !auth_header.is_empty());

    // Step 1: No auth header → return bare "Negotiate" challenge
    if auth_header.is_empty() {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Negotiate")
            .header("Server", "Microsoft-HTTPAPI/2.0")
            .body(Body::empty())
            .unwrap();
    }

    // Step 2: NTLM Type1 → generate and store challenge, return Type2
    if is_ntlm_type1(&auth_header) {
        let auth_ctx = NtlmAuthContext::new(&state.config.server_name);
        let challenge_b64 = auth_ctx.challenge_base64();

        // Store the challenge for this client's Type3 validation
        {
            let mut store = challenges.lock().await;
            store.insert(addr, auth_ctx);
        }

        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                header::WWW_AUTHENTICATE,
                format!("Negotiate {}", challenge_b64),
            )
            .header("Server", "Microsoft-HTTPAPI/2.0")
            .body(Body::empty())
            .unwrap();
    }

    // Step 3: NTLM Type3 → validate and upgrade to WebSocket
    if is_ntlm_type3(&auth_header) {
        let type3_data = extract_ntlm_token(&auth_header);
        let username =
            extract_username_from_type3(&type3_data).unwrap_or_else(|| "unknown".to_string());

        // Retrieve stored challenge (for future real validation)
        {
            let mut store = challenges.lock().await;
            let _auth_ctx = store.remove(&addr);
            // TODO: use auth_ctx.server_challenge to validate Type3 against DB
        }

        info!("Authenticated user: {} from {}", username, addr);

        // Perform manual WebSocket upgrade (works with any HTTP method)
        return do_websocket_upgrade(req, state, addr, username);
    }

    (StatusCode::BAD_REQUEST, "Invalid authorization").into_response()
}

/// Manually perform WebSocket upgrade without relying on Axum's WebSocketUpgrade extractor.
/// This allows non-GET methods like RDG_OUT_DATA to upgrade.
fn do_websocket_upgrade(
    req: Request<Body>,
    state: Arc<AppState>,
    addr: SocketAddr,
    username: String,
) -> Response {
    let headers = req.headers();

    // Verify WebSocket upgrade headers are present
    let has_upgrade = headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    let has_connection = headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false);

    let ws_key = headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    if !has_upgrade || !has_connection || ws_key.is_none() {
        warn!("Missing WebSocket upgrade headers from {}", addr);
        return (StatusCode::BAD_REQUEST, "Missing WebSocket headers").into_response();
    }

    let ws_key = ws_key.unwrap();
    let ws_accept = compute_ws_accept(&ws_key);

    // Use hyper's on_upgrade to get the raw upgraded IO
    let on_upgrade = hyper::upgrade::on(req);

    // Spawn task to handle the upgraded connection
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                // Wrap hyper's Upgraded in TokioIo for tokio AsyncRead/AsyncWrite
                let io = hyper_util::rt::TokioIo::new(upgraded);

                // Wrap in tokio-tungstenite WebSocket
                let ws_stream = WebSocketStream::from_raw_socket(
                    io,
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    None,
                )
                .await;

                handle_ws_session_tungstenite(ws_stream, state, addr, username).await;
            }
            Err(e) => {
                error!("WebSocket upgrade failed for {}: {}", addr, e);
            }
        }
    });

    // Return 101 Switching Protocols
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header("Sec-WebSocket-Accept", ws_accept)
        .body(Body::empty())
        .unwrap()
}

/// Compute Sec-WebSocket-Accept from the client key (RFC 6455)
fn compute_ws_accept(key: &str) -> String {
    // Use tungstenite's own derivation to ensure we match what the client expects
    tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes())
}

/// Handle WebSocket session using tokio-tungstenite (for RDG_OUT_DATA upgrade)
async fn handle_ws_session_tungstenite<S>(
    ws_stream: WebSocketStream<S>,
    state: Arc<AppState>,
    client_addr: SocketAddr,
    username: String,
)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio_tungstenite::tungstenite::Message as TMessage;

    info!(
        "WebSocket session started for {} from {}",
        username, client_addr
    );

    let mut session = GatewaySession::new();
    let (mut ws_sink, mut ws_stream) = ws_stream.split();

    loop {
        let msg = match ws_stream.next().await {
            Some(Ok(TMessage::Binary(data))) => data,
            Some(Ok(TMessage::Close(_))) | None => {
                info!("Client disconnected during handshake");
                return;
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => {
                error!("WebSocket error: {}", e);
                return;
            }
        };

        let tsg_msg = match messages::parse_message(&msg) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to parse TSG message: {}", e);
                return;
            }
        };

        debug!(
            "Received TSG message: {:?}",
            std::mem::discriminant(&tsg_msg)
        );

        if session.is_data_transfer() {
            if let TsgMessage::Data(data_msg) = tsg_msg {
                let target_host = session.target_host.clone().unwrap_or_default();
                let target_port = session.target_port.unwrap_or(3389);
                info!("Starting relay to {}:{}", target_host, target_port);

                // Reunite and start relay using tungstenite streams
                // For now, just connect TCP and relay manually
                let target_addr = format!("{}:{}", target_host, target_port);
                let tcp_stream = match tokio::net::TcpStream::connect(&target_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to connect to backend {}: {}", target_addr, e);
                        return;
                    }
                };

                let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

                // Send initial data
                use tokio::io::AsyncWriteExt;
                if let Err(e) = tcp_write.write_all(&data_msg.data).await {
                    error!("Failed to send initial data: {}", e);
                    return;
                }

                // WS → TCP task
                let ws_to_tcp = tokio::spawn(async move {
                    while let Some(Ok(msg)) = ws_stream.next().await {
                        if let TMessage::Binary(data) = msg {
                            match messages::parse_message(&data) {
                                Ok(TsgMessage::Data(d)) => {
                                    if tcp_write.write_all(&d.data).await.is_err() {
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    let _ = tcp_write.shutdown().await;
                });

                // TCP → WS task
                let tcp_to_ws = tokio::spawn(async move {
                    use rdg_proto::websocket::encode_data_message;
                    use tokio::io::AsyncReadExt;
                    let mut buf = vec![0u8; 8192];
                    loop {
                        let n = match tcp_read.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => n,
                            Err(_) => break,
                        };
                        let ws_msg = encode_data_message(&buf[..n]);
                        if ws_sink.send(TMessage::Binary(ws_msg)).await.is_err() {
                            break;
                        }
                    }
                    let _ = ws_sink.close().await;
                });

                let _ = tokio::join!(ws_to_tcp, tcp_to_ws);
                info!("Relay session ended for {}", username);
                return;
            }
        }

        match session.process_message(&tsg_msg) {
            Ok(Some(response)) => {
                use tokio_tungstenite::tungstenite::Message as TMessage;
                if ws_sink
                    .send(TMessage::Binary(response))
                    .await
                    .is_err()
                {
                    error!("Failed to send response");
                    return;
                }

                if session.is_data_transfer() {
                    info!(
                        "TSG handshake complete, awaiting data for relay to {}:{}",
                        session.target_host.as_deref().unwrap_or("?"),
                        session.target_port.unwrap_or(0)
                    );
                }
            }
            Ok(None) => {}
            Err(e) => {
                error!("Session error: {}", e);
                return;
            }
        }
    }
}

/// Handle WebSocket session using Axum's WebSocket type (for GET-based testing)
#[allow(dead_code)]
async fn handle_ws_session_axum(
    socket: axum::extract::ws::WebSocket,
    state: Arc<AppState>,
    client_addr: SocketAddr,
    username: String,
) {
    use axum::extract::ws::Message;

    info!(
        "WebSocket session started (axum) for {} from {}",
        username, client_addr
    );

    let mut session = GatewaySession::new();
    let (mut ws_sink, mut ws_stream) = socket.split();

    loop {
        let msg = match ws_stream.next().await {
            Some(Ok(Message::Binary(data))) => data,
            Some(Ok(Message::Close(_))) | None => {
                info!("Client disconnected during handshake");
                return;
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => {
                error!("WebSocket error: {}", e);
                return;
            }
        };

        let tsg_msg = match messages::parse_message(&msg) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to parse TSG message: {}", e);
                return;
            }
        };

        match session.process_message(&tsg_msg) {
            Ok(Some(response)) => {
                if ws_sink
                    .send(Message::Binary(response.to_vec().into()))
                    .await
                    .is_err()
                {
                    error!("Failed to send response");
                    return;
                }
            }
            Ok(None) => {}
            Err(e) => {
                error!("Session error: {}", e);
                return;
            }
        }
    }
}

fn is_ntlm_type1(auth: &str) -> bool {
    auth.strip_prefix("Negotiate ")
        .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
        .filter(|d| d.len() >= 12 && &d[0..8] == b"NTLMSSP\0" && d[8] == 1)
        .is_some()
}

fn is_ntlm_type3(auth: &str) -> bool {
    auth.strip_prefix("Negotiate ")
        .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
        .filter(|d| d.len() >= 12 && &d[0..8] == b"NTLMSSP\0" && d[8] == 3)
        .is_some()
}

fn extract_ntlm_token(auth: &str) -> Vec<u8> {
    auth.strip_prefix("Negotiate ")
        .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
        .unwrap_or_default()
}

fn extract_username_from_type3(data: &[u8]) -> Option<String> {
    rdg_proto::ntlm::parse_authenticate(data)
        .ok()
        .map(|a| a.username)
}
