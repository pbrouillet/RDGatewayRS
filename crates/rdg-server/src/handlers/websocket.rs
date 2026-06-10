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
        .route("/KdcProxy", any(kdcproxy_handler))
        .route("/remoteDesktopGateway", any(rdg_handler))
        .layer(axum::Extension(challenges))
}

/// KdcProxy handler - mstsc POSTs here for Kerberos. Return 503 to force NTLM fallback.
async fn kdcproxy_handler(req: Request<Body>) -> Response {
    warn!(
        "KdcProxy request: {} {} (ignoring - not in domain)",
        req.method(),
        req.uri()
    );
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(Body::empty())
        .unwrap()
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

    debug!(
        "RDG request from {} method={} auth={} headers: {:?}",
        addr, req.method(), !auth_header.is_empty(),
        req.headers().iter().map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("?"))).collect::<Vec<_>>()
    );

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

    let ws_protocol = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    if !has_upgrade || !has_connection || ws_key.is_none() {
        warn!("Missing WebSocket upgrade headers from {}", addr);
        return (StatusCode::BAD_REQUEST, "Missing WebSocket headers").into_response();
    }

    let ws_key = ws_key.unwrap();
    let ws_accept = compute_ws_accept(&ws_key);

    debug!("WebSocket upgrade: protocol={:?}", ws_protocol);

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

    // Return 101 Switching Protocols — must echo Sec-WebSocket-Protocol if client sent it
    let mut resp = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header("Sec-WebSocket-Accept", ws_accept);

    if let Some(proto) = ws_protocol {
        resp = resp.header("Sec-WebSocket-Protocol", proto);
    }

    resp.body(Body::empty()).unwrap()
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
            "Received TSG message: {:?} (raw {} bytes: {:02x?})",
            std::mem::discriminant(&tsg_msg),
            msg.len(),
            &msg[..msg.len().min(64)]
        );

        if session.is_data_transfer() {
            if let TsgMessage::Data(data_msg) = tsg_msg {
                let target_host = session.target_host.clone().unwrap_or_default();
                let target_port = session.target_port.unwrap_or(3389);
                info!("Starting relay to {}:{}", target_host, target_port);

                // Reunite and start relay using tungstenite streams
                let target_addr = format!("{}:{}", target_host, target_port);
                let tcp_stream = match tokio::net::TcpStream::connect(&target_addr).await {
                    Ok(s) => {
                        // Disable Nagle for low-latency relay (critical for TLS handshakes)
                        let _ = s.set_nodelay(true);
                        s
                    }
                    Err(e) => {
                        error!("Failed to connect to backend {}: {}", target_addr, e);
                        return;
                    }
                };

                let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

                // Send initial data — strip 2-byte cbDataLength prefix
                use tokio::io::AsyncWriteExt;
                let rdp_data = if data_msg.data.len() >= 2 {
                    &data_msg.data[2..]
                } else {
                    &data_msg.data[..]
                };
                if let Err(e) = tcp_write.write_all(rdp_data).await {
                    error!("Failed to send initial data: {}", e);
                    return;
                }
                let _ = tcp_write.flush().await;
                debug!("Relay: sent {} bytes initial RDP data to backend (hex: {:02x?})", rdp_data.len(), &rdp_data[..rdp_data.len().min(32)]);

                // Channel for the WS→TCP task to send control responses back to the client
                let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(8);

                // WS → TCP task: strip 2-byte cbDataLength from each data message
                let client_addr_log = client_addr;
                let ws_to_tcp = tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let mut total_bytes: u64 = 0;
                    let mut msg_count: u64 = 0;
                    // After IN-channel ChannelCreate, skip the next Data msg (duplicate X.224)
                    let mut skip_next_data = false;
                    while let Some(Ok(msg)) = ws_stream.next().await {
                        match msg {
                            TMessage::Binary(data) => {
                                match messages::parse_message(&data) {
                                    Ok(TsgMessage::Data(d)) => {
                                        if skip_next_data {
                                            debug!("Relay WS→TCP: skipping IN-channel initial Data ({} bytes)", d.data.len());
                                            skip_next_data = false;
                                            continue;
                                        }
                                        let payload = if d.data.len() >= 2 {
                                            &d.data[2..]
                                        } else {
                                            &d.data[..]
                                        };
                                        total_bytes += payload.len() as u64;
                                        msg_count += 1;
                                        if msg_count <= 10 || msg_count % 50 == 0 {
                                            debug!("Relay WS→TCP #{}: {} bytes (total: {}) first_bytes={:02x?}", msg_count, payload.len(), total_bytes, &payload[..payload.len().min(16)]);
                                        }
                                        if tcp_write.write_all(payload).await.is_err() {
                                            error!("Relay WS→TCP: write to backend failed");
                                            break;
                                        }
                                        let _ = tcp_write.flush().await;
                                    }
                                    Ok(TsgMessage::Keepalive) => {
                                        debug!("Relay WS→TCP: received Keepalive, sending response");
                                        let mut buf = bytes::BytesMut::new();
                                        messages::write_keepalive(&mut buf);
                                        let _ = ctrl_tx.send(buf.freeze()).await;
                                    }
                                    Ok(TsgMessage::CloseChannel { .. }) => {
                                        info!("Relay WS→TCP: received CloseChannel");
                                        let mut buf = bytes::BytesMut::new();
                                        messages::write_close_channel_response(&mut buf);
                                        let _ = ctrl_tx.send(buf.freeze()).await;
                                        break;
                                    }
                                    Ok(TsgMessage::Unknown { msg_type, payload }) => {
                                        if msg_type == 0x10 {
                                            // IN-pipe setup signal — respond with same type to acknowledge
                                            debug!("Relay WS→TCP: IN-pipe setup (type 0x10), sending acknowledgment");
                                            let mut buf = bytes::BytesMut::new();
                                            let resp_len: u32 = 8 + payload.len() as u32;
                                            buf.extend_from_slice(&(msg_type as u16).to_le_bytes());
                                            buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
                                            buf.extend_from_slice(&resp_len.to_le_bytes());
                                            buf.extend_from_slice(&payload);
                                            let _ = ctrl_tx.send(buf.freeze()).await;
                                        } else {
                                            debug!("Relay WS→TCP: unknown TSG type 0x{:02x} ({} bytes payload), ignoring", msg_type, payload.len());
                                        }
                                    }
                                    Ok(TsgMessage::ChannelCreate(req)) => {
                                        // IN-channel setup during relay — respond and skip next Data
                                        info!("Relay WS→TCP: ChannelCreate for {}:{}, responding", req.server_name, req.port);
                                        let response = messages::ChannelResponse {
                                            error_code: 0,
                                            fields_present: messages::HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
                                            reserved: 0,
                                            channel_id: Some(1),
                                            udp_port: None,
                                            auth_cookie: None,
                                        };
                                        let mut buf = bytes::BytesMut::new();
                                        response.write(&mut buf);
                                        let _ = ctrl_tx.send(buf.freeze()).await;
                                        skip_next_data = true;
                                    }
                                    Ok(other) => {
                                        warn!("Relay WS→TCP: unhandled TSG message during relay: {:?}", other);
                                    }
                                    Err(e) => {
                                        error!("Relay WS→TCP: parse error: {}", e);
                                    }
                                }
                            }
                            TMessage::Ping(_data) => {
                                debug!("Relay WS→TCP: got Ping");
                            }
                            TMessage::Close(_) => {
                                info!("Relay WS→TCP: client sent Close");
                                break;
                            }
                            _ => {}
                        }
                    }
                    info!("Relay WS→TCP ended: {} messages, {} bytes from {}", msg_count, total_bytes, client_addr_log);
                    let _ = tcp_write.shutdown().await;
                });

                // TCP → WS task: forward backend data + control responses to client
                let tcp_to_ws = tokio::spawn(async move {
                    use rdg_proto::websocket::encode_data_message;
                    use tokio::io::AsyncReadExt;
                    let mut buf = vec![0u8; 16384];
                    let mut total_bytes: u64 = 0;
                    let mut msg_count: u64 = 0;
                    loop {
                        tokio::select! {
                            // Forward backend TCP data to client via WebSocket
                            result = tcp_read.read(&mut buf) => {
                                let n = match result {
                                    Ok(0) => {
                                        info!("Relay TCP→WS: backend closed connection");
                                        break;
                                    }
                                    Ok(n) => n,
                                    Err(e) => {
                                        error!("Relay TCP→WS read error: {}", e);
                                        break;
                                    }
                                };
                                total_bytes += n as u64;
                                msg_count += 1;
                                if msg_count <= 10 || msg_count % 50 == 0 {
                                    debug!("Relay TCP→WS #{}: {} bytes (total: {}) first_bytes={:02x?}", msg_count, n, total_bytes, &buf[..n.min(16)]);
                                }
                                let ws_msg = encode_data_message(&buf[..n]);
                                if ws_sink.send(TMessage::Binary(ws_msg)).await.is_err() {
                                    error!("Relay TCP→WS: WS send failed");
                                    break;
                                }
                            }
                            // Forward control responses (keepalive, close) to client
                            Some(ctrl_msg) = ctrl_rx.recv() => {
                                debug!("Relay TCP→WS: sending control response ({} bytes)", ctrl_msg.len());
                                if ws_sink.send(TMessage::Binary(ctrl_msg)).await.is_err() {
                                    error!("Relay TCP→WS: WS send ctrl failed");
                                    break;
                                }
                            }
                        }
                    }
                    info!("Relay TCP→WS ended: {} messages, {} bytes", msg_count, total_bytes);
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
                debug!(
                    "Sending TSG response ({} bytes): {:02x?}",
                    response.len(),
                    &response[..response.len().min(64)]
                );
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
