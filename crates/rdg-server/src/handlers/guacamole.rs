use std::sync::Arc;

use axum::{
    Router,
    extract::{Query, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
    routing::get,
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

use crate::state::AppState;
use crate::handlers::auth;

#[derive(Debug, Deserialize)]
pub struct GuacConnectParams {
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub domain: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub dpi: Option<u32>,
    #[serde(default = "default_security")]
    pub security: String,
    #[serde(default)]
    pub ignore_cert: bool,
}

fn default_security() -> String {
    "any".to_string()
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/guacamole/connect", get(guac_ws_handler))
}

async fn guac_ws_handler(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
    Query(params): Query<GuacConnectParams>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Validate session cookie
    let cookie_header = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok());
    if auth::validate_session_cookie(cookie_header, &state).is_none() {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }

    if !state.config.guacamole.enabled {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    let guacd_host = state.config.guacamole.guacd_host.clone();
    let guacd_port = state.config.guacamole.guacd_port;

    ws.on_upgrade(move |socket| guac_proxy(socket, guacd_host, guacd_port, params))
}

/// Proxy between browser WebSocket (guacamole-common-js) and guacd TCP
async fn guac_proxy(
    ws: WebSocket,
    guacd_host: String,
    guacd_port: u16,
    params: GuacConnectParams,
) {
    let addr = format!("{}:{}", guacd_host, guacd_port);
    info!("Guacamole proxy: connecting to guacd at {}", addr);

    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Guacamole proxy: failed to connect to guacd at {}: {}", addr, e);
            return;
        }
    };

    let (tcp_read, mut tcp_write) = stream.into_split();
    let mut tcp_reader = BufReader::new(tcp_read);

    // Send Guacamole handshake to guacd
    let rdp_port = params.port.unwrap_or(3389);
    let width = params.width.unwrap_or(1024);
    let height = params.height.unwrap_or(768);
    let dpi = params.dpi.unwrap_or(96);

    // Guacamole protocol: select RDP
    let select_instruction = format!(
        "6.select,3.rdp;"
    );
    if tcp_write.write_all(select_instruction.as_bytes()).await.is_err() {
        error!("Guacamole proxy: failed to send select to guacd");
        return;
    }

    // Read guacd's args response
    let mut args_line = String::new();
    if tcp_reader.read_line(&mut args_line).await.is_err() {
        error!("Guacamole proxy: failed to read args from guacd");
        return;
    }
    debug!("Guacamole proxy: guacd args response: {}", args_line.trim());

    // Build connect instruction with RDP parameters
    let connect_args = build_connect_instruction(&params, rdp_port, width, height, dpi);
    if tcp_write.write_all(connect_args.as_bytes()).await.is_err() {
        error!("Guacamole proxy: failed to send connect to guacd");
        return;
    }

    // Read guacd's ready response
    let mut ready_line = String::new();
    if tcp_reader.read_line(&mut ready_line).await.is_err() {
        error!("Guacamole proxy: failed to read ready from guacd");
        return;
    }
    debug!("Guacamole proxy: guacd ready response: {}", ready_line.trim());

    if !ready_line.contains("ready") {
        error!("Guacamole proxy: guacd did not return ready: {}", ready_line.trim());
        return;
    }

    info!("Guacamole proxy: connected to {}:{} via guacd", params.host, rdp_port);

    // Relay between WebSocket and guacd
    let (mut ws_sink, mut ws_stream) = ws.split();

    // Send the ready instruction to the browser client
    if ws_sink.send(Message::Text(ready_line.trim().into())).await.is_err() {
        return;
    }

    // guacd → browser
    let guacd_to_browser = tokio::spawn(async move {
        let mut buf = String::new();
        loop {
            buf.clear();
            match tcp_reader.read_line(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = buf.trim_end_matches('\n');
                    if ws_sink.send(Message::Text(trimmed.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    debug!("Guacamole proxy: guacd read error: {}", e);
                    break;
                }
            }
        }
        info!("Guacamole proxy: guacd→browser ended");
    });

    // browser → guacd
    let browser_to_guacd = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_stream.next().await {
            match msg {
                Message::Text(text) => {
                    let mut data = text.as_bytes().to_vec();
                    data.push(b'\n');
                    if tcp_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        info!("Guacamole proxy: browser→guacd ended");
    });

    tokio::select! {
        _ = guacd_to_browser => {},
        _ = browser_to_guacd => {},
    }

    info!("Guacamole proxy: session ended");
}

/// Build the Guacamole `connect` instruction for RDP.
/// Format: 7.connect,{hostname},{port},{...args...};
fn build_connect_instruction(
    params: &GuacConnectParams,
    port: u16,
    width: u32,
    height: u32,
    dpi: u32,
) -> String {
    // Guacamole connect args (ordered as per guacd RDP args):
    // hostname, port, domain, username, password, width, height, dpi, security, ignore-cert, ...
    let hostname = encode_guac_arg(&params.host);
    let port_str = encode_guac_arg(&port.to_string());
    let domain = encode_guac_arg(params.domain.as_deref().unwrap_or(""));
    let username = encode_guac_arg(params.username.as_deref().unwrap_or(""));
    let password = encode_guac_arg(params.password.as_deref().unwrap_or(""));
    let width_s = encode_guac_arg(&width.to_string());
    let height_s = encode_guac_arg(&height.to_string());
    let dpi_s = encode_guac_arg(&dpi.to_string());
    let security = encode_guac_arg(&params.security);
    let ignore_cert = encode_guac_arg(if params.ignore_cert { "true" } else { "" });

    format!(
        "7.connect,{},{},{},{},{},{},{},{},{},{};\n",
        hostname, port_str, domain, username, password,
        width_s, height_s, dpi_s, security, ignore_cert
    )
}

/// Encode a value in Guacamole protocol format: `{length}.{value}`
fn encode_guac_arg(value: &str) -> String {
    format!("{}.{}", value.len(), value)
}
