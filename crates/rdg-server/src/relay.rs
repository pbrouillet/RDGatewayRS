//! TCP relay: bidirectional copy between WebSocket and backend TCP.

use crate::metrics;
use axum::extract::ws::{Message, WebSocket};
use bytes::Bytes;
use futures::stream::StreamExt;
use futures::SinkExt;
use opentelemetry::KeyValue;
use rdg_proto::messages;
use rdg_proto::websocket::encode_data_message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

/// Start bidirectional relay between the WebSocket and a backend TCP target.
pub async fn start_relay(
    socket: WebSocket,
    target_host: &str,
    target_port: u16,
    initial_data: Option<Bytes>,
) {
    let target_addr = format!("{}:{}", target_host, target_port);
    info!("Connecting to backend: {}", target_addr);

    let m = metrics::get();
    let attrs = [KeyValue::new("target", target_addr.clone())];
    m.connections_active.add(1, &attrs);
    let start = std::time::Instant::now();

    let tcp_stream = match TcpStream::connect(&target_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to backend {}: {}", target_addr, e);
            m.connections_active.add(-1, &attrs);
            return;
        }
    };

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
    let (mut ws_sink, mut ws_stream) = socket.split();

    // Send initial data to backend if present
    if let Some(data) = initial_data {
        if let Err(e) = tcp_write.write_all(&data).await {
            error!("Failed to send initial data to backend: {}", e);
            m.connections_active.add(-1, &attrs);
            return;
        }
        debug!("Sent {} bytes initial data to backend", data.len());
    }

    // WebSocket -> TCP (client to backend)
    let ws_to_tcp = tokio::spawn(async move {
        loop {
            let msg = match ws_stream.next().await {
                Some(Ok(Message::Binary(data))) => data,
                Some(Ok(Message::Close(_))) | None => {
                    debug!("WebSocket closed (client -> backend)");
                    break;
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => {
                    error!("WebSocket read error: {}", e);
                    break;
                }
            };

            match messages::parse_message(&msg) {
                Ok(messages::TsgMessage::Data(data_msg)) => {
                    if let Err(e) = tcp_write.write_all(&data_msg.data).await {
                        error!("TCP write error: {}", e);
                        break;
                    }
                }
                Ok(_) => {
                    debug!("Ignoring non-data message during relay");
                }
                Err(e) => {
                    error!("Failed to parse message during relay: {}", e);
                    break;
                }
            }
        }
        let _ = tcp_write.shutdown().await;
    });

    // TCP -> WebSocket (backend to client)
    let tcp_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = match tcp_read.read(&mut buf).await {
                Ok(0) => {
                    debug!("TCP backend closed connection");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    error!("TCP read error: {}", e);
                    break;
                }
            };

            let ws_msg = encode_data_message(&buf[..n]);
            if let Err(e) = ws_sink.send(Message::Binary(ws_msg.to_vec().into())).await {
                error!("WebSocket write error: {}", e);
                break;
            }
        }
        let _ = ws_sink.close().await;
    });

    let _ = tokio::join!(ws_to_tcp, tcp_to_ws);

    let duration = start.elapsed().as_secs_f64();
    m.connections_active.add(-1, &attrs);
    m.relay_duration_seconds.record(duration, &attrs);
    info!("Relay session ended (duration: {:.1}s)", duration);
}
