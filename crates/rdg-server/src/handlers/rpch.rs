//! RPC-over-HTTP v2 handler for mstsc compatibility.
//!
//! mstsc uses two HTTP channels:
//! - OUT channel (RPC_OUT_DATA): server→client data (long-lived response)
//! - IN channel (RPC_IN_DATA): client→server data (long-lived request body)
//!
//! Flow:
//! 1. Client opens OUT channel, sends CONN/A1 RTS
//! 2. Client opens IN channel, sends CONN/B1 RTS
//! 3. Server sends CONN/C2 on OUT channel
//! 4. Client sends DCE/RPC Bind on IN channel
//! 5. Server sends BindAck on OUT channel
//! 6. Client sends RPC Request (TSG opnums) on IN channel
//! 7. Server sends RPC Response on OUT channel
//! 8. Eventually enters data transfer (relay mode)

use axum::{
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode},
    routing::any,
    Router,
};
use bytes::Bytes;
use rdg_proto::{
    messages::{self, TsgMessage},
    rpc::{BindAckPdu, BindPdu, RequestPdu, ResponsePdu, RpcPduHeader, RpcPduType, RPC_HEADER_SIZE},
    rpch::{RtsPdu, VirtualConnection, PTYPE_RTS},
};
use rdg_core::session::GatewaySession;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::state::AppState;

/// Shared state for correlating IN/OUT channels of the same virtual connection.
#[derive(Default)]
struct RpchState {
    /// Maps virtual_connection_cookie → pending connection context
    pending: HashMap<Uuid, PendingConnection>,
}

struct PendingConnection {
    vconn: VirtualConnection,
    /// Sender to push data frames to the OUT channel response body
    out_sender: mpsc::Sender<Bytes>,
}

type SharedRpchState = Arc<Mutex<RpchState>>;

pub fn routes() -> Router<Arc<AppState>> {
    let rpch_state: SharedRpchState = Arc::new(Mutex::new(RpchState::default()));

    Router::new()
        .route(
            "/rpc/rpcproxy.dll",
            any(move |state, rpch, req| handle_rpch(state, rpch, req)),
        )
        .layer(axum::Extension(rpch_state))
}

async fn handle_rpch(
    State(_app_state): State<Arc<AppState>>,
    axum::Extension(rpch_state): axum::Extension<SharedRpchState>,
    req: Request<Body>,
) -> Response<Body> {
    let method = req.method().as_str().to_uppercase();

    match method.as_str() {
        "RPC_OUT_DATA" => handle_out_channel(rpch_state, req).await,
        "RPC_IN_DATA" => handle_in_channel(rpch_state, req).await,
        _ => {
            debug!("RPCH: unexpected method {}", method);
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::empty())
                .unwrap()
        }
    }
}

/// Handle the OUT channel (RPC_OUT_DATA).
/// Client sends CONN/A1, then this becomes a long-lived response streaming data back.
async fn handle_out_channel(
    rpch_state: SharedRpchState,
    req: Request<Body>,
) -> Response<Body> {
    // Read the request body (should contain CONN/A1 RTS PDU)
    let body_bytes = match axum::body::to_bytes(req.into_body(), 65536).await {
        Ok(b) => b,
        Err(e) => {
            error!("RPCH OUT: failed to read body: {}", e);
            return error_response(StatusCode::BAD_REQUEST);
        }
    };

    if body_bytes.len() < 20 {
        return error_response(StatusCode::BAD_REQUEST);
    }

    // Parse CONN/A1
    let pdu = match RtsPdu::parse(&body_bytes) {
        Ok(p) => p,
        Err(e) => {
            error!("RPCH OUT: failed to parse RTS PDU: {}", e);
            return error_response(StatusCode::BAD_REQUEST);
        }
    };

    let conn_a1 = match pdu.as_conn_a1() {
        Ok(a1) => a1,
        Err(e) => {
            error!("RPCH OUT: not a valid CONN/A1: {}", e);
            return error_response(StatusCode::BAD_REQUEST);
        }
    };

    info!(
        "RPCH OUT: CONN/A1 received, vconn={}, out_channel={}",
        conn_a1.virtual_connection_cookie, conn_a1.out_channel_cookie
    );

    let mut vconn = VirtualConnection::new();
    if let Err(e) = vconn.accept_out_channel(conn_a1.clone()) {
        error!("RPCH OUT: failed to accept out channel: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Create a channel for streaming data back to client
    let (tx, rx) = mpsc::channel::<Bytes>(64);

    // Store in shared state for IN channel correlation
    {
        let mut state = rpch_state.lock().await;
        state.pending.insert(
            conn_a1.virtual_connection_cookie,
            PendingConnection {
                vconn,
                out_sender: tx,
            },
        );
    }

    // Convert the receiver into a streaming response body
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(stream.map(Ok::<_, std::io::Error>));

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/rpc")
        .body(body)
        .unwrap()
}

/// Handle the IN channel (RPC_IN_DATA).
/// Client sends CONN/B1, then DCE/RPC PDUs (Bind, Request) as a streaming request body.
async fn handle_in_channel(
    rpch_state: SharedRpchState,
    req: Request<Body>,
) -> Response<Body> {
    use http_body_util::BodyExt;

    // Stream the body incrementally
    let mut body = req.into_body();
    let mut buf = bytes::BytesMut::new();

    // Read enough for the first RTS PDU (CONN/B1)
    while buf.len() < 20 {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    buf.extend_from_slice(data);
                }
            }
            _ => {
                error!("RPCH IN: body ended before CONN/B1");
                return error_response(StatusCode::BAD_REQUEST);
            }
        }
    }

    // Read the frag_length to know how much the first PDU is
    let frag_length = u16::from_le_bytes([buf[8], buf[9]]) as usize;
    while buf.len() < frag_length {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    buf.extend_from_slice(data);
                }
            }
            _ => {
                error!("RPCH IN: body ended mid-PDU");
                return error_response(StatusCode::BAD_REQUEST);
            }
        }
    }

    // First PDU should be CONN/B1 (RTS)
    if buf[2] != PTYPE_RTS {
        error!("RPCH IN: expected RTS PDU, got ptype={}", buf[2]);
        return error_response(StatusCode::BAD_REQUEST);
    }

    // Parse only the first frag_length bytes as CONN/B1
    let rts_pdu = match RtsPdu::parse(&buf[..frag_length]) {
        Ok(p) => p,
        Err(e) => {
            error!("RPCH IN: failed to parse CONN/B1: {}", e);
            return error_response(StatusCode::BAD_REQUEST);
        }
    };

    let conn_b1 = match rts_pdu.as_conn_b1() {
        Ok(b1) => b1,
        Err(e) => {
            error!("RPCH IN: not a valid CONN/B1: {}", e);
            return error_response(StatusCode::BAD_REQUEST);
        }
    };

    info!(
        "RPCH IN: CONN/B1 received, vconn={}, in_channel={}",
        conn_b1.virtual_connection_cookie, conn_b1.in_channel_cookie
    );

    // Look up the pending connection from OUT channel
    let (mut vconn, out_tx) = {
        let mut state = rpch_state.lock().await;
        match state.pending.remove(&conn_b1.virtual_connection_cookie) {
            Some(pending) => (pending.vconn, pending.out_sender),
            None => {
                error!(
                    "RPCH IN: no matching OUT channel for vconn={}",
                    conn_b1.virtual_connection_cookie
                );
                return error_response(StatusCode::BAD_REQUEST);
            }
        }
    };

    // Accept the IN channel and get CONN/C2 response
    let conn_c2 = match vconn.accept_in_channel(conn_b1) {
        Ok(c2) => c2,
        Err(e) => {
            error!("RPCH IN: failed to accept in channel: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Send CONN/C2 on the OUT channel
    let c2_bytes = conn_c2.to_bytes();
    if out_tx.send(Bytes::from(c2_bytes)).await.is_err() {
        error!("RPCH IN: OUT channel closed before CONN/C2 could be sent");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR);
    }

    debug!("RPCH: CONN/C2 sent, connection established");

    // Process remaining data from buffer + streaming body as DCE/RPC PDUs
    // Remove the already-consumed CONN/B1 from buf
    let _ = buf.split_to(frag_length);

    if let Err(e) = process_rpc_pdus_streaming(&mut buf, body, &out_tx, &mut vconn).await {
        error!("RPCH: RPC processing error: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

/// Process DCE/RPC PDUs streaming from the IN channel body.
async fn process_rpc_pdus_streaming(
    buf: &mut bytes::BytesMut,
    mut body: Body,
    out_tx: &mpsc::Sender<Bytes>,
    vconn: &mut VirtualConnection,
) -> Result<(), String> {
    use http_body_util::BodyExt;

    let mut session = GatewaySession::new();
    let mut bound = false;

    loop {
        // Ensure we have at least a header
        while buf.len() < RPC_HEADER_SIZE {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        buf.extend_from_slice(data);
                    }
                }
                _ => {
                    // Body ended — if buffer is empty, that's normal completion
                    if buf.is_empty() {
                        return Ok(());
                    }
                    return Err("Body ended mid-PDU header".to_string());
                }
            }
        }

        let header = RpcPduHeader::parse(buf)
            .map_err(|e| format!("RPC header parse error: {}", e))?;
        let frag_len = header.frag_length as usize;

        // Read until we have the complete PDU
        while buf.len() < frag_len {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        buf.extend_from_slice(data);
                    }
                }
                _ => return Err("Body ended mid-PDU".to_string()),
            }
        }

        // Extract this PDU
        let pdu_data = buf.split_to(frag_len).freeze();

        match header.ptype {
            RpcPduType::Bind => {
                let bind = BindPdu::parse(&pdu_data)
                    .map_err(|e| format!("Bind parse error: {}", e))?;

                if !bind.is_tsg_bind() {
                    return Err("Bind for non-TSG interface".to_string());
                }

                info!("RPCH: DCE/RPC Bind for TSG interface");

                vconn.enter_data_transfer()
                    .map_err(|e| format!("State transition error: {}", e))?;

                let ack = BindAckPdu::accepted(
                    bind.header.call_id,
                    bind.assoc_group_id,
                    b"\0",
                );
                out_tx.send(ack.encode())
                    .await
                    .map_err(|_| "OUT channel closed")?;
                bound = true;
                debug!("RPCH: BindAck sent");
            }

            RpcPduType::Request if bound => {
                let request = RequestPdu::parse(&pdu_data)
                    .map_err(|e| format!("Request parse error: {}", e))?;

                debug!("RPCH: RPC Request opnum={}", request.opnum);

                let response_stub = process_tsg_opnum(
                    request.opnum,
                    &request.stub_data,
                    &mut session,
                )?;

                let response = ResponsePdu::new(
                    request.header.call_id,
                    request.context_id,
                    response_stub,
                );
                out_tx.send(response.encode())
                    .await
                    .map_err(|_| "OUT channel closed")?;
            }

            other => {
                warn!("RPCH: unexpected PDU type {:?} (bound={})", other, bound);
            }
        }
    }
}

/// Map TSG opnums to our session state machine.
/// MS-TSGU opnums:
///   1 = TsgCreateTunnel
///   2 = TsgAuthorizeTunnel
///   3 = TsgMakeTunnelCall
///   4 = TsgCreateChannel
///   5 = TsgCloseChannel
///   6 = TsgCloseTunnel
///   9 = TsgSetupReceivePipe
fn process_tsg_opnum(
    opnum: u16,
    _stub_data: &[u8],
    session: &mut GatewaySession,
) -> Result<Bytes, String> {
    use bytes::BufMut;

    match opnum {
        1 => {
            // TsgCreateTunnel → equivalent of Handshake + TunnelCreate
            let handshake = messages::HandshakeRequest {
                major_version: 1,
                minor_version: 0,
                client_version: 0,
                ext_auth: 0,
            };
            let _ = session.process_message(&TsgMessage::HandshakeRequest(handshake))
                .map_err(|e| format!("session error: {}", e))?;

            let tunnel_create = messages::TunnelCreate {
                caps_flags: 0,
                fields_present: 0,
                reserved: 0,
                paa_cookie: None,
            };
            let _ = session.process_message(&TsgMessage::TunnelCreate(tunnel_create))
                .map_err(|e| format!("session error: {}", e))?;

            // Return success stub (tunnel_id + error_code)
            let mut stub = bytes::BytesMut::new();
            stub.put_u32_le(session.tunnel_id); // tunnel context
            stub.put_u32_le(0); // HRESULT = S_OK
            Ok(stub.freeze())
        }

        2 => {
            // TsgAuthorizeTunnel → equivalent of TunnelAuth
            let tunnel_auth = messages::TunnelAuth {
                fields_present: 0,
                client_name: "MSTSC-CLIENT".to_string(),
            };
            let _ = session.process_message(&TsgMessage::TunnelAuth(tunnel_auth))
                .map_err(|e| format!("session error: {}", e))?;

            let mut stub = bytes::BytesMut::new();
            stub.put_u32_le(0); // HRESULT = S_OK
            stub.put_u32_le(0x0003); // flags
            stub.put_u32_le(0); // idle timeout
            Ok(stub.freeze())
        }

        4 => {
            // TsgCreateChannel → equivalent of ChannelCreate
            let channel_create = messages::ChannelCreate {
                num_resources: 1,
                num_alt_resources: 0,
                port: 3389, // TODO: parse from stub_data
                protocol: 0,
                server_name: "localhost".to_string(), // TODO: parse from stub_data
            };
            let _ = session.process_message(&TsgMessage::ChannelCreate(channel_create))
                .map_err(|e| format!("session error: {}", e))?;

            let mut stub = bytes::BytesMut::new();
            stub.put_u32_le(session.channel_id); // channel context
            stub.put_u32_le(0); // HRESULT = S_OK
            Ok(stub.freeze())
        }

        9 => {
            // TsgSetupReceivePipe — signals ready for data
            info!("RPCH: TsgSetupReceivePipe — entering data transfer mode");
            let mut stub = bytes::BytesMut::new();
            stub.put_u32_le(0); // HRESULT = S_OK
            Ok(stub.freeze())
        }

        opnum => {
            warn!("RPCH: unhandled TSG opnum {}", opnum);
            let mut stub = bytes::BytesMut::new();
            stub.put_u32_le(0); // generic success
            Ok(stub.freeze())
        }
    }
}

fn error_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap()
}

use tokio_stream::StreamExt;
