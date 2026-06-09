//! TSG session state machine.
//!
//! Tracks the lifecycle of a gateway connection through:
//! Handshake → TunnelCreate → TunnelAuth → ChannelCreate → Data

use bytes::{Bytes, BytesMut};
use rdg_proto::messages::*;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    AwaitingHandshake,
    AwaitingTunnelCreate,
    AwaitingTunnelAuth,
    AwaitingChannelCreate,
    DataTransfer,
    Closed,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("unexpected message type 0x{0:04x} in state {1:?}")]
    UnexpectedMessage(u16, SessionState),
    #[error("protocol error: {0}")]
    Protocol(#[from] MessageError),
    #[error("session closed")]
    Closed,
}

/// Server-side session state machine for a single gateway connection.
pub struct GatewaySession {
    pub state: SessionState,
    pub tunnel_id: u32,
    pub channel_id: u32,
    pub client_name: Option<String>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    next_tunnel_id: u32,
    next_channel_id: u32,
}

impl GatewaySession {
    pub fn new() -> Self {
        Self {
            state: SessionState::AwaitingHandshake,
            tunnel_id: 0,
            channel_id: 0,
            client_name: None,
            target_host: None,
            target_port: None,
            next_tunnel_id: 1,
            next_channel_id: 1,
        }
    }

    /// Process an incoming TSG message and produce the response.
    /// Returns None for Data messages (handled separately).
    pub fn process_message(&mut self, msg: &TsgMessage) -> Result<Option<Bytes>, SessionError> {
        match (self.state, msg) {
            (SessionState::AwaitingHandshake, TsgMessage::HandshakeRequest(req)) => {
                let response = HandshakeResponse {
                    error_code: 0,
                    major_version: req.major_version,
                    minor_version: req.minor_version,
                    server_version: 0,
                    ext_auth: 0x0007, // Match real server
                };
                let mut buf = BytesMut::new();
                response.write(&mut buf);
                self.state = SessionState::AwaitingTunnelCreate;
                Ok(Some(buf.freeze()))
            }

            (SessionState::AwaitingTunnelCreate, TsgMessage::TunnelCreate(_req)) => {
                self.tunnel_id = self.next_tunnel_id;
                self.next_tunnel_id += 1;

                let response = TunnelResponse {
                    server_version: 0,
                    error_code: 0,
                    fields_present: HTTP_TUNNEL_RESPONSE_FIELD_TUNNEL_ID
                        | HTTP_TUNNEL_RESPONSE_FIELD_CAPS,
                    reserved: 0,
                    tunnel_id: Some(self.tunnel_id),
                    caps: Some(0x0d), // NAP_QUAR_SOH | CONSENT_SIGN | SERVICE_MSG
                };
                let mut buf = BytesMut::new();
                response.write(&mut buf);
                self.state = SessionState::AwaitingTunnelAuth;
                Ok(Some(buf.freeze()))
            }

            (SessionState::AwaitingTunnelAuth, TsgMessage::TunnelAuth(req)) => {
                self.client_name = Some(req.client_name.clone());

                let response = TunnelAuthResponse {
                    error_code: 0,
                    flags: 0x0003,
                    reserved: 0,
                    idle_timeout: 0,
                    soh_response: None,
                };
                let mut buf = BytesMut::new();
                response.write(&mut buf);
                self.state = SessionState::AwaitingChannelCreate;
                Ok(Some(buf.freeze()))
            }

            (SessionState::AwaitingChannelCreate, TsgMessage::ChannelCreate(req)) => {
                self.target_host = Some(req.server_name.clone());
                self.target_port = Some(req.port);
                self.channel_id = self.next_channel_id;
                self.next_channel_id += 1;

                let response = ChannelResponse {
                    error_code: 0,
                    fields_present: HTTP_CHANNEL_RESPONSE_FIELD_CHANNELID,
                    reserved: 0,
                    channel_id: Some(self.channel_id),
                    udp_port: None,
                    auth_cookie: None,
                };
                let mut buf = BytesMut::new();
                response.write(&mut buf);
                self.state = SessionState::DataTransfer;
                Ok(Some(buf.freeze()))
            }

            (SessionState::DataTransfer, TsgMessage::Data(_)) => {
                // Data messages are handled by the relay, not the state machine
                Ok(None)
            }

            (state, msg) => {
                let msg_type = match msg {
                    TsgMessage::HandshakeRequest(_) => MessageType::HandshakeRequest as u16,
                    TsgMessage::HandshakeResponse(_) => MessageType::HandshakeResponse as u16,
                    TsgMessage::TunnelCreate(_) => MessageType::TunnelCreate as u16,
                    TsgMessage::TunnelResponse(_) => MessageType::TunnelResponse as u16,
                    TsgMessage::TunnelAuth(_) => MessageType::TunnelAuth as u16,
                    TsgMessage::TunnelAuthResponse(_) => MessageType::TunnelAuthResponse as u16,
                    TsgMessage::ChannelCreate(_) => MessageType::ChannelCreate as u16,
                    TsgMessage::ChannelResponse(_) => MessageType::ChannelResponse as u16,
                    TsgMessage::Data(_) => MessageType::Data as u16,
                    TsgMessage::Unknown { msg_type, .. } => *msg_type,
                };
                Err(SessionError::UnexpectedMessage(msg_type, state))
            }
        }
    }

    pub fn is_data_transfer(&self) -> bool {
        self.state == SessionState::DataTransfer
    }
}

impl Default for GatewaySession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake_request() -> TsgMessage {
        TsgMessage::HandshakeRequest(HandshakeRequest {
            major_version: 1,
            minor_version: 0,
            client_version: 0,
            ext_auth: 0,
        })
    }

    fn tunnel_create() -> TsgMessage {
        TsgMessage::TunnelCreate(TunnelCreate {
            caps_flags: 0x0001_0001,
            fields_present: 0,
            reserved: 0,
            paa_cookie: None,
        })
    }

    fn tunnel_auth() -> TsgMessage {
        TsgMessage::TunnelAuth(TunnelAuth {
            fields_present: 0,
            client_name: "TEST-PC".to_string(),
        })
    }

    fn channel_create() -> TsgMessage {
        TsgMessage::ChannelCreate(ChannelCreate {
            num_resources: 1,
            num_alt_resources: 0,
            port: 3389,
            protocol: 0,
            server_name: "rdp-host".to_string(),
        })
    }

    fn data_msg() -> TsgMessage {
        TsgMessage::Data(DataMessage {
            data: Bytes::from_static(b"hello"),
        })
    }

    #[test]
    fn happy_path_full_progression() {
        let mut session = GatewaySession::new();
        assert_eq!(session.state, SessionState::AwaitingHandshake);

        // Handshake
        let resp = session.process_message(&handshake_request()).unwrap();
        assert!(resp.is_some());
        assert_eq!(session.state, SessionState::AwaitingTunnelCreate);

        // TunnelCreate
        let resp = session.process_message(&tunnel_create()).unwrap();
        assert!(resp.is_some());
        assert_eq!(session.state, SessionState::AwaitingTunnelAuth);
        assert_eq!(session.tunnel_id, 1);

        // TunnelAuth
        let resp = session.process_message(&tunnel_auth()).unwrap();
        assert!(resp.is_some());
        assert_eq!(session.state, SessionState::AwaitingChannelCreate);
        assert_eq!(session.client_name.as_deref(), Some("TEST-PC"));

        // ChannelCreate
        let resp = session.process_message(&channel_create()).unwrap();
        assert!(resp.is_some());
        assert_eq!(session.state, SessionState::DataTransfer);
        assert_eq!(session.target_host.as_deref(), Some("rdp-host"));
        assert_eq!(session.target_port, Some(3389));
        assert_eq!(session.channel_id, 1);

        // Data
        let resp = session.process_message(&data_msg()).unwrap();
        assert!(resp.is_none()); // Data messages not handled by state machine
        assert!(session.is_data_transfer());
    }

    #[test]
    fn wrong_message_in_handshake_state() {
        let mut session = GatewaySession::new();
        let err = session.process_message(&tunnel_create()).unwrap_err();
        assert!(matches!(
            err,
            SessionError::UnexpectedMessage(0x0004, SessionState::AwaitingHandshake)
        ));
    }

    #[test]
    fn wrong_message_in_tunnel_create_state() {
        let mut session = GatewaySession::new();
        session.process_message(&handshake_request()).unwrap();
        let err = session.process_message(&channel_create()).unwrap_err();
        assert!(matches!(
            err,
            SessionError::UnexpectedMessage(0x0008, SessionState::AwaitingTunnelCreate)
        ));
    }

    #[test]
    fn wrong_message_in_tunnel_auth_state() {
        let mut session = GatewaySession::new();
        session.process_message(&handshake_request()).unwrap();
        session.process_message(&tunnel_create()).unwrap();
        let err = session.process_message(&handshake_request()).unwrap_err();
        assert!(matches!(
            err,
            SessionError::UnexpectedMessage(0x0001, SessionState::AwaitingTunnelAuth)
        ));
    }

    #[test]
    fn wrong_message_in_channel_create_state() {
        let mut session = GatewaySession::new();
        session.process_message(&handshake_request()).unwrap();
        session.process_message(&tunnel_create()).unwrap();
        session.process_message(&tunnel_auth()).unwrap();
        let err = session.process_message(&data_msg()).unwrap_err();
        assert!(matches!(
            err,
            SessionError::UnexpectedMessage(0x000A, SessionState::AwaitingChannelCreate)
        ));
    }

    #[test]
    fn data_in_data_transfer_returns_none() {
        let mut session = GatewaySession::new();
        session.process_message(&handshake_request()).unwrap();
        session.process_message(&tunnel_create()).unwrap();
        session.process_message(&tunnel_auth()).unwrap();
        session.process_message(&channel_create()).unwrap();

        let resp = session.process_message(&data_msg()).unwrap();
        assert!(resp.is_none());
        assert_eq!(session.state, SessionState::DataTransfer);
    }

    #[test]
    fn tunnel_ids_increment() {
        let mut session = GatewaySession::new();
        session.process_message(&handshake_request()).unwrap();
        session.process_message(&tunnel_create()).unwrap();
        assert_eq!(session.tunnel_id, 1);
    }

    #[test]
    fn default_trait_works() {
        let session = GatewaySession::default();
        assert_eq!(session.state, SessionState::AwaitingHandshake);
    }

    #[test]
    fn handshake_response_echoes_version() {
        let mut session = GatewaySession::new();
        let req = TsgMessage::HandshakeRequest(HandshakeRequest {
            major_version: 2,
            minor_version: 5,
            client_version: 0x0300,
            ext_auth: 0x001F,
        });
        let resp_bytes = session.process_message(&req).unwrap().unwrap();
        let resp_msg = parse_message(&resp_bytes).unwrap();
        match resp_msg {
            TsgMessage::HandshakeResponse(h) => {
                assert_eq!(h.major_version, 2);
                assert_eq!(h.minor_version, 5);
                assert_eq!(h.error_code, 0);
            }
            _ => panic!("Expected HandshakeResponse"),
        }
    }
}
