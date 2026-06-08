//! TSG (Terminal Services Gateway) message types.
//!
//! Wire format (little-endian):
//! ```text
//! [type: u16][reserved: u16][length: u32][payload...]
//! ```
//! Length includes the 8-byte header.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

pub const HEADER_SIZE: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    HandshakeRequest = 0x0001,
    HandshakeResponse = 0x0002,
    TunnelCreate = 0x0004,
    TunnelResponse = 0x0005,
    TunnelAuth = 0x0006,
    TunnelAuthResponse = 0x0007,
    ChannelCreate = 0x0008,
    ChannelResponse = 0x0009,
    Data = 0x000A,
    ServiceMessage = 0x000B,
    ReasuthMessage = 0x000C,
}

impl MessageType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(Self::HandshakeRequest),
            0x0002 => Some(Self::HandshakeResponse),
            0x0004 => Some(Self::TunnelCreate),
            0x0005 => Some(Self::TunnelResponse),
            0x0006 => Some(Self::TunnelAuth),
            0x0007 => Some(Self::TunnelAuthResponse),
            0x0008 => Some(Self::ChannelCreate),
            0x0009 => Some(Self::ChannelResponse),
            0x000A => Some(Self::Data),
            0x000B => Some(Self::ServiceMessage),
            0x000C => Some(Self::ReasuthMessage),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("buffer too short: need {needed} bytes, have {have}")]
    BufferTooShort { needed: usize, have: usize },
    #[error("unknown message type: 0x{0:04x}")]
    UnknownType(u16),
    #[error("invalid message length: {0}")]
    InvalidLength(u32),
    #[error("invalid utf-16 string")]
    InvalidUtf16,
}

/// Raw message header
#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    pub msg_type: u16,
    pub reserved: u16,
    pub length: u32,
}

impl MessageHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, MessageError> {
        if buf.len() < HEADER_SIZE {
            return Err(MessageError::BufferTooShort {
                needed: HEADER_SIZE,
                have: buf.len(),
            });
        }
        let mut r = buf;
        let msg_type = r.get_u16_le();
        let reserved = r.get_u16_le();
        let length = r.get_u32_le();
        Ok(Self {
            msg_type,
            reserved,
            length,
        })
    }

    pub fn write(&self, buf: &mut BytesMut) {
        buf.put_u16_le(self.msg_type);
        buf.put_u16_le(self.reserved);
        buf.put_u32_le(self.length);
    }
}

// --- Handshake ---

/// Capabilities / extended auth flags
pub const HTTP_CAPABILITY_TYPE_QUAR_SOH: u16 = 0x0001;
pub const HTTP_CAPABILITY_IDLE_TIMEOUT: u16 = 0x0002;
pub const HTTP_CAPABILITY_MESSAGING_CONSENT_SIGN: u16 = 0x0004;
pub const HTTP_CAPABILITY_MESSAGING_SERVICE_MSG: u16 = 0x0008;
pub const HTTP_CAPABILITY_REAUTH: u16 = 0x0010;
pub const HTTP_CAPABILITY_UDP_TRANSPORT: u16 = 0x0020;

#[derive(Debug, Clone)]
pub struct HandshakeRequest {
    pub major_version: u8,
    pub minor_version: u8,
    pub client_version: u16,
    pub ext_auth: u16,
}

impl HandshakeRequest {
    pub fn parse(payload: &[u8]) -> Result<Self, MessageError> {
        if payload.len() < 6 {
            return Err(MessageError::BufferTooShort {
                needed: 6,
                have: payload.len(),
            });
        }
        let mut r = payload;
        let major_version = r.get_u8();
        let minor_version = r.get_u8();
        let client_version = r.get_u16_le();
        let ext_auth = r.get_u16_le();
        Ok(Self {
            major_version,
            minor_version,
            client_version,
            ext_auth,
        })
    }

    pub fn write(&self, buf: &mut BytesMut) {
        let len = (HEADER_SIZE + 6) as u32;
        MessageHeader {
            msg_type: MessageType::HandshakeRequest as u16,
            reserved: 0,
            length: len,
        }
        .write(buf);
        buf.put_u8(self.major_version);
        buf.put_u8(self.minor_version);
        buf.put_u16_le(self.client_version);
        buf.put_u16_le(self.ext_auth);
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub error_code: u32,
    pub major_version: u8,
    pub minor_version: u8,
    pub server_version: u16,
    pub ext_auth: u16,
}

impl HandshakeResponse {
    pub fn write(&self, buf: &mut BytesMut) {
        let len = (HEADER_SIZE + 10) as u32;
        MessageHeader {
            msg_type: MessageType::HandshakeResponse as u16,
            reserved: 0,
            length: len,
        }
        .write(buf);
        buf.put_u32_le(self.error_code);
        buf.put_u8(self.major_version);
        buf.put_u8(self.minor_version);
        buf.put_u16_le(self.server_version);
        buf.put_u16_le(self.ext_auth);
    }

    pub fn parse(payload: &[u8]) -> Result<Self, MessageError> {
        if payload.len() < 10 {
            return Err(MessageError::BufferTooShort {
                needed: 10,
                have: payload.len(),
            });
        }
        let mut r = payload;
        let error_code = r.get_u32_le();
        let major_version = r.get_u8();
        let minor_version = r.get_u8();
        let server_version = r.get_u16_le();
        let ext_auth = r.get_u16_le();
        Ok(Self {
            error_code,
            major_version,
            minor_version,
            server_version,
            ext_auth,
        })
    }
}

// --- Tunnel Create ---

pub const HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE: u16 = 0x0001;
pub const HTTP_TUNNEL_PACKET_FIELD_REAUTH: u16 = 0x0002;

#[derive(Debug, Clone)]
pub struct TunnelCreate {
    pub caps_flags: u32,
    pub fields_present: u16,
    pub reserved: u16,
    pub paa_cookie: Option<String>,
}

impl TunnelCreate {
    pub fn parse(payload: &[u8]) -> Result<Self, MessageError> {
        if payload.len() < 8 {
            return Err(MessageError::BufferTooShort {
                needed: 8,
                have: payload.len(),
            });
        }
        let mut r = payload;
        let caps_flags = r.get_u32_le();
        let fields_present = r.get_u16_le();
        let reserved = r.get_u16_le();

        let paa_cookie =
            if fields_present & HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE != 0 && r.remaining() >= 2 {
                let cookie_len = r.get_u16_le() as usize;
                if r.remaining() >= cookie_len {
                    let data = &r[..cookie_len];
                    let s = read_utf16le(data)?;
                    Some(s)
                } else {
                    None
                }
            } else {
                None
            };

        Ok(Self {
            caps_flags,
            fields_present,
            reserved,
            paa_cookie,
        })
    }

    pub fn write(&self, buf: &mut BytesMut) {
        let payload_size = 8;
        let len = (HEADER_SIZE + payload_size) as u32;
        MessageHeader {
            msg_type: MessageType::TunnelCreate as u16,
            reserved: 0,
            length: len,
        }
        .write(buf);
        buf.put_u32_le(self.caps_flags);
        buf.put_u16_le(self.fields_present);
        buf.put_u16_le(self.reserved);
    }
}

#[derive(Debug, Clone)]
pub struct TunnelResponse {
    pub server_version: u16,
    pub status_code: u32,
    pub tunnel_id: u32,
    pub caps: u32,
    pub max_len: u32,
}

impl TunnelResponse {
    pub fn write(&self, buf: &mut BytesMut) {
        let len = (HEADER_SIZE + 18) as u32;
        MessageHeader {
            msg_type: MessageType::TunnelResponse as u16,
            reserved: 0,
            length: len,
        }
        .write(buf);
        buf.put_u16_le(self.server_version);
        buf.put_u32_le(self.status_code);
        buf.put_u32_le(self.tunnel_id);
        buf.put_u32_le(self.caps);
        buf.put_u32_le(self.max_len);
    }

    pub fn parse(payload: &[u8]) -> Result<Self, MessageError> {
        if payload.len() < 18 {
            return Err(MessageError::BufferTooShort {
                needed: 18,
                have: payload.len(),
            });
        }
        let mut r = payload;
        let server_version = r.get_u16_le();
        let status_code = r.get_u32_le();
        let tunnel_id = r.get_u32_le();
        let caps = r.get_u32_le();
        let max_len = r.get_u32_le();
        Ok(Self {
            server_version,
            status_code,
            tunnel_id,
            caps,
            max_len,
        })
    }
}

// --- Tunnel Auth ---

#[derive(Debug, Clone)]
pub struct TunnelAuth {
    pub fields_present: u16,
    pub client_name: String,
}

impl TunnelAuth {
    pub fn parse(payload: &[u8]) -> Result<Self, MessageError> {
        if payload.len() < 4 {
            return Err(MessageError::BufferTooShort {
                needed: 4,
                have: payload.len(),
            });
        }
        let mut r = payload;
        let fields_present = r.get_u16_le();
        let name_len = r.get_u16_le() as usize;
        if r.remaining() < name_len {
            return Err(MessageError::BufferTooShort {
                needed: name_len,
                have: r.remaining(),
            });
        }
        let client_name = read_utf16le(&r[..name_len])?;
        Ok(Self {
            fields_present,
            client_name,
        })
    }

    pub fn write(&self, buf: &mut BytesMut) {
        let name_bytes = encode_utf16le(&self.client_name);
        let payload_size = 4 + name_bytes.len();
        let len = (HEADER_SIZE + payload_size) as u32;
        MessageHeader {
            msg_type: MessageType::TunnelAuth as u16,
            reserved: 0,
            length: len,
        }
        .write(buf);
        buf.put_u16_le(self.fields_present);
        buf.put_u16_le(name_bytes.len() as u16);
        buf.put_slice(&name_bytes);
    }
}

#[derive(Debug, Clone)]
pub struct TunnelAuthResponse {
    pub error_code: u32,
    pub flags: u16,
    pub reserved: u16,
    pub idle_timeout: u32,
    pub soh_response: Option<Bytes>,
}

impl TunnelAuthResponse {
    pub fn write(&self, buf: &mut BytesMut) {
        let len = (HEADER_SIZE + 16) as u32;
        MessageHeader {
            msg_type: MessageType::TunnelAuthResponse as u16,
            reserved: 0,
            length: len,
        }
        .write(buf);
        buf.put_u32_le(self.error_code);
        buf.put_u16_le(self.flags);
        buf.put_u16_le(self.reserved);
        buf.put_u32_le(self.idle_timeout);
        buf.put_u32_le(0); // SOH response length = 0
    }

    pub fn parse(payload: &[u8]) -> Result<Self, MessageError> {
        if payload.len() < 12 {
            return Err(MessageError::BufferTooShort {
                needed: 12,
                have: payload.len(),
            });
        }
        let mut r = payload;
        let error_code = r.get_u32_le();
        let flags = r.get_u16_le();
        let reserved = r.get_u16_le();
        let idle_timeout = r.get_u32_le();
        Ok(Self {
            error_code,
            flags,
            reserved,
            idle_timeout,
            soh_response: None,
        })
    }
}

// --- Channel Create ---

pub const HTTP_CHANNEL_FIELD_REAUTH: u16 = 0x0001;

#[derive(Debug, Clone)]
pub struct ChannelCreate {
    pub num_resources: u8,
    pub num_alt_resources: u8,
    pub port: u16,
    pub protocol: u16,
    pub server_name: String,
}

impl ChannelCreate {
    pub fn parse(payload: &[u8]) -> Result<Self, MessageError> {
        if payload.len() < 8 {
            return Err(MessageError::BufferTooShort {
                needed: 8,
                have: payload.len(),
            });
        }
        let mut r = payload;
        let num_resources = r.get_u8();
        let num_alt_resources = r.get_u8();
        let port = r.get_u16_le();
        let protocol = r.get_u16_le();
        let name_len = r.get_u16_le() as usize;
        if r.remaining() < name_len {
            return Err(MessageError::BufferTooShort {
                needed: name_len,
                have: r.remaining(),
            });
        }
        let server_name = read_utf16le(&r[..name_len])?;
        Ok(Self {
            num_resources,
            num_alt_resources,
            port,
            protocol,
            server_name,
        })
    }

    pub fn write(&self, buf: &mut BytesMut) {
        let name_bytes = encode_utf16le(&self.server_name);
        let payload_size = 8 + name_bytes.len();
        let len = (HEADER_SIZE + payload_size) as u32;
        MessageHeader {
            msg_type: MessageType::ChannelCreate as u16,
            reserved: 0,
            length: len,
        }
        .write(buf);
        buf.put_u8(self.num_resources);
        buf.put_u8(self.num_alt_resources);
        buf.put_u16_le(self.port);
        buf.put_u16_le(self.protocol);
        buf.put_u16_le(name_bytes.len() as u16);
        buf.put_slice(&name_bytes);
    }
}

#[derive(Debug, Clone)]
pub struct ChannelResponse {
    pub error_code: u32,
    pub flags: u16,
    pub fields_present: u16,
    pub channel_id: u32,
    /// Optional server certificate (DER or PKCS7)
    pub certificate: Option<Bytes>,
}

impl ChannelResponse {
    pub fn write(&self, buf: &mut BytesMut) {
        let cert_data = self.certificate.as_ref().map(|c| c.as_ref()).unwrap_or(&[]);
        let payload_size = 12
            + if cert_data.is_empty() {
                0
            } else {
                4 + cert_data.len()
            };
        let len = (HEADER_SIZE + payload_size) as u32;
        MessageHeader {
            msg_type: MessageType::ChannelResponse as u16,
            reserved: 0,
            length: len,
        }
        .write(buf);
        buf.put_u32_le(self.error_code);
        buf.put_u16_le(self.flags);
        buf.put_u16_le(self.fields_present);
        buf.put_u32_le(self.channel_id);
        if !cert_data.is_empty() {
            buf.put_u32_le(cert_data.len() as u32);
            buf.put_slice(cert_data);
        }
    }

    pub fn parse(payload: &[u8]) -> Result<Self, MessageError> {
        if payload.len() < 12 {
            return Err(MessageError::BufferTooShort {
                needed: 12,
                have: payload.len(),
            });
        }

        let mut r = payload;
        let error_code = r.get_u32_le();
        let flags = r.get_u16_le();
        let fields_present = r.get_u16_le();
        let channel_id = r.get_u32_le();
        let certificate = if r.remaining() >= 4 {
            let cert_len = r.get_u32_le() as usize;
            if r.remaining() < cert_len {
                return Err(MessageError::BufferTooShort {
                    needed: cert_len,
                    have: r.remaining(),
                });
            }
            Some(Bytes::copy_from_slice(&r[..cert_len]))
        } else {
            None
        };

        Ok(Self {
            error_code,
            flags,
            fields_present,
            channel_id,
            certificate,
        })
    }
}

// --- Data ---

#[derive(Debug, Clone)]
pub struct DataMessage {
    pub data: Bytes,
}

impl DataMessage {
    pub fn parse(payload: &[u8]) -> Self {
        Self {
            data: Bytes::copy_from_slice(payload),
        }
    }

    pub fn write(data: &[u8], buf: &mut BytesMut) {
        let len = (HEADER_SIZE + data.len()) as u32;
        MessageHeader {
            msg_type: MessageType::Data as u16,
            reserved: 0,
            length: len,
        }
        .write(buf);
        buf.put_slice(data);
    }
}

// --- Parsed message enum ---

#[derive(Debug, Clone)]
pub enum TsgMessage {
    HandshakeRequest(HandshakeRequest),
    HandshakeResponse(HandshakeResponse),
    TunnelCreate(TunnelCreate),
    TunnelResponse(TunnelResponse),
    TunnelAuth(TunnelAuth),
    TunnelAuthResponse(TunnelAuthResponse),
    ChannelCreate(ChannelCreate),
    ChannelResponse(ChannelResponse),
    Data(DataMessage),
    Unknown { msg_type: u16, payload: Bytes },
}

/// Parse a complete message from a buffer (header + payload)
pub fn parse_message(buf: &[u8]) -> Result<TsgMessage, MessageError> {
    let header = MessageHeader::parse(buf)?;
    let total_len = header.length as usize;
    if total_len < HEADER_SIZE {
        return Err(MessageError::InvalidLength(header.length));
    }
    if buf.len() < total_len {
        return Err(MessageError::BufferTooShort {
            needed: total_len,
            have: buf.len(),
        });
    }
    let payload = &buf[HEADER_SIZE..total_len];

    match MessageType::from_u16(header.msg_type) {
        Some(MessageType::HandshakeRequest) => Ok(TsgMessage::HandshakeRequest(
            HandshakeRequest::parse(payload)?,
        )),
        Some(MessageType::HandshakeResponse) => Ok(TsgMessage::HandshakeResponse(
            HandshakeResponse::parse(payload)?,
        )),
        Some(MessageType::TunnelCreate) => {
            Ok(TsgMessage::TunnelCreate(TunnelCreate::parse(payload)?))
        }
        Some(MessageType::TunnelResponse) => {
            Ok(TsgMessage::TunnelResponse(TunnelResponse::parse(payload)?))
        }
        Some(MessageType::TunnelAuth) => Ok(TsgMessage::TunnelAuth(TunnelAuth::parse(payload)?)),
        Some(MessageType::TunnelAuthResponse) => Ok(TsgMessage::TunnelAuthResponse(
            TunnelAuthResponse::parse(payload)?,
        )),
        Some(MessageType::ChannelCreate) => {
            Ok(TsgMessage::ChannelCreate(ChannelCreate::parse(payload)?))
        }
        Some(MessageType::ChannelResponse) => Ok(TsgMessage::ChannelResponse(
            ChannelResponse::parse(payload)?,
        )),
        Some(MessageType::Data) => Ok(TsgMessage::Data(DataMessage::parse(payload))),
        _ => Ok(TsgMessage::Unknown {
            msg_type: header.msg_type,
            payload: Bytes::copy_from_slice(payload),
        }),
    }
}

// --- Utility functions ---

fn read_utf16le(data: &[u8]) -> Result<String, MessageError> {
    if data.len() % 2 != 0 {
        return Err(MessageError::InvalidUtf16);
    }
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    // Strip trailing null
    let len = u16s.iter().position(|&c| c == 0).unwrap_or(u16s.len());
    String::from_utf16(&u16s[..len]).map_err(|_| MessageError::InvalidUtf16)
}

fn encode_utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for c in s.encode_utf16() {
        out.extend_from_slice(&c.to_le_bytes());
    }
    // Null terminator
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_handshake_request() {
        let req = HandshakeRequest {
            major_version: 1,
            minor_version: 0,
            client_version: 0x0100,
            ext_auth: 0x0007,
        };
        let mut buf = BytesMut::new();
        req.write(&mut buf);
        let parsed = parse_message(&buf).unwrap();
        match parsed {
            TsgMessage::HandshakeRequest(h) => {
                assert_eq!(h.major_version, 1);
                assert_eq!(h.minor_version, 0);
                assert_eq!(h.client_version, 0x0100);
                assert_eq!(h.ext_auth, 0x0007);
            }
            _ => panic!("Expected HandshakeRequest"),
        }
    }

    #[test]
    fn roundtrip_handshake_response() {
        let resp = HandshakeResponse {
            error_code: 0,
            major_version: 1,
            minor_version: 0,
            server_version: 0,
            ext_auth: 0x0007,
        };
        let mut buf = BytesMut::new();
        resp.write(&mut buf);
        let parsed = parse_message(&buf).unwrap();
        match parsed {
            TsgMessage::HandshakeResponse(h) => {
                assert_eq!(h.error_code, 0);
                assert_eq!(h.major_version, 1);
                assert_eq!(h.ext_auth, 0x0007);
            }
            _ => panic!("Expected HandshakeResponse"),
        }
    }

    #[test]
    fn roundtrip_tunnel_create() {
        let tc = TunnelCreate {
            caps_flags: 0x0001_0001,
            fields_present: 0,
            reserved: 0,
            paa_cookie: None,
        };
        let mut buf = BytesMut::new();
        tc.write(&mut buf);
        let parsed = parse_message(&buf).unwrap();
        match parsed {
            TsgMessage::TunnelCreate(t) => {
                assert_eq!(t.caps_flags, 0x0001_0001);
                assert_eq!(t.fields_present, 0);
            }
            _ => panic!("Expected TunnelCreate"),
        }
    }

    #[test]
    fn roundtrip_tunnel_response() {
        let tr = TunnelResponse {
            server_version: 0,
            status_code: 0,
            tunnel_id: 42,
            caps: 0x09,
            max_len: 0x0d,
        };
        let mut buf = BytesMut::new();
        tr.write(&mut buf);
        let parsed = parse_message(&buf).unwrap();
        match parsed {
            TsgMessage::TunnelResponse(t) => {
                assert_eq!(t.tunnel_id, 42);
                assert_eq!(t.caps, 0x09);
                assert_eq!(t.max_len, 0x0d);
            }
            _ => panic!("Expected TunnelResponse"),
        }
    }

    #[test]
    fn roundtrip_tunnel_auth() {
        let ta = TunnelAuth {
            fields_present: 0,
            client_name: "WORKSTATION".to_string(),
        };
        let mut buf = BytesMut::new();
        ta.write(&mut buf);
        let parsed = parse_message(&buf).unwrap();
        match parsed {
            TsgMessage::TunnelAuth(t) => {
                assert_eq!(t.client_name, "WORKSTATION");
            }
            _ => panic!("Expected TunnelAuth"),
        }
    }

    #[test]
    fn roundtrip_tunnel_auth_response() {
        let tar = TunnelAuthResponse {
            error_code: 0,
            flags: 0x0003,
            reserved: 0,
            idle_timeout: 300,
            soh_response: None,
        };
        let mut buf = BytesMut::new();
        tar.write(&mut buf);
        let parsed = parse_message(&buf).unwrap();
        match parsed {
            TsgMessage::TunnelAuthResponse(t) => {
                assert_eq!(t.error_code, 0);
                assert_eq!(t.flags, 0x0003);
                assert_eq!(t.idle_timeout, 300);
            }
            _ => panic!("Expected TunnelAuthResponse"),
        }
    }

    #[test]
    fn roundtrip_channel_create() {
        let cc = ChannelCreate {
            num_resources: 1,
            num_alt_resources: 0,
            port: 3389,
            protocol: 0,
            server_name: "rdp-host.example.com".to_string(),
        };
        let mut buf = BytesMut::new();
        cc.write(&mut buf);
        let parsed = parse_message(&buf).unwrap();
        match parsed {
            TsgMessage::ChannelCreate(c) => {
                assert_eq!(c.port, 3389);
                assert_eq!(c.server_name, "rdp-host.example.com");
                assert_eq!(c.num_resources, 1);
            }
            _ => panic!("Expected ChannelCreate"),
        }
    }

    #[test]
    fn roundtrip_data_message() {
        let payload = b"hello RDP world";
        let mut buf = BytesMut::new();
        DataMessage::write(payload, &mut buf);
        let parsed = parse_message(&buf).unwrap();
        match parsed {
            TsgMessage::Data(d) => {
                assert_eq!(&d.data[..], payload);
            }
            _ => panic!("Expected Data"),
        }
    }

    #[test]
    fn parse_from_capture_handshake_request() {
        // Real capture: type=0x0001, reserved=0, length=14, payload: 01 00 00 00 00 00
        let data = hex::decode("010000000e000000010000000000").unwrap();
        let msg = parse_message(&data).unwrap();
        match msg {
            TsgMessage::HandshakeRequest(h) => {
                assert_eq!(h.major_version, 1);
                assert_eq!(h.minor_version, 0);
                assert_eq!(h.client_version, 0);
                assert_eq!(h.ext_auth, 0);
            }
            _ => panic!("Expected HandshakeRequest"),
        }
    }

    #[test]
    fn error_buffer_too_short() {
        let data = vec![0x01, 0x00, 0x00]; // Only 3 bytes, need 8
        let err = parse_message(&data).unwrap_err();
        assert!(matches!(
            err,
            MessageError::BufferTooShort { needed: 8, have: 3 }
        ));
    }

    #[test]
    fn error_payload_truncated() {
        // Header says length=100 but we only have 8 bytes
        let mut buf = BytesMut::new();
        buf.put_u16_le(0x0001); // type
        buf.put_u16_le(0); // reserved
        buf.put_u32_le(100); // length (claims 100 bytes total)
        let err = parse_message(&buf).unwrap_err();
        assert!(matches!(err, MessageError::BufferTooShort { .. }));
    }

    #[test]
    fn unknown_message_type() {
        let mut buf = BytesMut::new();
        buf.put_u16_le(0x00FF); // unknown type
        buf.put_u16_le(0);
        buf.put_u32_le(12); // 8 header + 4 payload
        buf.put_u32_le(0xDEADBEEF);
        let msg = parse_message(&buf).unwrap();
        match msg {
            TsgMessage::Unknown { msg_type, payload } => {
                assert_eq!(msg_type, 0x00FF);
                assert_eq!(payload.len(), 4);
            }
            _ => panic!("Expected Unknown"),
        }
    }

    #[test]
    fn utf16le_roundtrip_with_unicode() {
        let ta = TunnelAuth {
            fields_present: 0,
            client_name: "Ünïcödé-PC".to_string(),
        };
        let mut buf = BytesMut::new();
        ta.write(&mut buf);
        let parsed = parse_message(&buf).unwrap();
        match parsed {
            TsgMessage::TunnelAuth(t) => {
                assert_eq!(t.client_name, "Ünïcödé-PC");
            }
            _ => panic!("Expected TunnelAuth"),
        }
    }

    #[test]
    fn message_type_from_u16_all_known() {
        assert_eq!(
            MessageType::from_u16(0x0001),
            Some(MessageType::HandshakeRequest)
        );
        assert_eq!(
            MessageType::from_u16(0x0002),
            Some(MessageType::HandshakeResponse)
        );
        assert_eq!(
            MessageType::from_u16(0x0004),
            Some(MessageType::TunnelCreate)
        );
        assert_eq!(
            MessageType::from_u16(0x0005),
            Some(MessageType::TunnelResponse)
        );
        assert_eq!(MessageType::from_u16(0x0006), Some(MessageType::TunnelAuth));
        assert_eq!(
            MessageType::from_u16(0x0007),
            Some(MessageType::TunnelAuthResponse)
        );
        assert_eq!(
            MessageType::from_u16(0x0008),
            Some(MessageType::ChannelCreate)
        );
        assert_eq!(
            MessageType::from_u16(0x0009),
            Some(MessageType::ChannelResponse)
        );
        assert_eq!(MessageType::from_u16(0x000A), Some(MessageType::Data));
        assert_eq!(
            MessageType::from_u16(0x000B),
            Some(MessageType::ServiceMessage)
        );
        assert_eq!(
            MessageType::from_u16(0x000C),
            Some(MessageType::ReasuthMessage)
        );
        assert_eq!(MessageType::from_u16(0x0003), None);
        assert_eq!(MessageType::from_u16(0xFFFF), None);
    }

    #[test]
    fn header_write_and_parse() {
        let hdr = MessageHeader {
            msg_type: 0x0004,
            reserved: 0x1234,
            length: 0xDEAD,
        };
        let mut buf = BytesMut::new();
        hdr.write(&mut buf);
        let parsed = MessageHeader::parse(&buf).unwrap();
        assert_eq!(parsed.msg_type, 0x0004);
        assert_eq!(parsed.reserved, 0x1234);
        assert_eq!(parsed.length, 0xDEAD);
    }
}
