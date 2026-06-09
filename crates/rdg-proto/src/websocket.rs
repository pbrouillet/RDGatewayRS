//! WebSocket transport layer for TSG messages.
//!
//! Handles framing TSG messages within WebSocket binary frames.
//! The WebSocket layer is transparent — each WS binary message
//! contains exactly one TSG message (header + payload).

use crate::messages::{self, MessageError, MessageHeader, TsgMessage, HEADER_SIZE};
use bytes::{Bytes, BytesMut};

/// Extract a TSG message from a WebSocket binary frame payload.
pub fn decode_ws_message(ws_payload: &[u8]) -> Result<TsgMessage, MessageError> {
    messages::parse_message(ws_payload)
}

/// Peek at the message type without full parsing.
pub fn peek_message_type(ws_payload: &[u8]) -> Result<u16, MessageError> {
    let header = MessageHeader::parse(ws_payload)?;
    Ok(header.msg_type)
}

/// Get the expected total message length from header.
pub fn message_length(ws_payload: &[u8]) -> Result<usize, MessageError> {
    let header = MessageHeader::parse(ws_payload)?;
    Ok(header.length as usize)
}

/// Encode a raw payload into a TSG Data message suitable for WebSocket send.
/// Adds the 2-byte cbDataLength prefix before the payload as per MS-RDPEGW.
pub fn encode_data_message(data: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER_SIZE + 2 + data.len());
    // Build the full payload: [cbDataLength: u16_le][data]
    let payload_with_len = {
        let mut p = BytesMut::with_capacity(2 + data.len());
        p.extend_from_slice(&(data.len() as u16).to_le_bytes());
        p.extend_from_slice(data);
        p
    };
    messages::DataMessage::write(&payload_with_len, &mut buf);
    buf.freeze()
}

/// Check if a buffer contains a complete TSG message.
pub fn is_complete_message(buf: &[u8]) -> bool {
    if buf.len() < HEADER_SIZE {
        return false;
    }
    match MessageHeader::parse(buf) {
        Ok(header) => buf.len() >= header.length as usize,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_decode_data_message() {
        let payload = b"raw RDP data here";
        let encoded = encode_data_message(payload);
        let decoded = decode_ws_message(&encoded).unwrap();
        match decoded {
            TsgMessage::Data(d) => {
                // Data includes 2-byte cbDataLength prefix + payload
                assert_eq!(d.data.len(), 2 + payload.len());
                let cb_len = u16::from_le_bytes([d.data[0], d.data[1]]) as usize;
                assert_eq!(cb_len, payload.len());
                assert_eq!(&d.data[2..], payload.as_slice());
            }
            _ => panic!("Expected Data message"),
        }
    }

    #[test]
    fn peek_message_type_works() {
        let encoded = encode_data_message(b"test");
        let msg_type = peek_message_type(&encoded).unwrap();
        assert_eq!(msg_type, 0x000A); // Data
    }

    #[test]
    fn message_length_correct() {
        let data = b"12345";
        let encoded = encode_data_message(data);
        let len = message_length(&encoded).unwrap();
        assert_eq!(len, HEADER_SIZE + 2 + data.len()); // header + cbDataLength + data
        assert_eq!(len, encoded.len());
    }

    #[test]
    fn is_complete_message_true_for_full_message() {
        let encoded = encode_data_message(b"complete");
        assert!(is_complete_message(&encoded));
    }

    #[test]
    fn is_complete_message_false_for_truncated() {
        let encoded = encode_data_message(b"complete");
        assert!(!is_complete_message(&encoded[..6])); // only 6 of 8+ bytes
    }

    #[test]
    fn is_complete_message_false_for_empty() {
        assert!(!is_complete_message(&[]));
    }

    #[test]
    fn encode_empty_data() {
        let encoded = encode_data_message(&[]);
        // header + 2-byte cbDataLength (value=0)
        assert_eq!(encoded.len(), HEADER_SIZE + 2);
        let decoded = decode_ws_message(&encoded).unwrap();
        match decoded {
            TsgMessage::Data(d) => {
                // 2 bytes for cbDataLength=0, no actual data
                assert_eq!(d.data.len(), 2);
                assert_eq!(&d.data[..], &[0u8, 0u8]);
            }
            _ => panic!("Expected Data message"),
        }
    }

    #[test]
    fn peek_type_error_on_short_buffer() {
        let result = peek_message_type(&[0x01, 0x02]);
        assert!(result.is_err());
    }
}
