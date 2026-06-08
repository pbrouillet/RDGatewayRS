//! NTLM authentication message parsing and generation.
//!
//! Implements enough of NTLM to:
//! - Parse Type1 (Negotiate) messages from clients
//! - Generate Type2 (Challenge) messages
//! - Parse and validate Type3 (Authenticate) messages

use bytes::{BufMut, BytesMut};
use digest::Digest;
use hmac::{Hmac, Mac};
use rand::RngCore;
use thiserror::Error;

type HmacMd5 = Hmac<md5::Md5>;

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

// Negotiate flags
pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x00000001;
pub const NTLMSSP_NEGOTIATE_OEM: u32 = 0x00000002;
pub const NTLMSSP_REQUEST_TARGET: u32 = 0x00000004;
pub const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x00000010;
pub const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x00000020;
pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x00000200;
pub const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x00008000;
pub const NTLMSSP_TARGET_TYPE_SERVER: u32 = 0x00020000;
pub const NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY: u32 = 0x00080000;
pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x00800000;
pub const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x02000000;
pub const NTLMSSP_NEGOTIATE_128: u32 = 0x20000000;
pub const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x40000000;
pub const NTLMSSP_NEGOTIATE_56: u32 = 0x80000000;

// AV_PAIR IDs
pub const MSV_AV_EOL: u16 = 0x0000;
pub const MSV_AV_NB_COMPUTER_NAME: u16 = 0x0001;
pub const MSV_AV_NB_DOMAIN_NAME: u16 = 0x0002;
pub const MSV_AV_DNS_COMPUTER_NAME: u16 = 0x0003;
pub const MSV_AV_DNS_DOMAIN_NAME: u16 = 0x0004;
pub const MSV_AV_TIMESTAMP: u16 = 0x0007;

#[derive(Debug, Error)]
pub enum NtlmError {
    #[error("invalid NTLMSSP signature")]
    InvalidSignature,
    #[error("unexpected message type: {0}")]
    UnexpectedType(u32),
    #[error("buffer too short")]
    BufferTooShort,
    #[error("HMAC key error")]
    HmacError,
    #[error("authentication failed")]
    AuthFailed,
}

/// Parsed NTLM Type1 (Negotiate) message
#[derive(Debug, Clone)]
pub struct NtlmNegotiate {
    pub flags: u32,
    pub domain: String,
    pub workstation: String,
}

/// NTLM Type2 (Challenge) generation context
#[derive(Debug, Clone)]
pub struct NtlmChallenge {
    pub target_name: String,
    pub server_challenge: [u8; 8],
    pub flags: u32,
    pub target_info: Vec<u8>,
}

/// Parsed NTLM Type3 (Authenticate) message
#[derive(Debug, Clone)]
pub struct NtlmAuthenticate {
    pub flags: u32,
    pub domain: String,
    pub username: String,
    pub workstation: String,
    pub lm_response: Vec<u8>,
    pub nt_response: Vec<u8>,
    pub encrypted_random_session_key: Vec<u8>,
}

/// Parse NTLM Type1 message from raw bytes
pub fn parse_negotiate(data: &[u8]) -> Result<NtlmNegotiate, NtlmError> {
    if data.len() < 32 {
        return Err(NtlmError::BufferTooShort);
    }
    if &data[0..8] != NTLMSSP_SIGNATURE {
        return Err(NtlmError::InvalidSignature);
    }
    let msg_type = u32::from_le_bytes(data[8..12].try_into().unwrap());
    if msg_type != 1 {
        return Err(NtlmError::UnexpectedType(msg_type));
    }
    let flags = u32::from_le_bytes(data[12..16].try_into().unwrap());

    // Domain and workstation security buffers (optional)
    let domain = read_security_buffer(data, 16).unwrap_or_default();
    let workstation = read_security_buffer(data, 24).unwrap_or_default();

    Ok(NtlmNegotiate {
        flags,
        domain,
        workstation,
    })
}

/// Generate NTLM Type2 (Challenge) message
pub fn generate_challenge(target_name: &str, server_challenge: &[u8; 8]) -> NtlmChallenge {
    let flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_TARGET_TYPE_SERVER
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY
        | NTLMSSP_NEGOTIATE_TARGET_INFO
        | NTLMSSP_NEGOTIATE_VERSION
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_KEY_EXCH
        | NTLMSSP_NEGOTIATE_56
        | NTLMSSP_NEGOTIATE_SEAL
        | NTLMSSP_NEGOTIATE_SIGN;

    let target_info = build_target_info(target_name);

    NtlmChallenge {
        target_name: target_name.to_string(),
        server_challenge: *server_challenge,
        flags,
        target_info,
    }
}

/// Serialize NTLM Type2 Challenge to wire format
pub fn serialize_challenge(challenge: &NtlmChallenge) -> Vec<u8> {
    let target_name_bytes = encode_utf16le(&challenge.target_name);
    let target_info = &challenge.target_info;

    // Layout: signature(8) + type(4) + target_name_sec_buf(8) + flags(4) + challenge(8) + reserved(8) + target_info_sec_buf(8) + version(8) + payload
    let header_size = 56; // fixed header
    let target_name_offset = header_size;
    let target_info_offset = target_name_offset + target_name_bytes.len();

    let mut buf = BytesMut::with_capacity(target_info_offset + target_info.len());

    // Signature + Type
    buf.put_slice(NTLMSSP_SIGNATURE);
    buf.put_u32_le(2); // Type 2

    // Target Name security buffer
    buf.put_u16_le(target_name_bytes.len() as u16); // len
    buf.put_u16_le(target_name_bytes.len() as u16); // max len
    buf.put_u32_le(target_name_offset as u32); // offset

    // Flags
    buf.put_u32_le(challenge.flags);

    // Server Challenge
    buf.put_slice(&challenge.server_challenge);

    // Reserved (8 bytes)
    buf.put_u64_le(0);

    // Target Info security buffer
    buf.put_u16_le(target_info.len() as u16);
    buf.put_u16_le(target_info.len() as u16);
    buf.put_u32_le(target_info_offset as u32);

    // Version (8 bytes) - Windows Server 2025-ish
    buf.put_slice(&[0x0a, 0x00, 0xf4, 0x65, 0x00, 0x00, 0x00, 0x0f]);

    // Payload: target name + target info
    buf.put_slice(&target_name_bytes);
    buf.put_slice(target_info);

    buf.to_vec()
}

/// Parse NTLM Type3 (Authenticate) message
pub fn parse_authenticate(data: &[u8]) -> Result<NtlmAuthenticate, NtlmError> {
    if data.len() < 64 {
        return Err(NtlmError::BufferTooShort);
    }
    if &data[0..8] != NTLMSSP_SIGNATURE {
        return Err(NtlmError::InvalidSignature);
    }
    let msg_type = u32::from_le_bytes(data[8..12].try_into().unwrap());
    if msg_type != 3 {
        return Err(NtlmError::UnexpectedType(msg_type));
    }

    let lm_response = read_security_buffer_raw(data, 12)?;
    let nt_response = read_security_buffer_raw(data, 20)?;
    let domain_buf = read_security_buffer_raw(data, 28)?;
    let username_buf = read_security_buffer_raw(data, 36)?;
    let workstation_buf = read_security_buffer_raw(data, 44)?;
    let encrypted_random_session_key = read_security_buffer_raw(data, 52).unwrap_or_default();

    let flags = if data.len() >= 64 {
        u32::from_le_bytes(data[60..64].try_into().unwrap())
    } else {
        0
    };

    let domain = String::from_utf16_lossy(
        &domain_buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    );
    let username = String::from_utf16_lossy(
        &username_buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    );
    let workstation = String::from_utf16_lossy(
        &workstation_buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    );

    Ok(NtlmAuthenticate {
        flags,
        domain,
        username,
        workstation,
        lm_response,
        nt_response,
        encrypted_random_session_key,
    })
}

/// Validate NTLMv2 response against stored NT hash
pub fn validate_ntlmv2(
    nt_hash: &[u8; 16],
    server_challenge: &[u8; 8],
    authenticate: &NtlmAuthenticate,
) -> Result<(), NtlmError> {
    if authenticate.nt_response.len() < 24 {
        return Err(NtlmError::AuthFailed);
    }

    // NTLMv2: ResponseKeyNT = HMAC_MD5(NT_Hash, UPPER(Username) + Domain)
    let user_upper = authenticate.username.to_uppercase();
    let identity = format!("{}{}", user_upper, authenticate.domain);
    let identity_bytes = encode_utf16le(&identity);

    let response_key = hmac_md5(nt_hash, &identity_bytes).map_err(|_| NtlmError::HmacError)?;

    // NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge + NTClientChallenge)
    let nt_proof_str = &authenticate.nt_response[..16];
    let nt_client_challenge = &authenticate.nt_response[16..];

    let mut verify_input = Vec::with_capacity(8 + nt_client_challenge.len());
    verify_input.extend_from_slice(server_challenge);
    verify_input.extend_from_slice(nt_client_challenge);

    let expected = hmac_md5(&response_key, &verify_input).map_err(|_| NtlmError::HmacError)?;

    if constant_time_eq(nt_proof_str, &expected) {
        Ok(())
    } else {
        Err(NtlmError::AuthFailed)
    }
}

/// Compute NT hash from password: MD4(UTF-16LE(password))
pub fn compute_nt_hash(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut hasher = md4::Md4::new();
    hasher.update(&utf16);
    let result = hasher.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// Generate a random 8-byte challenge
pub fn generate_server_challenge() -> [u8; 8] {
    let mut challenge = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

// --- Internal helpers ---

fn build_target_info(server_name: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    let name_utf16 = encode_utf16le(server_name);

    // MsvAvNbComputerName
    buf.put_u16_le(MSV_AV_NB_COMPUTER_NAME);
    buf.put_u16_le(name_utf16.len() as u16);
    buf.put_slice(&name_utf16);

    // MsvAvNbDomainName (same as computer for workgroup)
    buf.put_u16_le(MSV_AV_NB_DOMAIN_NAME);
    buf.put_u16_le(name_utf16.len() as u16);
    buf.put_slice(&name_utf16);

    // MsvAvDnsComputerName
    buf.put_u16_le(MSV_AV_DNS_COMPUTER_NAME);
    buf.put_u16_le(name_utf16.len() as u16);
    buf.put_slice(&name_utf16);

    // MsvAvDnsDomainName
    buf.put_u16_le(MSV_AV_DNS_DOMAIN_NAME);
    buf.put_u16_le(name_utf16.len() as u16);
    buf.put_slice(&name_utf16);

    // MsvAvTimestamp
    let timestamp = windows_filetime_now();
    buf.put_u16_le(MSV_AV_TIMESTAMP);
    buf.put_u16_le(8);
    buf.put_u64_le(timestamp);

    // MsvAvEOL
    buf.put_u16_le(MSV_AV_EOL);
    buf.put_u16_le(0);

    buf.to_vec()
}

fn windows_filetime_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Windows FILETIME: 100ns intervals since 1601-01-01
    // Offset: 11644473600 seconds between 1601 and 1970
    (unix_secs + 11644473600) * 10_000_000
}

fn encode_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn read_security_buffer(data: &[u8], offset: usize) -> Option<String> {
    let raw = read_security_buffer_raw(data, offset).ok()?;
    if raw.is_empty() {
        return Some(String::new());
    }
    if raw.len() % 2 == 0 {
        let u16s: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&u16s))
    } else {
        Some(String::from_utf8_lossy(&raw).to_string())
    }
}

fn read_security_buffer_raw(data: &[u8], offset: usize) -> Result<Vec<u8>, NtlmError> {
    if data.len() < offset + 8 {
        return Err(NtlmError::BufferTooShort);
    }
    let len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
    let buf_offset = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    if data.len() < buf_offset + len {
        return Err(NtlmError::BufferTooShort);
    }
    Ok(data[buf_offset..buf_offset + len].to_vec())
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Result<[u8; 16], ()> {
    let mut mac = HmacMd5::new_from_slice(key).map_err(|_| ())?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    Ok(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_nt_hash_known_vector() {
        // Known: NT hash of "Password" = a4f49c406510bdcab6824ee7c30fd852
        let hash = compute_nt_hash("Password");
        assert_eq!(hex::encode(hash), "a4f49c406510bdcab6824ee7c30fd852");
    }

    #[test]
    fn compute_nt_hash_empty_password() {
        // NT hash of "" = 31d6cfe0d16ae931b73c59d7e0c089c0
        let hash = compute_nt_hash("");
        assert_eq!(hex::encode(hash), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn parse_negotiate_minimal_type1() {
        // Minimal NTLM Type1: signature + type(1) + flags + empty domain/workstation buffers
        let mut buf = Vec::new();
        buf.extend_from_slice(b"NTLMSSP\0"); // signature
        buf.extend_from_slice(&1u32.to_le_bytes()); // type 1
        buf.extend_from_slice(&0xB7820862u32.to_le_bytes()); // flags
                                                             // Domain security buffer (len=0, maxlen=0, offset=0)
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        // Workstation security buffer
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

        let neg = parse_negotiate(&buf).unwrap();
        assert_eq!(neg.flags, 0xB7820862);
        assert_eq!(neg.domain, "");
        assert_eq!(neg.workstation, "");
    }

    #[test]
    fn parse_negotiate_rejects_type2() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"NTLMSSP\0");
        buf.extend_from_slice(&2u32.to_le_bytes()); // type 2, not 1
        buf.extend_from_slice(&[0u8; 20]); // padding
        let err = parse_negotiate(&buf).unwrap_err();
        assert!(matches!(err, NtlmError::UnexpectedType(2)));
    }

    #[test]
    fn parse_negotiate_rejects_bad_signature() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"BADSSSP\0");
        buf.extend_from_slice(&[0u8; 24]);
        let err = parse_negotiate(&buf).unwrap_err();
        assert!(matches!(err, NtlmError::InvalidSignature));
    }

    #[test]
    fn parse_negotiate_rejects_short_buffer() {
        let buf = vec![0u8; 10]; // too short
        let err = parse_negotiate(&buf).unwrap_err();
        assert!(matches!(err, NtlmError::BufferTooShort));
    }

    #[test]
    fn generate_and_serialize_challenge() {
        let challenge_bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let challenge = generate_challenge("TESTSERVER", &challenge_bytes);

        assert_eq!(challenge.target_name, "TESTSERVER");
        assert_eq!(challenge.server_challenge, challenge_bytes);

        let serialized = serialize_challenge(&challenge);

        // Verify signature
        assert_eq!(&serialized[0..8], b"NTLMSSP\0");
        // Verify type = 2
        assert_eq!(u32::from_le_bytes(serialized[8..12].try_into().unwrap()), 2);
        // Verify challenge is embedded
        assert_eq!(&serialized[24..32], &challenge_bytes);
        // Verify flags include UNICODE and NTLM
        let flags = u32::from_le_bytes(serialized[20..24].try_into().unwrap());
        assert!(flags & NTLMSSP_NEGOTIATE_UNICODE != 0);
        assert!(flags & NTLMSSP_NEGOTIATE_NTLM != 0);
        assert!(flags & NTLMSSP_NEGOTIATE_TARGET_INFO != 0);
    }

    #[test]
    fn serialize_challenge_target_info_contains_av_pairs() {
        let challenge_bytes = [0; 8];
        let challenge = generate_challenge("SRV", &challenge_bytes);
        let serialized = serialize_challenge(&challenge);

        // Target info should contain MsvAvNbComputerName (0x0001) somewhere
        let target_info = &challenge.target_info;
        assert!(target_info.len() > 4);
        // First AV_PAIR should be NbComputerName (0x0001)
        assert_eq!(
            u16::from_le_bytes([target_info[0], target_info[1]]),
            MSV_AV_NB_COMPUTER_NAME
        );
    }

    #[test]
    fn parse_authenticate_minimal_type3() {
        // Build a minimal Type3 message
        let mut buf = Vec::new();
        buf.extend_from_slice(b"NTLMSSP\0"); // 0: signature
        buf.extend_from_slice(&3u32.to_le_bytes()); // 8: type 3

        let payload_offset = 72u32; // after fixed header
        let domain_utf16 = encode_utf16le("DOMAIN");
        let user_utf16 = encode_utf16le("admin");
        let ws_utf16 = encode_utf16le("WS1");

        let lm_response = vec![0u8; 24];
        let nt_response = vec![0u8; 24];
        let session_key = vec![0u8; 16];

        // Calculate offsets
        let mut offset = payload_offset as usize;
        let lm_offset = offset;
        offset += lm_response.len();
        let nt_offset = offset;
        offset += nt_response.len();
        let domain_offset = offset;
        offset += domain_utf16.len();
        let user_offset = offset;
        offset += user_utf16.len();
        let ws_offset = offset;
        offset += ws_utf16.len();
        let sk_offset = offset;

        // LM security buffer (12)
        buf.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(lm_offset as u32).to_le_bytes());
        // NT security buffer (20)
        buf.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(nt_offset as u32).to_le_bytes());
        // Domain security buffer (28)
        buf.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(domain_offset as u32).to_le_bytes());
        // User security buffer (36)
        buf.extend_from_slice(&(user_utf16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(user_utf16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(user_offset as u32).to_le_bytes());
        // Workstation security buffer (44)
        buf.extend_from_slice(&(ws_utf16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(ws_utf16.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(ws_offset as u32).to_le_bytes());
        // EncryptedRandomSessionKey security buffer (52)
        buf.extend_from_slice(&(session_key.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(session_key.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(sk_offset as u32).to_le_bytes());
        // Flags (60)
        buf.extend_from_slice(&NTLMSSP_NEGOTIATE_UNICODE.to_le_bytes());

        // Pad to payload_offset
        while buf.len() < payload_offset as usize {
            buf.push(0);
        }

        // Payload
        buf.extend_from_slice(&lm_response);
        buf.extend_from_slice(&nt_response);
        buf.extend_from_slice(&domain_utf16);
        buf.extend_from_slice(&user_utf16);
        buf.extend_from_slice(&ws_utf16);
        buf.extend_from_slice(&session_key);

        let auth = parse_authenticate(&buf).unwrap();
        assert_eq!(auth.username, "admin");
        assert_eq!(auth.domain, "DOMAIN");
        assert_eq!(auth.workstation, "WS1");
        assert_eq!(auth.lm_response.len(), 24);
        assert_eq!(auth.nt_response.len(), 24);
    }

    #[test]
    fn validate_ntlmv2_wrong_hash_fails() {
        let nt_hash = compute_nt_hash("CorrectPassword");
        let server_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        // Fake authenticate with garbage nt_response
        let auth = NtlmAuthenticate {
            flags: 0,
            domain: "DOMAIN".to_string(),
            username: "user".to_string(),
            workstation: "WS".to_string(),
            lm_response: vec![0u8; 24],
            nt_response: vec![0u8; 32], // garbage
            encrypted_random_session_key: vec![],
        };

        let result = validate_ntlmv2(&nt_hash, &server_challenge, &auth);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NtlmError::AuthFailed));
    }

    #[test]
    fn validate_ntlmv2_short_response_fails() {
        let nt_hash = compute_nt_hash("pass");
        let server_challenge = [0; 8];
        let auth = NtlmAuthenticate {
            flags: 0,
            domain: "".to_string(),
            username: "u".to_string(),
            workstation: "".to_string(),
            lm_response: vec![],
            nt_response: vec![0u8; 10], // too short (< 24)
            encrypted_random_session_key: vec![],
        };
        let result = validate_ntlmv2(&nt_hash, &server_challenge, &auth);
        assert!(matches!(result.unwrap_err(), NtlmError::AuthFailed));
    }

    #[test]
    fn generate_server_challenge_is_random() {
        let c1 = generate_server_challenge();
        let c2 = generate_server_challenge();
        // Extremely unlikely to be equal
        assert_ne!(c1, c2);
    }
}
