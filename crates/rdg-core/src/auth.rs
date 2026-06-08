//! Authentication provider.

use crate::db::DbProvider;
use rdg_proto::ntlm::{self, NtlmChallenge, NtlmError, NtlmNegotiate};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("NTLM error: {0}")]
    Ntlm(#[from] NtlmError),
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("user disabled: {0}")]
    UserDisabled(String),
    #[error("database error: {0}")]
    Database(String),
}

/// Manages NTLM authentication state for a single connection.
pub struct NtlmAuthContext {
    pub server_challenge: [u8; 8],
    pub challenge_msg: NtlmChallenge,
    pub negotiate: Option<NtlmNegotiate>,
    pub authenticated_user: Option<String>,
}

impl NtlmAuthContext {
    pub fn new(server_name: &str) -> Self {
        let server_challenge = ntlm::generate_server_challenge();
        let challenge_msg = ntlm::generate_challenge(server_name, &server_challenge);
        Self {
            server_challenge,
            challenge_msg,
            negotiate: None,
            authenticated_user: None,
        }
    }

    /// Process Type1 (Negotiate) and return serialized Type2 (Challenge)
    pub fn process_negotiate(&mut self, type1_bytes: &[u8]) -> Result<Vec<u8>, AuthError> {
        let negotiate = ntlm::parse_negotiate(type1_bytes)?;
        self.negotiate = Some(negotiate);
        Ok(ntlm::serialize_challenge(&self.challenge_msg))
    }

    /// Process Type3 (Authenticate) and validate against DB
    pub async fn process_authenticate(
        &mut self,
        type3_bytes: &[u8],
        db: &Arc<dyn DbProvider>,
    ) -> Result<String, AuthError> {
        let auth = ntlm::parse_authenticate(type3_bytes)?;
        let username = auth.username.clone();

        // Look up user in database
        let user = db
            .get_user_by_username(&username)
            .await
            .map_err(|e| AuthError::Database(e.to_string()))?
            .ok_or_else(|| AuthError::UserNotFound(username.clone()))?;

        if !user.enabled {
            return Err(AuthError::UserDisabled(username));
        }

        // Validate NTLMv2 response
        let nt_hash: [u8; 16] = user
            .nt_hash
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::Database("invalid NT hash in database".to_string()))?;

        ntlm::validate_ntlmv2(&nt_hash, &self.server_challenge, &auth)?;

        self.authenticated_user = Some(username.clone());
        Ok(username)
    }

    /// Get the serialized challenge message (for WWW-Authenticate header)
    pub fn challenge_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .encode(ntlm::serialize_challenge(&self.challenge_msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_context_generates_valid_challenge() {
        let ctx = NtlmAuthContext::new("TESTSERVER");
        assert_eq!(ctx.challenge_msg.target_name, "TESTSERVER");
        assert_ne!(ctx.server_challenge, [0u8; 8]);
    }

    #[test]
    fn process_negotiate_returns_valid_type2() {
        let mut ctx = NtlmAuthContext::new("SRV");

        // Build minimal Type1
        let mut type1 = Vec::new();
        type1.extend_from_slice(b"NTLMSSP\0");
        type1.extend_from_slice(&1u32.to_le_bytes());
        type1.extend_from_slice(&0xB7820862u32.to_le_bytes());
        type1.extend_from_slice(&[0u8; 16]); // empty domain + workstation

        let type2_bytes = ctx.process_negotiate(&type1).unwrap();

        // Verify it's a valid Type2
        assert_eq!(&type2_bytes[0..8], b"NTLMSSP\0");
        assert_eq!(
            u32::from_le_bytes(type2_bytes[8..12].try_into().unwrap()),
            2
        );
        assert!(ctx.negotiate.is_some());
    }

    #[test]
    fn challenge_base64_is_valid() {
        let ctx = NtlmAuthContext::new("HOST");
        let b64 = ctx.challenge_base64();
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap();
        assert_eq!(&decoded[0..8], b"NTLMSSP\0");
    }

    #[test]
    fn two_contexts_have_different_challenges() {
        let ctx1 = NtlmAuthContext::new("A");
        let ctx2 = NtlmAuthContext::new("A");
        assert_ne!(ctx1.server_challenge, ctx2.server_challenge);
    }
}
