//! Negotiate (SPNEGO) authentication provider.
//!
//! Detects whether an incoming `Authorization: Negotiate` token is
//! Kerberos (SPNEGO-wrapped AP-REQ) or NTLM, and routes accordingly.
//!
//! - Kerberos: delegated to `cross-krb5` (SSPI on Windows, GSSAPI on Linux/macOS)
//! - NTLM: handled by our existing `NtlmAuthContext`

use base64::Engine;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::auth::NtlmAuthContext;
use crate::db::DbProvider;
use std::sync::Arc;

/// NTLMSSP signature at the start of raw NTLM tokens
const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";

/// SPNEGO OID 1.3.6.1.5.5.2 (DER-encoded) — Kerberos tokens are wrapped in this
const SPNEGO_OID_PREFIX: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

#[derive(Debug, Error)]
pub enum NegotiateError {
    #[error("invalid base64 token")]
    InvalidBase64,
    #[error("NTLM error: {0}")]
    Ntlm(#[from] crate::auth::AuthError),
    #[error("Kerberos error: {0}")]
    Kerberos(String),
    #[error("Kerberos support not compiled (feature 'kerberos' disabled)")]
    KerberosNotAvailable,
    #[error("unsupported token type")]
    UnsupportedToken,
    #[error("authentication incomplete — more steps needed")]
    Incomplete,
}

/// The type of token detected in a Negotiate header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Ntlm,
    Kerberos,
    Unknown,
}

/// Detect whether a raw (decoded) Negotiate token is NTLM or Kerberos.
pub fn detect_token_type(token: &[u8]) -> TokenType {
    if token.len() >= 8 && &token[0..8] == NTLMSSP_SIGNATURE {
        return TokenType::Ntlm;
    }
    // SPNEGO tokens start with ASN.1 APPLICATION [0] (0x60) containing the SPNEGO OID
    if token.first() == Some(&0x60) && token.len() > 10 {
        // Look for SPNEGO OID within first ~12 bytes
        if token.windows(SPNEGO_OID_PREFIX.len()).any(|w| w == SPNEGO_OID_PREFIX) {
            return TokenType::Kerberos;
        }
    }
    // Could also be a raw Kerberos AP-REQ (application tag [14] = 0x6E)
    if token.first() == Some(&0x6E) || token.first() == Some(&0x60) {
        return TokenType::Kerberos;
    }
    TokenType::Unknown
}

/// Result of a negotiate authentication step
#[derive(Debug)]
pub enum NegotiateResult {
    /// Authentication succeeded. Contains the authenticated principal name.
    Success(String),
    /// Server needs to send a challenge back (contains base64 response token).
    Challenge(String),
}

/// Unified authentication context that handles both NTLM and Kerberos
/// via the HTTP `Negotiate` mechanism.
pub struct NegotiateAuthContext {
    server_name: String,
    ntlm_ctx: Option<NtlmAuthContext>,
    #[cfg(feature = "kerberos")]
    krb_spn: Option<String>,
}

impl NegotiateAuthContext {
    /// Create a new context.
    /// - `server_name`: used as NTLM target name and to construct the Kerberos SPN
    /// - `spn`: optional explicit SPN for Kerberos (e.g. "HTTP/gateway.domain.com")
    ///          If None, defaults to "HTTP/{server_name}"
    pub fn new(server_name: &str, spn: Option<&str>) -> Self {
        Self {
            server_name: server_name.to_string(),
            ntlm_ctx: None,
            #[cfg(feature = "kerberos")]
            krb_spn: Some(spn.unwrap_or(&format!("HTTP/{}", server_name)).to_string()),
        }
    }

    /// Process an incoming `Authorization: Negotiate <base64>` token.
    /// Returns either a challenge (send as `WWW-Authenticate: Negotiate <token>`)
    /// or a successful authentication with the principal name.
    pub async fn process_token(
        &mut self,
        base64_token: &str,
        db: &Arc<dyn DbProvider>,
    ) -> Result<NegotiateResult, NegotiateError> {
        let token_bytes = base64::engine::general_purpose::STANDARD
            .decode(base64_token)
            .map_err(|_| NegotiateError::InvalidBase64)?;

        match detect_token_type(&token_bytes) {
            TokenType::Ntlm => self.process_ntlm(&token_bytes, db).await,
            TokenType::Kerberos => self.process_kerberos(&token_bytes).await,
            TokenType::Unknown => {
                warn!("Unknown Negotiate token type (first byte: 0x{:02x})", token_bytes.first().unwrap_or(&0));
                Err(NegotiateError::UnsupportedToken)
            }
        }
    }

    async fn process_ntlm(
        &mut self,
        token: &[u8],
        db: &Arc<dyn DbProvider>,
    ) -> Result<NegotiateResult, NegotiateError> {
        // NTLM Type1 (Negotiate) → return challenge
        if token.len() >= 12 {
            let msg_type = u32::from_le_bytes(token[8..12].try_into().unwrap_or([0; 4]));
            if msg_type == 1 {
                debug!("NTLM Type1 received, generating challenge");
                let ctx = NtlmAuthContext::new(&self.server_name);
                let challenge_b64 = ctx.challenge_base64();
                self.ntlm_ctx = Some(ctx);
                return Ok(NegotiateResult::Challenge(challenge_b64));
            }
            if msg_type == 3 {
                debug!("NTLM Type3 received, validating");
                let ctx = self.ntlm_ctx.as_mut().ok_or_else(|| {
                    NegotiateError::Ntlm(crate::auth::AuthError::Ntlm(
                        rdg_proto::ntlm::NtlmError::BufferTooShort,
                    ))
                })?;
                let username = ctx.process_authenticate(token, db).await?;
                info!("NTLM authentication succeeded for: {}", username);
                return Ok(NegotiateResult::Success(username));
            }
        }
        Err(NegotiateError::UnsupportedToken)
    }

    #[cfg(feature = "kerberos")]
    async fn process_kerberos(
        &mut self,
        token: &[u8],
    ) -> Result<NegotiateResult, NegotiateError> {
        use cross_krb5::{AcceptFlags, K5ServerCtx, ServerCtx, Step};

        let spn = self.krb_spn.as_deref();
        debug!("Kerberos token received, processing with SPN: {:?}", spn);

        // Create a server context and process the token in one step
        // For HTTP Negotiate, this is typically a single-step exchange
        let server = ServerCtx::new(AcceptFlags::empty(), spn, None)
            .map_err(|e| NegotiateError::Kerberos(format!("failed to create server context: {}", e)))?;

        match server.step(token) {
            Ok(Step::Finished((mut ctx, response_token))) => {
                let principal = ctx.client().map(|c| c.to_string()).unwrap_or_default();
                info!("Kerberos authentication succeeded for: {}", principal);

                if let Some(_resp) = response_token {
                    debug!("Kerberos mutual auth token generated");
                    // For simplicity, treat as success — the response token is optional in HTTP Negotiate
                    Ok(NegotiateResult::Success(principal))
                } else {
                    Ok(NegotiateResult::Success(principal))
                }
            }
            Ok(Step::Continue((_ctx, token))) => {
                // Multi-leg exchange (rare in HTTP Negotiate)
                let challenge = base64::engine::general_purpose::STANDARD.encode(&*token);
                Ok(NegotiateResult::Challenge(challenge))
            }
            Err(e) => {
                warn!("Kerberos authentication failed: {}", e);
                Err(NegotiateError::Kerberos(format!("authentication failed: {}", e)))
            }
        }
    }

    #[cfg(not(feature = "kerberos"))]
    async fn process_kerberos(
        &mut self,
        _token: &[u8],
    ) -> Result<NegotiateResult, NegotiateError> {
        warn!("Kerberos token received but feature 'kerberos' is disabled");
        Err(NegotiateError::KerberosNotAvailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_ntlm_token() {
        let mut token = Vec::new();
        token.extend_from_slice(b"NTLMSSP\0");
        token.extend_from_slice(&1u32.to_le_bytes());
        token.extend_from_slice(&[0u8; 20]);
        assert_eq!(detect_token_type(&token), TokenType::Ntlm);
    }

    #[test]
    fn detect_spnego_kerberos_token() {
        // Minimal SPNEGO initToken: 0x60 (APPLICATION [0]) + length + SPNEGO OID
        let mut token = vec![0x60, 0x40]; // tag + length
        token.extend_from_slice(SPNEGO_OID_PREFIX);
        token.extend_from_slice(&[0u8; 50]);
        assert_eq!(detect_token_type(&token), TokenType::Kerberos);
    }

    #[test]
    fn detect_raw_kerberos_ap_req() {
        // Raw AP-REQ starts with 0x6E (APPLICATION [14])
        let token = vec![0x6E, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_token_type(&token), TokenType::Kerberos);
    }

    #[test]
    fn detect_unknown_token() {
        let token = vec![0xFF, 0x00, 0x01, 0x02];
        assert_eq!(detect_token_type(&token), TokenType::Unknown);
    }

    #[test]
    fn detect_empty_is_unknown() {
        assert_eq!(detect_token_type(&[]), TokenType::Unknown);
    }

    #[test]
    fn negotiate_context_creation() {
        let ctx = NegotiateAuthContext::new("GATEWAY", Some("HTTP/gateway.corp.com"));
        assert_eq!(ctx.server_name, "GATEWAY");
        #[cfg(feature = "kerberos")]
        assert_eq!(ctx.krb_spn.as_deref(), Some("HTTP/gateway.corp.com"));
    }

    #[test]
    fn negotiate_context_default_spn() {
        let ctx = NegotiateAuthContext::new("myhost", None);
        #[cfg(feature = "kerberos")]
        assert_eq!(ctx.krb_spn.as_deref(), Some("HTTP/myhost"));
    }
}
