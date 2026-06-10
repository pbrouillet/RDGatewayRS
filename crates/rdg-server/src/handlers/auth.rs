//! Authentication handlers: signup, signin, signout, session cookie management.

use crate::state::AppState;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

const SESSION_COOKIE_NAME: &str = "rdg_session";
const SESSION_TTL_SECS: u64 = 86400; // 24 hours

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/signin", post(signin))
        .route("/api/auth/signout", post(signout))
        .route("/api/auth/me", get(me))
}

// --- Public helpers for session validation ---

/// Extract and validate the session cookie, returning the user_id if valid.
pub fn validate_session_cookie(cookie_header: Option<&str>, state: &AppState) -> Option<i64> {
    let cookies = cookie_header?;
    let token = cookies
        .split(';')
        .map(|c| c.trim())
        .find(|c| c.starts_with(&format!("{}=", SESSION_COOKIE_NAME)))?
        .strip_prefix(&format!("{}=", SESSION_COOKIE_NAME))?;

    validate_session_token(token, &session_secret(state))
}

fn session_secret(state: &AppState) -> Vec<u8> {
    format!("rdg-auth-session:{}", state.config.server_name).into_bytes()
}

fn sign_session(user_id: i64, issued_at: u64, secret: &[u8]) -> String {
    let payload = format!("{}:{}", user_id, issued_at);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(payload.as_bytes());
    let sig = mac.finalize().into_bytes();
    use base64::Engine;
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
    format!("{}.{}", payload, sig_b64)
}

fn validate_session_token(token: &str, secret: &[u8]) -> Option<i64> {
    let parts: Vec<&str> = token.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let (sig_b64, payload) = (parts[0], parts[1]);

    // Verify signature
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(payload.as_bytes());
    use base64::Engine;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    mac.verify_slice(&sig).ok()?;

    // Parse payload
    let fields: Vec<&str> = payload.split(':').collect();
    if fields.len() != 2 {
        return None;
    }
    let user_id: i64 = fields[0].parse().ok()?;
    let issued_at: u64 = fields[1].parse().ok()?;

    // Check TTL
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now.saturating_sub(issued_at) > SESSION_TTL_SECS {
        return None;
    }

    Some(user_id)
}

fn set_session_cookie(user_id: i64, state: &AppState) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secret = session_secret(state);
    let token = sign_session(user_id, now, &secret);
    format!(
        "{}={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        SESSION_COOKIE_NAME, token, SESSION_TTL_SECS
    )
}

fn clear_session_cookie() -> String {
    format!(
        "{}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",
        SESSION_COOKIE_NAME
    )
}

/// Compute NT hash (MD4 of UTF-16LE password) for NTLM relay to targets.
fn compute_nt_hash(password: &str) -> Vec<u8> {
    use md4::{Digest, Md4};
    let utf16le: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut hasher = Md4::new();
    hasher.update(&utf16le);
    hasher.finalize().to_vec()
}

// --- Request/Response types ---

#[derive(Deserialize)]
struct AuthRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct AuthResponse {
    id: i64,
    username: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// --- Handlers ---

async fn signup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthRequest>,
) -> impl IntoResponse {
    let username = req.username.trim().to_string();
    let password = req.password.clone();

    if username.is_empty() || password.len() < 4 {
        return (
            StatusCode::BAD_REQUEST,
            [(header::SET_COOKIE, String::new())],
            Json(serde_json::json!({"error": "Username required, password must be at least 4 characters"})),
        );
    }

    // Check if user already exists
    if let Ok(Some(_)) = state.db.get_user_by_username(&username).await {
        return (
            StatusCode::CONFLICT,
            [(header::SET_COOKIE, String::new())],
            Json(serde_json::json!({"error": "Username already taken"})),
        );
    }

    // Hash password with argon2
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::SET_COOKIE, String::new())],
                Json(serde_json::json!({"error": "Internal error"})),
            );
        }
    };

    // Compute NT hash for NTLM relay
    let nt_hash = compute_nt_hash(&password);

    // Create user
    let user = match state
        .db
        .create_user_with_password(&username, &nt_hash, &password_hash)
        .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Failed to create user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::SET_COOKIE, String::new())],
                Json(serde_json::json!({"error": "Failed to create user"})),
            );
        }
    };

    let cookie = set_session_cookie(user.id, &state);
    (
        StatusCode::CREATED,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"id": user.id, "username": user.username})),
    )
}

async fn signin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthRequest>,
) -> impl IntoResponse {
    let username = req.username.trim().to_string();
    let password = req.password.clone();

    let user = match state.db.get_user_by_username(&username).await {
        Ok(Some(u)) => u,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::SET_COOKIE, String::new())],
                Json(serde_json::json!({"error": "Invalid credentials"})),
            );
        }
    };

    if !user.enabled {
        return (
            StatusCode::FORBIDDEN,
            [(header::SET_COOKIE, String::new())],
            Json(serde_json::json!({"error": "Account disabled"})),
        );
    }

    // Verify password
    let password_hash = match &user.password_hash {
        Some(h) => h.clone(),
        None => {
            // User was created via NTLM only — no password login available
            return (
                StatusCode::UNAUTHORIZED,
                [(header::SET_COOKIE, String::new())],
                Json(serde_json::json!({"error": "Invalid credentials"})),
            );
        }
    };

    let parsed_hash = match PasswordHash::new(&password_hash) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::SET_COOKIE, String::new())],
                Json(serde_json::json!({"error": "Internal error"})),
            );
        }
    };

    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::SET_COOKIE, String::new())],
            Json(serde_json::json!({"error": "Invalid credentials"})),
        );
    }

    let cookie = set_session_cookie(user.id, &state);
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"id": user.id, "username": user.username})),
    )
}

async fn signout() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::SET_COOKIE, clear_session_cookie())],
        Json(serde_json::json!({"ok": true})),
    )
}

async fn me(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok());

    let user_id = match validate_session_cookie(cookie_header, &state) {
        Some(id) => id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Not authenticated"})),
            );
        }
    };

    // Look up user by scanning (we could add get_user_by_id but this works)
    let users = state.db.list_users().await.unwrap_or_default();
    match users.into_iter().find(|u| u.id == user_id) {
        Some(user) => (
            StatusCode::OK,
            Json(serde_json::json!({"id": user.id, "username": user.username})),
        ),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "User not found"})),
        ),
    }
}
