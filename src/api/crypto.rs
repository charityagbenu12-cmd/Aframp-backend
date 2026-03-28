//! Payload encryption API endpoints.
//!
//! GET  /api/crypto/public-key   — returns current and transitional public keys
//! POST /api/crypto/test-decrypt — non-production test endpoint for consumer integration testing

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::crypto::{
    envelope::EncryptedEnvelope,
    keys::{KeyStore, PublicKeyInfo},
    middleware::DecryptionState,
};

// ---------------------------------------------------------------------------
// GET /api/crypto/public-key
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct PublicKeyResponse {
    pub keys: Vec<PublicKeyInfo>,
    pub active_kid: String,
}

pub async fn get_public_key(State(key_store): State<Arc<KeyStore>>) -> impl IntoResponse {
    Json(PublicKeyResponse {
        active_kid: key_store.active_kid.clone(),
        keys: key_store.public_versions(),
    })
}

// ---------------------------------------------------------------------------
// POST /api/crypto/test-decrypt  (non-production only)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TestDecryptRequest {
    /// A single encrypted field envelope to test decryption.
    pub field: serde_json::Value,
}

#[derive(Serialize)]
pub struct TestDecryptResponse {
    pub success: bool,
    pub field_length: usize,
    pub message: &'static str,
}

/// Test endpoint — confirms successful decryption without revealing the plaintext.
/// Only available in non-production environments.
pub async fn test_decrypt(
    State(state): State<DecryptionState>,
    Json(body): Json<TestDecryptRequest>,
) -> Response {
    // Guard: refuse in production.
    let app_env = std::env::var("APP_ENV").unwrap_or_else(|_| "development".into());
    if app_env == "production" {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
            .into_response();
    }

    if !EncryptedEnvelope::is_envelope(&body.field) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "not_an_envelope",
                "message": "The 'field' value is not an encrypted envelope"
            })),
        )
            .into_response();
    }

    let envelope: EncryptedEnvelope = match serde_json::from_value(body.field) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "malformed_envelope",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    };

    if let Err(e) = envelope.validate_algorithms() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "unsupported_algorithm", "message": e.to_string()})),
        )
            .into_response();
    }

    let key_version = match state.key_store.get_for_decryption(&envelope.kid) {
        Ok(kv) => kv,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "key_error", "message": e.to_string()})),
            )
                .into_response()
        }
    };

    let session_key = match key_version.unwrap_session_key(&envelope.epk, &envelope.ek) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "session_key_error", "message": e.to_string()})),
            )
                .into_response()
        }
    };

    let nonce = match crate::crypto::envelope::decode_nonce(&envelope.iv) {
        Ok(n) => n,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "nonce_error", "message": e.to_string()})),
            )
                .into_response()
        }
    };

    let ct_tag = match crate::crypto::envelope::concat_ct_tag(&envelope) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "ciphertext_error", "message": e.to_string()})),
            )
                .into_response()
        }
    };

    match crate::crypto::envelope::aes_gcm_decrypt(&session_key, &nonce, &ct_tag) {
        Ok(plaintext) => {
            // Return length only — never the plaintext value.
            Json(TestDecryptResponse {
                success: true,
                field_length: plaintext.len(),
                message: "Decryption successful. Plaintext not returned for security.",
            })
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "decryption_failed", "message": e.to_string()})),
        )
            .into_response(),
    }
}
