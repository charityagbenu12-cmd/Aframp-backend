//! Server-side decryption middleware.
//!
//! Walks the JSON request body, detects encrypted field envelopes, decrypts
//! them, and replaces the envelope with the plaintext value before the handler
//! sees the request.
//!
//! # Security guarantees
//! - Decrypted plaintext is NEVER written to any log at any level.
//! - The session key is zeroed from memory immediately after all field
//!   decryptions for a request are complete.
//! - GCM authentication tag verification is mandatory — any tampered field
//!   causes the entire request to be rejected.
//! - Requests using retired key versions are rejected with a clear error.

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::Value;
use std::sync::Arc;
use tracing::{error, warn};
use zeroize::Zeroizing;

use super::{
    envelope::{aes_gcm_decrypt, concat_ct_tag, decode_nonce, EncryptedEnvelope},
    keys::{EncryptionError, KeyStore},
    metrics,
};

// ---------------------------------------------------------------------------
// Middleware state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DecryptionState {
    pub key_store: Arc<KeyStore>,
    /// When `true`, plaintext sensitive fields are accepted with a deprecation
    /// warning (grace period mode). When `false`, they are rejected.
    pub grace_period: bool,
    /// Header name used to extract the consumer ID for alerting.
    pub consumer_id_header: &'static str,
}

// ---------------------------------------------------------------------------
// Error response
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct DecryptionErrorBody {
    error: &'static str,
    code: String,
    message: String,
}

fn error_response(status: StatusCode, code: impl Into<String>, msg: impl Into<String>) -> Response {
    (
        status,
        Json(DecryptionErrorBody {
            error: "decryption_error",
            code: code.into(),
            message: msg.into(),
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Middleware entry point
// ---------------------------------------------------------------------------

/// Axum middleware layer that decrypts encrypted field envelopes in request bodies.
pub async fn decryption_middleware(
    State(state): State<DecryptionState>,
    req: Request,
    next: Next,
) -> Response {
    let (parts, body) = req.into_parts();

    let is_json = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("application/json"))
        .unwrap_or(false);

    if !is_json {
        return next.run(Request::from_parts(parts, body)).await;
    }

    let body_bytes = match to_bytes(body, 4 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return error_response(StatusCode::BAD_REQUEST, "body_read_error", "Failed to read request body")
        }
    };

    let mut json: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            let new_body = Body::from(body_bytes);
            return next.run(Request::from_parts(parts, new_body)).await;
        }
    };

    let consumer_id = parts
        .headers
        .get(state.consumer_id_header)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    if let Err(resp) = decrypt_fields(&mut json, &state, &consumer_id) {
        return resp;
    }

    let new_body_bytes = match serde_json::to_vec(&json) {
        Ok(b) => b,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "serialization_error",
                "Failed to re-serialize body",
            )
        }
    };

    next.run(Request::from_parts(parts, Body::from(new_body_bytes))).await
}

// ---------------------------------------------------------------------------
// Recursive field decryption
// ---------------------------------------------------------------------------

fn decrypt_fields(
    value: &mut Value,
    state: &DecryptionState,
    consumer_id: &str,
) -> Result<(), Response> {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let field_value = map.get_mut(&key).unwrap();
                if EncryptedEnvelope::is_envelope(field_value) {
                    let envelope: EncryptedEnvelope =
                        match serde_json::from_value(field_value.clone()) {
                            Ok(e) => e,
                            Err(_) => {
                                metrics::inc_decryption_failure(&key, "malformed_envelope");
                                error!(field = %key, consumer_id = %consumer_id, "Malformed encrypted envelope");
                                return Err(error_response(
                                    StatusCode::BAD_REQUEST,
                                    "malformed_envelope",
                                    format!("Malformed encrypted envelope for field '{key}'"),
                                ));
                            }
                        };

                    let plaintext = decrypt_envelope(&envelope, state, &key, consumer_id)?;
                    // NEVER log plaintext
                    *field_value =
                        Value::String(String::from_utf8(plaintext.to_vec()).unwrap_or_default());
                } else {
                    decrypt_fields(field_value, state, consumer_id)?;
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                decrypt_fields(item, state, consumer_id)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn decrypt_envelope(
    envelope: &EncryptedEnvelope,
    state: &DecryptionState,
    field_name: &str,
    consumer_id: &str,
) -> Result<Zeroizing<Vec<u8>>, Response> {
    if let Err(e) = envelope.validate_algorithms() {
        metrics::inc_decryption_failure(field_name, "unsupported_algorithm");
        return Err(error_response(StatusCode::BAD_REQUEST, "unsupported_algorithm", e.to_string()));
    }

    let key_version = match state.key_store.get_for_decryption(&envelope.kid) {
        Ok(kv) => kv,
        Err(EncryptionError::KeyVersionRetired(kid)) => {
            metrics::inc_decryption_failure(field_name, "retired_key_version");
            warn!(kid = %kid, consumer_id = %consumer_id, field = %field_name, "Request using retired key version");
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "retired_key_version",
                format!("Key version '{kid}' has been retired. Refresh the public key and re-encrypt."),
            ));
        }
        Err(EncryptionError::KeyVersionNotFound(kid)) => {
            metrics::inc_decryption_failure(field_name, "unknown_key_version");
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "unknown_key_version",
                format!("Key version '{kid}' is not recognised."),
            ));
        }
        Err(e) => {
            metrics::inc_decryption_failure(field_name, "key_lookup_error");
            error!(error = %e, "Key lookup error");
            return Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, "key_lookup_error", "Internal key lookup error"));
        }
    };

    metrics::inc_key_version_usage(&envelope.kid);

    let session_key = match key_version.unwrap_session_key(&envelope.epk, &envelope.ek) {
        Ok(k) => k,
        Err(_) => {
            metrics::inc_decryption_failure(field_name, "session_key_decryption_failed");
            error!(field = %field_name, consumer_id = %consumer_id, "Session key decryption failed");
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "session_key_decryption_failed",
                "Failed to decrypt session key",
            ));
        }
    };

    let nonce = match decode_nonce(&envelope.iv) {
        Ok(n) => n,
        Err(e) => {
            metrics::inc_decryption_failure(field_name, "malformed_nonce");
            return Err(error_response(StatusCode::BAD_REQUEST, "malformed_nonce", e.to_string()));
        }
    };

    let ct_tag = match concat_ct_tag(envelope) {
        Ok(b) => b,
        Err(e) => {
            metrics::inc_decryption_failure(field_name, "malformed_ciphertext");
            return Err(error_response(StatusCode::BAD_REQUEST, "malformed_ciphertext", e.to_string()));
        }
    };

    // session_key is Zeroizing — zeroed on drop after this function returns.
    let plaintext = match aes_gcm_decrypt(&session_key, &nonce, &ct_tag) {
        Ok(p) => p,
        Err(EncryptionError::AuthTagVerificationFailed) => {
            metrics::inc_decryption_failure(field_name, "auth_tag_verification_failed");
            error!(field = %field_name, consumer_id = %consumer_id, "GCM auth tag verification failed — possible tampering");
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "auth_tag_verification_failed",
                format!("Authentication tag verification failed for field '{field_name}' — possible tampering"),
            ));
        }
        Err(e) => {
            metrics::inc_decryption_failure(field_name, "decryption_failed");
            error!(field = %field_name, error = %e, "Field decryption failed");
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "decryption_failed",
                format!("Decryption failed for field '{field_name}'"),
            ));
        }
    };

    metrics::inc_decryption(field_name);
    Ok(Zeroizing::new(plaintext.to_vec()))
}

// ---------------------------------------------------------------------------
// Plaintext sensitive field enforcement
// ---------------------------------------------------------------------------

/// Check a JSON body for plaintext sensitive fields.
///
/// Grace period mode: logs a deprecation warning and allows the request.
/// Enforcement mode: returns a 422 error response.
pub fn enforce_sensitive_field_encryption(
    body: &Value,
    grace_period: bool,
    endpoint: &str,
) -> Result<(), Response> {
    use super::keys::SENSITIVE_FIELDS;

    if let Value::Object(map) = body {
        for field in SENSITIVE_FIELDS {
            if let Some(v) = map.get(*field) {
                if v.is_string() {
                    metrics::inc_plaintext_rejection(endpoint, field);
                    if grace_period {
                        warn!(
                            field = %field,
                            endpoint = %endpoint,
                            "DEPRECATION: sensitive field submitted as plaintext — will be rejected after grace period expires"
                        );
                    } else {
                        return Err(error_response(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "plaintext_sensitive_field",
                            format!(
                                "Field '{field}' must be submitted in encrypted form. \
                                 See GET /api/crypto/public-key for the platform encryption key."
                            ),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
