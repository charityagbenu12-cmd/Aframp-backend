//! Integration tests for payload encryption — Issue: Data Security & Encryption
//!
//! Tests the full encrypted field submission lifecycle, key rotation,
//! retired key rejection, plaintext rejection, and reference implementation.

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        middleware,
        routing::post,
        Router,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p384::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    use rand::rngs::OsRng;
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tower::ServiceExt;

    use Bitmesh_backend::crypto::{
        envelope::{aes_gcm_encrypt, generate_session_key, EncryptedEnvelope},
        keys::{aes_kw_wrap, ecdh_derive_kek, KeyStatus, KeyStore, PlatformKeyVersion},
        middleware::{decryption_middleware, enforce_sensitive_field_encryption, DecryptionState},
    };

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build an encrypted envelope for a plaintext value using the given platform public key.
    fn encrypt_field(
        plaintext: &[u8],
        platform_pub: &PublicKey,
        kid: &str,
    ) -> EncryptedEnvelope {
        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let ephemeral_pub = ephemeral_secret.public_key();
        let epk_bytes = ephemeral_pub.to_encoded_point(false).as_bytes().to_vec();

        let kek = ecdh_derive_kek(&ephemeral_secret, platform_pub).unwrap();
        let session_key = generate_session_key();
        let wrapped_key = aes_kw_wrap(&kek, &session_key).unwrap();

        let (nonce, ct_tag) = aes_gcm_encrypt(&session_key, plaintext).unwrap();
        let tag_start = ct_tag.len() - 16;

        EncryptedEnvelope {
            marker: true,
            kid: kid.to_string(),
            alg: "ECDH-ES+A256KW".to_string(),
            enc: "A256GCM".to_string(),
            epk: URL_SAFE_NO_PAD.encode(&epk_bytes),
            ek: URL_SAFE_NO_PAD.encode(&wrapped_key),
            iv: URL_SAFE_NO_PAD.encode(nonce),
            ct: URL_SAFE_NO_PAD.encode(&ct_tag[..tag_start]),
            tag: URL_SAFE_NO_PAD.encode(&ct_tag[tag_start..]),
        }
    }

    fn make_store_with_key(kid: &str, status: KeyStatus) -> (KeyStore, PlatformKeyVersion) {
        let key = PlatformKeyVersion::generate(kid, status.clone()).unwrap();
        // We need to clone the key for the store and keep one for the public key.
        // Since PlatformKeyVersion is Clone, we can do this.
        let key_clone = key.clone();
        let store = KeyStore::new(vec![key]).unwrap();
        (store, key_clone)
    }

    fn decryption_state(store: KeyStore, grace_period: bool) -> DecryptionState {
        DecryptionState {
            key_store: Arc::new(store),
            grace_period,
            consumer_id_header: "x-aframp-key-id",
        }
    }

    fn build_app(state: DecryptionState) -> Router {
        // Echo handler — returns the decrypted body as-is.
        async fn echo(body: axum::extract::Json<Value>) -> axum::Json<Value> {
            body
        }

        Router::new()
            .route("/test", post(echo))
            .layer(middleware::from_fn_with_state(
                state,
                decryption_middleware,
            ))
    }

    async fn post_json(app: Router, body: Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri("/test")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    // -----------------------------------------------------------------------
    // Full encrypted field submission and decryption
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_encrypted_field_is_decrypted_in_request_context() {
        let (store, key) = make_store_with_key("v1", KeyStatus::Active);
        let platform_pub = PublicKey::from_sec1_bytes(&key.public_key_bytes).unwrap();

        let envelope = encrypt_field(b"NG12345678", &platform_pub, "v1");
        let body = json!({ "national_id": serde_json::to_value(&envelope).unwrap() });

        let app = build_app(decryption_state(store, false));
        let (status, resp) = post_json(app, body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["national_id"], "NG12345678");
    }

    #[tokio::test]
    async fn test_multiple_encrypted_fields_decrypted() {
        let (store, key) = make_store_with_key("v1", KeyStatus::Active);
        let platform_pub = PublicKey::from_sec1_bytes(&key.public_key_bytes).unwrap();

        let id_env = encrypt_field(b"AB123456", &platform_pub, "v1");
        let phone_env = encrypt_field(b"+254712345678", &platform_pub, "v1");

        let body = json!({
            "national_id": serde_json::to_value(&id_env).unwrap(),
            "phone_number": serde_json::to_value(&phone_env).unwrap(),
            "amount": "5000"
        });

        let app = build_app(decryption_state(store, false));
        let (status, resp) = post_json(app, body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["national_id"], "AB123456");
        assert_eq!(resp["phone_number"], "+254712345678");
        assert_eq!(resp["amount"], "5000"); // non-sensitive field unchanged
    }

    // -----------------------------------------------------------------------
    // Key rotation — simultaneous old and new key validity
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_transitional_key_still_accepted_during_rotation() {
        let old_key = PlatformKeyVersion::generate("v1", KeyStatus::Transitional).unwrap();
        let new_key = PlatformKeyVersion::generate("v2", KeyStatus::Active).unwrap();

        let old_pub = PublicKey::from_sec1_bytes(&old_key.public_key_bytes).unwrap();
        let store = KeyStore::new(vec![old_key, new_key]).unwrap();

        // Encrypt with old (transitional) key.
        let envelope = encrypt_field(b"passport-XYZ", &old_pub, "v1");
        let body = json!({ "passport_number": serde_json::to_value(&envelope).unwrap() });

        let app = build_app(decryption_state(store, false));
        let (status, resp) = post_json(app, body).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["passport_number"], "passport-XYZ");
    }

    // -----------------------------------------------------------------------
    // Retired key version rejection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_retired_key_version_is_rejected() {
        let active = PlatformKeyVersion::generate("v2", KeyStatus::Active).unwrap();
        let retired = PlatformKeyVersion::generate("v1", KeyStatus::Retired).unwrap();
        let retired_pub = PublicKey::from_sec1_bytes(&retired.public_key_bytes).unwrap();

        let store = KeyStore::new(vec![active, retired]).unwrap();

        let envelope = encrypt_field(b"secret", &retired_pub, "v1");
        let body = json!({ "national_id": serde_json::to_value(&envelope).unwrap() });

        let app = build_app(decryption_state(store, false));
        let (status, resp) = post_json(app, body).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp["code"], "retired_key_version");
    }

    // -----------------------------------------------------------------------
    // Plaintext sensitive field rejection after grace period
    // -----------------------------------------------------------------------

    #[test]
    fn test_plaintext_sensitive_field_rejected_after_grace_period() {
        let body = json!({ "national_id": "NG12345678" });
        let result = enforce_sensitive_field_encryption(&body, false, "/api/kyc/submit");
        assert!(result.is_err());
    }

    #[test]
    fn test_plaintext_sensitive_field_allowed_during_grace_period() {
        let body = json!({ "national_id": "NG12345678" });
        // Grace period = true → should succeed (with a warning log).
        let result = enforce_sensitive_field_encryption(&body, true, "/api/kyc/submit");
        assert!(result.is_ok());
    }

    #[test]
    fn test_non_sensitive_plaintext_field_always_allowed() {
        let body = json!({ "amount": "5000", "wallet_address": "GXXX..." });
        let result = enforce_sensitive_field_encryption(&body, false, "/api/onramp/initiate");
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // GCM authentication tag verification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_tampered_ciphertext_is_rejected() {
        let (store, key) = make_store_with_key("v1", KeyStatus::Active);
        let platform_pub = PublicKey::from_sec1_bytes(&key.public_key_bytes).unwrap();

        let mut envelope = encrypt_field(b"sensitive-data", &platform_pub, "v1");
        // Tamper with the ciphertext.
        let mut ct_bytes = URL_SAFE_NO_PAD.decode(&envelope.ct).unwrap();
        ct_bytes[0] ^= 0xFF;
        envelope.ct = URL_SAFE_NO_PAD.encode(&ct_bytes);

        let body = json!({ "national_id": serde_json::to_value(&envelope).unwrap() });

        let app = build_app(decryption_state(store, false));
        let (status, resp) = post_json(app, body).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp["code"], "auth_tag_verification_failed");
    }

    // -----------------------------------------------------------------------
    // Non-JSON body passes through unchanged
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_non_json_body_passes_through() {
        let (store, _) = make_store_with_key("v1", KeyStatus::Active);
        let state = decryption_state(store, false);

        async fn echo_text(body: String) -> String {
            body
        }

        let app = Router::new()
            .route("/test", post(echo_text))
            .layer(middleware::from_fn_with_state(
                state,
                decryption_middleware,
            ));

        let req = Request::builder()
            .method("POST")
            .uri("/test")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("plain text body"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
