//! Integration tests for Auth endpoints
//!
//! Requires: REDIS_URL
//! Run with: cargo test auth_api -- --ignored

use std::sync::Arc;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
    Router,
    extract::ConnectInfo,
};
use tower::ServiceExt;
use serde_json::json;
use ed25519_dalek::{SigningKey, Signer};
use base64::prelude::*;
use rand::rngs::OsRng;

use Bitmesh_backend::cache::{init_cache_pool, CacheConfig, RedisCache};
use Bitmesh_backend::api::auth::{
    AuthState, ChallengeResponse, AuthTokens, generate_challenge, verify_signature
};

async fn setup_router() -> Router {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let cache_config = CacheConfig {
        redis_url,
        ..Default::default()
    };
    let cache_pool = init_cache_pool(cache_config).await.expect("Redis init");
    let redis_cache = RedisCache::new(cache_pool);

    let auth_state = AuthState {
        redis_cache: Arc::new(redis_cache),
    };

    Router::new()
        .route("/api/auth/challenge", post(generate_challenge))
        .route("/api/auth/verify", post(verify_signature))
        .with_state(Arc::new(auth_state))
}

fn create_test_request(uri: &str, body: serde_json::Value) -> Request<Body> {
    let mut req = Request::builder()
        .uri(uri)
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, "TestAgent/1.0")
        .header(header::HOST, "localhost:8080")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    
    // Mock the connection info for rate limiting
    req.extensions_mut().insert(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))));
    req
}

#[tokio::test]
#[ignore]
async fn test_auth_flow_success() {
    let app = setup_router().await;

    // Generate test KeyPair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let public_key = signing_key.verifying_key();
    
    use stellar_strkey::ed25519::PublicKey as StellarPublicKey;
    let wallet_address = StellarPublicKey::from_binary(public_key.to_bytes()).to_string();

    // 1. Generate Challenge
    let challenge_req = create_test_request(
        "/api/auth/challenge",
        json!({ "wallet_address": wallet_address })
    );

    let response = app.clone().oneshot(challenge_req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let challenge_resp: ChallengeResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert!(!challenge_resp.challenge.is_empty());
    assert!(!challenge_resp.nonce.is_empty());
    
    // 2. Sign Challenge (Stellar uses SHA-256 hash or raw message. Our backend expects the hash as standard dalek signature against the hash)
    // Wait, the backend does:
    // let mut hasher = Sha256::new();
    // hasher.update(payload.message.as_bytes());
    // let hashed_msg = hasher.finalize();
    // verifying_key.verify(&hashed_msg, &signature)
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(challenge_resp.challenge.as_bytes());
    let hashed_msg = hasher.finalize();
    let signature = signing_key.sign(&hashed_msg);
    let signature_base64 = BASE64_STANDARD.encode(signature.to_bytes());

    // 3. Verify Signature
    let verify_req = create_test_request(
        "/api/auth/verify",
        json!({
            "wallet_address": wallet_address,
            "message": challenge_resp.challenge,
            "signature": signature_base64,
            "nonce": challenge_resp.nonce
        })
    );

    let verify_response = app.clone().oneshot(verify_req).await.unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);

    let verify_bytes = axum::body::to_bytes(verify_response.into_body(), usize::MAX).await.unwrap();
    let auth_tokens: AuthTokens = serde_json::from_slice(&verify_bytes).unwrap();

    assert!(!auth_tokens.access_token.is_empty());
    assert!(!auth_tokens.refresh_token.is_empty());
    assert!(!auth_tokens.session_id.is_empty());
}

#[tokio::test]
#[ignore]
async fn test_auth_invalid_address() {
    let app = setup_router().await;

    let challenge_req = create_test_request(
        "/api/auth/challenge",
        json!({ "wallet_address": "invalid_address" })
    );

    let response = app.clone().oneshot(challenge_req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
