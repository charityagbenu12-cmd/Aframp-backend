use axum::{
    extract::{State, ConnectInfo},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::cache::RedisCache;
use uuid::Uuid;
use chrono::Utc;
use stellar_strkey::ed25519::PublicKey as StellarPublicKey;
use std::net::SocketAddr;
use tracing::{info, warn, error};
use serde_json::json;

use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use sha2::{Sha256, Digest};
use base64::prelude::*;
use jsonwebtoken::{encode, Header, EncodingKey};

// JWT claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub token_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub wallet_address: String,
    pub created_at: i64,
    pub last_active: i64,
    pub ip_address: String,
    pub user_agent: String,
}

pub struct AuthState {
    pub redis_cache: Arc<RedisCache>,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub wallet_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeData {
    pub wallet_address: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub nonce: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub wallet_address: String,
    pub message: String,
    pub signature: String,
    pub nonce: String,
}

#[derive(Debug, Serialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: String,
}

pub async fn generate_challenge(
    State(state): State<Arc<AuthState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<ChallengeRequest>,
) -> impl IntoResponse {
    let wallet_address = payload.wallet_address.trim().to_string();

    // 1. Validate Stellar wallet address
    if StellarPublicKey::from_string(&wallet_address).is_err() {
        warn!(wallet = %wallet_address, "Invalid Stellar wallet address provided for challenge");
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid Stellar wallet address"}))).into_response();
    }

    // 2. Rate limiting
    let ip = addr.ip().to_string();
    let mut conn = match state.redis_cache.get_connection().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to get Redis connection: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Internal server error"}))).into_response();
        }
    };

    let ip_key = format!("ratelimit:challenge:ip:{}", ip);
    let wallet_key = format!("ratelimit:challenge:wallet:{}", wallet_address);

    let (ip_count, wallet_count): (i64, i64) = match redis::pipe()
        .atomic()
        .cmd("INCR").arg(&ip_key)
        .cmd("EXPIRE").arg(&ip_key).arg(60).ignore()
        .cmd("INCR").arg(&wallet_key)
        .cmd("EXPIRE").arg(&wallet_key).arg(60).ignore()
        .query_async(&mut *conn).await 
    {
        Ok(res) => res,
        Err(e) => {
            error!("Redis rate limit error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Internal server error"}))).into_response();
        }
    };

    if ip_count > 10 {
        warn!(ip = %ip, "Rate limit exceeded for IP on challenge generation");
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "Too many requests from this IP"}))).into_response();
    }
    if wallet_count > 20 {
        warn!(wallet = %wallet_address, "Rate limit exceeded for wallet on challenge generation");
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "Too many requests for this wallet"}))).into_response();
    }

    // 3. Generate nonce and timestamps
    let nonce = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    let expires_at = now + 300; // 5 minutes TTL

    // 4. Create human-readable challenge message
    let challenge_msg = format!(
        "Sign this message to authenticate with Aframp:\n\nWallet: {}\nTimestamp: {}\nNonce: {}\n\nThis request will not trigger a blockchain transaction or cost any fees.",
        wallet_address, now, nonce
    );

    // 5. Store challenge in Redis
    let challenge_key = format!("auth:challenge:{}", nonce);
    let challenge_data = ChallengeData {
        wallet_address: wallet_address.clone(),
        created_at: now,
        expires_at,
    };

    let data_json = match serde_json::to_string(&challenge_data) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to serialize challenge data: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Serialization error"}))).into_response();
        }
    };

    let set_res: redis::RedisResult<()> = redis::cmd("SETEX")
        .arg(&challenge_key)
        .arg(300)
        .arg(&data_json)
        .query_async(&mut *conn).await;

    if let Err(e) = set_res {
        error!("Failed to save challenge to Redis: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to store challenge"}))).into_response();
    }

    info!(wallet = %wallet_address, nonce = %nonce, "Challenge generated successfully");

    // 6. Return challenge
    let response = ChallengeResponse {
        challenge: challenge_msg,
        nonce,
        expires_at,
    };

    (StatusCode::OK, Json(response)).into_response()
}

pub async fn verify_signature(
    State(state): State<Arc<AuthState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    let user_agent = req.headers().get("user-agent").and_then(|h| h.to_str().ok()).unwrap_or("unknown").to_string();

    // extract payload
    let payload = match axum::extract::Json::<VerifyRequest>::from_request(req, &state).await {
        Ok(p) => p.0,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid JSON format"}))).into_response(),
    };

    let wallet_address = payload.wallet_address.trim().to_string();
    let ip = addr.ip().to_string();

    let mut conn = match state.redis_cache.get_connection().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to get Redis connection: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Internal server error"}))).into_response();
        }
    };

    // Rate Limiting (5 requests/min per wallet)
    let rl_key = format!("ratelimit:verify:wallet:{}", wallet_address);
    let count: i64 = match redis::pipe()
        .atomic()
        .cmd("INCR").arg(&rl_key)
        .cmd("EXPIRE").arg(&rl_key).arg(60).ignore()
        .query_async(&mut *conn).await
    {
        Ok(res) => {
            let res_tuple: (i64, i64) = res;
            res_tuple.0
        },
        Err(e) => {
            error!("Redis rate limit error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Internal server error"}))).into_response();
        }
    };

    if count > 5 {
        warn!(wallet = %wallet_address, "Rate limit exceeded for verify endpoint");
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "Too many requests for verification. Try again later."}))).into_response();
    }

    // Retrieve challenge from Redis
    let challenge_key = format!("auth:challenge:{}", payload.nonce);
    let expected_data_str: Option<String> = match redis::cmd("GET").arg(&challenge_key).query_async(&mut *conn).await {
        Ok(res) => res,
        Err(e) => {
            error!("Redis GET error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Internal server error"}))).into_response();
        }
    };

    let expected_data_str = match expected_data_str {
        Some(d) => d,
        None => {
            warn!(nonce = %payload.nonce, "Challenge not found or expired");
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Challenge not found or expired"}))).into_response();
        }
    };

    let challenge: ChallengeData = match serde_json::from_str(&expected_data_str) {
        Ok(c) => c,
        Err(_) => {
            error!("Failed to deserialize challenge data");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Internal server error"}))).into_response();
        }
    };

    // Validate Challenge Data
    let now = Utc::now().timestamp();
    if challenge.wallet_address != wallet_address {
        warn!(
            expected = %challenge.wallet_address,
            provided = %wallet_address,
            "Wallet address mismatch in verification"
        );
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Wallet address does not match challenge"}))).into_response();
    }

    if now > challenge.expires_at {
        warn!(nonce = %payload.nonce, "Challenge expired");
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Challenge has expired"}))).into_response();
    }

    // Stellar Signature Verification
    let pub_key_bytes = match StellarPublicKey::from_string(&wallet_address) {
        Ok(pk) => pk.into_binary(),
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid wallet address structure"}))).into_response();
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&pub_key_bytes) {
        Ok(k) => k,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "Failed to parse public key"}))).into_response();
        }
    };

    let signature_bytes = match BASE64_STANDARD.decode(&payload.signature) {
        Ok(s) => s,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid signature base64 encoding"}))).into_response();
        }
    };

    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(s) => s,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid signature length"}))).into_response();
        }
    };

    // Hash the message with SHA-256
    let mut hasher = Sha256::new();
    hasher.update(payload.message.as_bytes());
    let hashed_msg = hasher.finalize();

    if verifying_key.verify(&hashed_msg, &signature).is_err() {
        warn!(wallet = %wallet_address, "Signature verification failed");
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid signature"}))).into_response();
    }

    // Prevent Replay Attack: Delete the challenge
    let _: () = redis::cmd("DEL").arg(&challenge_key).query_async(&mut *conn).await.unwrap_or(());

    // Generate session & JWT matching session data
    let session_id = Uuid::new_v4().to_string();
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "default-development-secret-key-change-in-prod!".to_string());
    let encoding_key = EncodingKey::from_secret(jwt_secret.as_bytes());

    let access_exp = now + 3600; // 1 hour
    let refresh_exp = now + (14 * 24 * 3600); // 14 days

    let auth_claims = Claims {
        sub: wallet_address.clone(),
        exp: access_exp,
        iat: now,
        token_type: "access".to_string(),
    };

    let refresh_claims = Claims {
        sub: wallet_address.clone(),
        exp: refresh_exp,
        iat: now,
        token_type: "refresh".to_string(),
    };

    let access_token = match encode(&Header::default(), &auth_claims, &encoding_key) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to generate access token: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Token generation failed"}))).into_response();
        }
    };

    let refresh_token = match encode(&Header::default(), &refresh_claims, &encoding_key) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to generate refresh token: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Token generation failed"}))).into_response();
        }
    };

    // Store Session in Redis
    let session_key = format!("auth:session:{}", session_id);
    let session_data = SessionMetadata {
        wallet_address: wallet_address.clone(),
        created_at: now,
        last_active: now,
        ip_address: ip,
        user_agent,
    };

    if let Ok(json_data) = serde_json::to_string(&session_data) {
        let _: () = redis::cmd("SETEX")
            .arg(&session_key)
            .arg(14 * 24 * 3600) // TTL 14 days
            .arg(&json_data)
            .query_async(&mut *conn).await.unwrap_or(());
    }

    info!(wallet = %wallet_address, session = %session_id, "Wallet authenticated successfully");

    (StatusCode::OK, Json(AuthTokens {
        access_token,
        refresh_token,
        session_id,
    })).into_response()
}
