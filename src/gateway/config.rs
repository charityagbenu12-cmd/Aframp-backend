//! Gateway configuration — loaded from environment variables.
//! All security policies are defined here and applied via the middleware stack.

use std::collections::HashMap;
use std::env;

/// Per-endpoint category body size limits (bytes).
pub const BODY_LIMIT_DEFAULT: usize = 1024 * 1024;       // 1 MB
pub const BODY_LIMIT_KYC: usize = 10 * 1024 * 1024;      // 10 MB (document uploads)
pub const BODY_LIMIT_PAYMENT: usize = 64 * 1024;          // 64 KB
pub const MAX_URL_LENGTH: usize = 2048;

/// Gateway-level rate limits (higher than app-level — catch egregious abuse only).
pub const GATEWAY_RATE_LIMIT_PER_IP: u64 = 1000;         // per minute
pub const GATEWAY_RATE_LIMIT_PER_KEY_PREFIX: u64 = 5000; // per minute

/// HMAC-SHA256 secret used to sign the X-Gateway-Signature header.
/// Upstream services verify this to reject non-gateway traffic.
pub fn gateway_secret() -> String {
    env::var("GATEWAY_SIGNING_SECRET")
        .unwrap_or_else(|_| "dev-gateway-secret-change-in-production".to_string())
}

/// HSTS max-age in seconds (default 1 year).
pub fn hsts_max_age() -> u64 {
    env::var("HSTS_MAX_AGE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(31_536_000)
}

/// Allowed HTTP methods per endpoint category prefix.
pub fn allowed_methods_for(path: &str) -> &'static [&'static str] {
    if path.starts_with("/api/admin") {
        &["GET", "POST", "PATCH", "DELETE", "OPTIONS"]
    } else if path.starts_with("/api/v1/auth") || path.starts_with("/api/v1/oauth") {
        &["GET", "POST", "OPTIONS"]
    } else {
        &["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    }
}

/// Body size limit for a given path.
pub fn body_limit_for(path: &str) -> usize {
    if path.contains("/kyc") || path.contains("/document") {
        BODY_LIMIT_KYC
    } else if path.contains("/payment") || path.contains("/onramp") || path.contains("/offramp") {
        BODY_LIMIT_PAYMENT
    } else {
        BODY_LIMIT_DEFAULT
    }
}

/// CORS allowed origins per endpoint category.
pub fn cors_origins_for(path: &str) -> Vec<String> {
    let env_name = env::var("APP_ENV").unwrap_or_else(|_| "development".into());

    if path.starts_with("/api/admin") {
        // Admin: only internal dashboard origin
        match env_name.as_str() {
            "production" => vec!["https://admin.aframp.io".into()],
            "staging" => vec!["https://admin-staging.aframp.io".into()],
            _ => vec!["http://localhost:3001".into()],
        }
    } else if path.starts_with("/api/developer") {
        // Developer portal
        match env_name.as_str() {
            "production" => vec!["https://developers.aframp.io".into()],
            "staging" => vec!["https://developers-staging.aframp.io".into()],
            _ => vec!["http://localhost:3002".into()],
        }
    } else {
        // Consumer API
        match env_name.as_str() {
            "production" => vec![
                "https://app.aframp.io".into(),
                "https://aframp.io".into(),
            ],
            "staging" => vec!["https://staging.aframp.io".into()],
            _ => vec![
                "http://localhost:3000".into(),
                "http://localhost:5173".into(),
                "http://127.0.0.1:3000".into(),
            ],
        }
    }
}
