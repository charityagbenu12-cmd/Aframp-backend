use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderValue, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::File, net::SocketAddr, sync::Arc};
use uuid::Uuid;
use chrono::Utc;
use tracing::{error, warn, info};
use crate::cache::RedisCache;
use serde_json::json;
use jsonwebtoken::{decode, DecodingKey, Validation};

#[derive(Debug, Deserialize, Clone)]
pub struct LimitConfig {
    pub limit: i64,
    pub window: i64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EndpointLimits {
    pub per_ip: Option<LimitConfig>,
    pub per_wallet: Option<LimitConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    pub endpoints: HashMap<String, EndpointLimits>,
    pub default: EndpointLimits,
}

impl RateLimitConfig {
    pub fn load(path: &str) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let config: RateLimitConfig = serde_yaml::from_reader(file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    pub fn get_limits(&self, path: &str) -> EndpointLimits {
        for (prefix, limits) in &self.endpoints {
            if path.starts_with(prefix) {
                return limits.clone();
            }
        }
        self.default.clone()
    }
}

#[derive(Clone)]
pub struct RateLimitState {
    pub cache: Arc<RedisCache>,
    pub config: Arc<RateLimitConfig>,
}

pub async fn rate_limit_middleware(
    State(state): State<RateLimitState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let path = req.uri().path().to_string();

    // 1. Bypass logic
    if path.starts_with("/health") {
        return Ok(next.run(req).await);
    }
    
    // Check admin bypass via header
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str == "Bearer admin-bypass-token" || req.headers().get("x-admin-token").is_some() {
                info!("Admin bypass triggered for rate limit on path: {}", path);
                return Ok(next.run(req).await);
            }
        }
    }

    let limits = state.config.get_limits(&path);
    let mut wallet_address = None;

    // 2. Extract Wallet from JWT if available
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "default-development-secret-key-change-in-prod!".to_string());
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                use crate::api::auth::Claims; // using the Claims struct we built previously
                let mut validation = Validation::default();
                validation.validate_exp = true;
                validation.insecure_disable_signature_validation(); // Just decode safely for limits or properly validate if preferred, but verification is better. The actual auth middleware does strict verification. We'll just softly decode for identity.
                
                // Decode token securely
                if let Ok(token_data) = decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()) {
                    wallet_address = Some(token_data.claims.sub);
                }
            }
        }
    }

    let ip = req.headers().get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    let (redis_key, limit_conf) = if let Some(ref w) = wallet_address {
        if let Some(wl) = limits.per_wallet {
            (format!("rate_limit:wallet:{}:{}", w, path), wl)
        } else if let Some(il) = limits.per_ip {
            // Fallback to IP if no wallet limit exists
            (format!("rate_limit:ip:{}:{}", ip, path), il)
        } else {
            return Ok(next.run(req).await); 
        }
    } else {
        if let Some(il) = limits.per_ip {
            (format!("rate_limit:ip:{}:{}", ip, path), il)
        } else {
            return Ok(next.run(req).await);
        }
    };

    // 3. Sliding Window Algorithm Pipeline
    let mut conn = match state.cache.get_connection().await {
        Ok(c) => c,
        Err(e) => {
            error!("Redis connection failed in rate_limit_middleware: {}", e);
            let body = Json(json!({"error": "Internal server error"}));
            return Err((StatusCode::INTERNAL_SERVER_ERROR, body).into_response());
        }
    };

    let now_ms = Utc::now().timestamp_millis();
    let window_start_ms = now_ms - (limit_conf.window * 1000);
    let req_id = Uuid::new_v4().to_string();

    // Pipeline:
    // ZREMRANGEBYSCORE key -inf window_start_ms
    // ZCOUNT key -inf +inf
    let (removed, count): (i64, i64) = match redis::pipe()
        .atomic()
        .cmd("ZREMRANGEBYSCORE").arg(&redis_key).arg("-inf").arg(window_start_ms)
        .cmd("ZCARD").arg(&redis_key)
        .query_async(&mut *conn).await 
    {
        Ok(res) => res,
        Err(e) => {
            error!("Redis pipe error in rate_limit_middleware: {}", e);
            let body = Json(json!({"error": "Internal server error"}));
            return Err((StatusCode::INTERNAL_SERVER_ERROR, body).into_response());
        }
    };

    let remaining = limit_conf.limit - count;

    let reset_at = (now_ms / 1000) + limit_conf.window;
    let mut retry_after = limit_conf.window;

    if count >= limit_conf.limit {
        warn!(key = %redis_key, count = count, limit = limit_conf.limit, "Rate limit exceeded");

        // Emit metric for alert rule: aframp_rate_limit_breaches_total
        #[cfg(feature = "cache")]
        crate::metrics::alerting::rate_limit_breaches_total()
            .with_label_values(&[&path])
            .inc();

        let response_body = json!({
            "error": {
                "code": "RATE_LIMIT_EXCEEDED",
                "message": "Too many requests",
                "limit": limit_conf.limit,
                "remaining": 0,
                "retry_after": retry_after,
                "reset_at": chrono::DateTime::<Utc>::from_utc(
                    chrono::NaiveDateTime::from_timestamp_opt(reset_at, 0).unwrap_or_default(), Utc
                ).to_rfc3339()
            }
        });

        let mut res = (StatusCode::TOO_MANY_REQUESTS, Json(response_body)).into_response();
        res.headers_mut().insert("X-RateLimit-Limit", HeaderValue::from_str(&limit_conf.limit.to_string()).unwrap());
        res.headers_mut().insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));
        res.headers_mut().insert("X-RateLimit-Reset", HeaderValue::from_str(&reset_at.to_string()).unwrap());
        res.headers_mut().insert("X-RateLimit-Used", HeaderValue::from_str(&count.to_string()).unwrap());
        res.headers_mut().insert("Retry-After", HeaderValue::from_str(&retry_after.to_string()).unwrap());

        return Err(res);
    }

    // Allow path: Add current request
    let _: () = match redis::pipe()
        .atomic()
        .cmd("ZADD").arg(&redis_key).arg(now_ms).arg(&req_id)
        .cmd("EXPIRE").arg(&redis_key).arg(limit_conf.window)
        .query_async::<()>(&mut *conn).await
    {
        Ok(_) => (),
        Err(e) => error!("Failed to add to sorted set for rate_limit_middleware: {}", e),
    };

    // Forward the request to the next logical layer
    let mut res = next.run(req).await.into_response();

    // Inject successful Rate Limit headers
    res.headers_mut().insert("X-RateLimit-Limit", HeaderValue::from_str(&limit_conf.limit.to_string()).unwrap());
    res.headers_mut().insert("X-RateLimit-Remaining", HeaderValue::from_str(&(remaining - 1).max(0).to_string()).unwrap());
    res.headers_mut().insert("X-RateLimit-Reset", HeaderValue::from_str(&reset_at.to_string()).unwrap());
    res.headers_mut().insert("X-RateLimit-Used", HeaderValue::from_str(&(count + 1).to_string()).unwrap());

    Ok(res)
}
