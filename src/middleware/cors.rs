//! CORS (Cross-Origin Resource Sharing) middleware
//!
//! Provides secure cross-origin access configuration for the Aframp API.
//! Supports environment-based origin configuration and proper preflight handling.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, Method, Request, Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{debug, info, warn};

/// CORS configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: u32,
}

impl CorsConfig {
    /// Create CORS configuration from environment variables
    pub fn from_env() -> Self {
        let env = std::env::var("ENVIRONMENT")
            .or_else(|_| std::env::var("APP_ENV"))
            .unwrap_or_else(|_| "development".to_string());
        
        let allowed_origins = match env.as_str() {
            "production" => {
                info!("🔒 Production CORS: Restricting to production domains");
                vec![
                    "https://app.aframp.com".to_string(),
                    "https://aframp.com".to_string(),
                ]
            },
            "staging" => {
                info!("🔧 Staging CORS: Allowing staging domains");
                vec![
                    "https://staging.aframp.com".to_string(),
                    "https://app-staging.aframp.com".to_string(),
                ]
            },
            _ => {
                info!("🛠️  Development CORS: Allowing localhost origins");
                vec![
                    "http://localhost:3000".to_string(),
                    "http://localhost:5173".to_string(),
                    "http://localhost:8080".to_string(),
                    "http://127.0.0.1:3000".to_string(),
                    "http://127.0.0.1:5173".to_string(),
                    "http://127.0.0.1:8080".to_string(),
                ]
            },
        };
        
        // Allow custom origins via environment variable
        let custom_origins = std::env::var("CORS_ALLOWED_ORIGINS")
            .ok()
            .map(|origins| {
                origins
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        
        let mut final_origins = allowed_origins;
        final_origins.extend(custom_origins);
        
        Self {
            allowed_origins: final_origins,
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "PATCH".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Request-ID".to_string(),
                "X-API-Key".to_string(),
                "X-Signature".to_string(),
                "X-Timestamp".to_string(),
            ],
            allow_credentials: true,
            max_age: 86400, // 24 hours
        }
    }
    
    /// Check if an origin is allowed
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.contains(&origin.to_string())
    }
}

/// CORS middleware function
pub async fn cors_middleware<B>(
    State(config): State<CorsConfig>,
    request: Request<B>,
    next: Next<B>,
) -> Response<Body> {
    // Get origin from request headers
    let origin = request
        .headers()
        .get("Origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    
    debug!(origin = %origin, "Processing CORS request");
    
    // Check if origin is allowed
    let origin_allowed = config.is_origin_allowed(origin);
    
    if !origin.is_empty() && !origin_allowed {
        warn!(
            origin = %origin,
            allowed_origins = ?config.allowed_origins,
            "CORS: Origin not allowed"
        );
    }
    
    // Handle preflight requests (OPTIONS)
    if request.method() == Method::OPTIONS {
        debug!("Handling CORS preflight request");
        
        let mut response = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap();
        
        if origin_allowed {
            add_cors_headers(&mut response, &config, origin);
            info!(origin = %origin, "CORS preflight: Origin allowed");
        } else {
            info!(origin = %origin, "CORS preflight: Origin blocked");
        }
        
        return response;
    }
    
    // Process normal request
    let mut response = next.run(request).await;
    
    // Add CORS headers to response if origin is allowed
    if origin_allowed {
        add_cors_headers(&mut response, &config, origin);
        debug!(origin = %origin, "CORS headers added to response");
    }
    
    response
}

/// Add CORS headers to response
fn add_cors_headers(response: &mut Response<Body>, config: &CorsConfig, origin: &str) {
    let headers = response.headers_mut();
    
    // Set allowed origin (specific origin, not wildcard for credentials)
    if let Ok(origin_value) = HeaderValue::from_str(origin) {
        headers.insert("Access-Control-Allow-Origin", origin_value);
    }
    
    // Set allowed methods
    if let Ok(methods_value) = HeaderValue::from_str(&config.allowed_methods.join(", ")) {
        headers.insert("Access-Control-Allow-Methods", methods_value);
    }
    
    // Set allowed headers
    if let Ok(headers_value) = HeaderValue::from_str(&config.allowed_headers.join(", ")) {
        headers.insert("Access-Control-Allow-Headers", headers_value);
    }
    
    // Set max age for preflight cache
    if let Ok(max_age_value) = HeaderValue::from_str(&config.max_age.to_string()) {
        headers.insert("Access-Control-Max-Age", max_age_value);
    }
    
    // Set credentials flag
    if config.allow_credentials {
        headers.insert(
            "Access-Control-Allow-Credentials",
            HeaderValue::from_static("true"),
        );
    }
    
    // Expose additional headers that the frontend might need
    headers.insert(
        "Access-Control-Expose-Headers",
        HeaderValue::from_static("X-Request-ID, X-RateLimit-Remaining, X-RateLimit-Reset"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cors_config_from_env() {
        // Test development environment
        std::env::set_var("ENVIRONMENT", "development");
        let config = CorsConfig::from_env();
        assert!(config.allowed_origins.contains(&"http://localhost:3000".to_string()));
        assert!(config.allow_credentials);
        assert_eq!(config.max_age, 86400);
        
        // Test production environment
        std::env::set_var("ENVIRONMENT", "production");
        let config = CorsConfig::from_env();
        assert!(config.allowed_origins.contains(&"https://app.aframp.com".to_string()));
        assert!(!config.allowed_origins.contains(&"http://localhost:3000".to_string()));
    }
    
    #[test]
    fn test_origin_allowed() {
        let config = CorsConfig {
            allowed_origins: vec!["https://app.aframp.com".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_headers: vec!["Content-Type".to_string()],
            allow_credentials: true,
            max_age: 3600,
        };
        
        assert!(config.is_origin_allowed("https://app.aframp.com"));
        assert!(!config.is_origin_allowed("https://malicious.com"));
        assert!(!config.is_origin_allowed(""));
    }
}