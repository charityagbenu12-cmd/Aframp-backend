//! Security headers middleware
//!
//! Implements comprehensive security headers to protect against common web vulnerabilities
//! including clickjacking, MIME sniffing, XSS, and other attacks.

use axum::{
    body::Body,
    http::{HeaderValue, Request, Response},
    middleware::Next,
};
use tracing::{debug, info};

/// Security headers middleware function
pub async fn security_headers_middleware<B>(
    request: Request<B>,
    next: Next<B>,
) -> Response<Body> {
    let mut response = next.run(request).await;
    
    add_security_headers(&mut response);
    
    response
}

/// Add comprehensive security headers to response
fn add_security_headers(response: &mut Response<Body>) {
    let headers = response.headers_mut();
    
    // X-Frame-Options: Prevent clickjacking attacks
    headers.insert(
        "X-Frame-Options",
        HeaderValue::from_static("DENY")
    );
    
    // X-Content-Type-Options: Prevent MIME sniffing
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff")
    );
    
    // X-XSS-Protection: Enable XSS filtering (legacy browsers)
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block")
    );
    
    // Referrer-Policy: Control referrer information
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin")
    );
    
    // Permissions-Policy: Restrict access to browser features
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=(), payment=(), usb=()")
    );
    
    // Content Security Policy: Prevent XSS and injection attacks
    let csp = build_content_security_policy();
    if let Ok(csp_value) = HeaderValue::from_str(&csp) {
        headers.insert("Content-Security-Policy", csp_value);
    }
    
    // HSTS (HTTP Strict Transport Security) - only in production with HTTPS
    if should_add_hsts() {
        headers.insert(
            "Strict-Transport-Security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload")
        );
        info!("🔒 HSTS header added for HTTPS production environment");
    }
    
    // Hide server information
    headers.insert(
        "Server",
        HeaderValue::from_static("Aframp API")
    );
    
    // Remove potentially revealing headers
    headers.remove("X-Powered-By");
    headers.remove("Server");
    
    // Add custom server header
    headers.insert(
        "Server",
        HeaderValue::from_static("Aframp API")
    );
    
    // Cache control for security-sensitive responses
    if is_sensitive_endpoint(response) {
        headers.insert(
            "Cache-Control",
            HeaderValue::from_static("no-store, no-cache, must-revalidate, private")
        );
        headers.insert(
            "Pragma",
            HeaderValue::from_static("no-cache")
        );
    }
    
    debug!("🛡️  Security headers added to response");
}

/// Build Content Security Policy header value
fn build_content_security_policy() -> String {
    let mut csp_directives = vec![
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'", // Allow inline styles for API responses
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self'",
        "media-src 'none'",
        "object-src 'none'",
        "child-src 'none'",
        "frame-src 'none'",
        "worker-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "base-uri 'self'",
        "manifest-src 'self'",
    ];
    
    // In development, allow additional sources for debugging
    if is_development_environment() {
        csp_directives.push("script-src 'self' 'unsafe-eval'"); // For dev tools
        info!("🛠️  Development CSP: Allowing unsafe-eval for debugging");
    }
    
    csp_directives.join("; ")
}

/// Check if HSTS should be added (production + HTTPS)
fn should_add_hsts() -> bool {
    let environment = std::env::var("ENVIRONMENT")
        .or_else(|_| std::env::var("APP_ENV"))
        .unwrap_or_else(|_| "development".to_string());
    
    let is_production = environment.to_lowercase() == "production";
    let is_https = is_https_environment();
    
    is_production && is_https
}

/// Check if the current environment is using HTTPS
fn is_https_environment() -> bool {
    // Check various environment variables that might indicate HTTPS
    std::env::var("HTTPS").unwrap_or_default().to_lowercase() == "true"
        || std::env::var("TLS_ENABLED").unwrap_or_default().to_lowercase() == "true"
        || std::env::var("SSL_ENABLED").unwrap_or_default().to_lowercase() == "true"
        || std::env::var("SERVER_URL")
            .unwrap_or_default()
            .starts_with("https://")
}

/// Check if this is a development environment
fn is_development_environment() -> bool {
    let environment = std::env::var("ENVIRONMENT")
        .or_else(|_| std::env::var("APP_ENV"))
        .unwrap_or_else(|_| "development".to_string());
    
    matches!(environment.to_lowercase().as_str(), "development" | "dev" | "local")
}

/// Check if the response is from a security-sensitive endpoint
fn is_sensitive_endpoint(response: &Response<Body>) -> bool {
    // Check if this response should have strict cache control
    // This is a simple heuristic - in practice, you might want to check the request path
    
    // For now, apply strict caching to all API responses
    // You can customize this based on your specific needs
    true
}

/// Security configuration structure for advanced settings
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub enable_hsts: bool,
    pub hsts_max_age: u32,
    pub enable_csp: bool,
    pub custom_csp: Option<String>,
    pub hide_server_header: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_hsts: true,
            hsts_max_age: 31536000, // 1 year
            enable_csp: true,
            custom_csp: None,
            hide_server_header: false,
        }
    }
}

impl SecurityConfig {
    /// Create security configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            enable_hsts: std::env::var("SECURITY_ENABLE_HSTS")
                .unwrap_or_else(|_| "true".to_string())
                .to_lowercase() == "true",
            hsts_max_age: std::env::var("SECURITY_HSTS_MAX_AGE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(31536000),
            enable_csp: std::env::var("SECURITY_ENABLE_CSP")
                .unwrap_or_else(|_| "true".to_string())
                .to_lowercase() == "true",
            custom_csp: std::env::var("SECURITY_CUSTOM_CSP").ok(),
            hide_server_header: std::env::var("SECURITY_HIDE_SERVER")
                .unwrap_or_else(|_| "false".to_string())
                .to_lowercase() == "true",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    
    #[test]
    fn test_security_config_from_env() {
        // Test default configuration
        let config = SecurityConfig::default();
        assert!(config.enable_hsts);
        assert_eq!(config.hsts_max_age, 31536000);
        assert!(config.enable_csp);
        
        // Test environment-based configuration
        std::env::set_var("SECURITY_ENABLE_HSTS", "false");
        std::env::set_var("SECURITY_HSTS_MAX_AGE", "86400");
        let config = SecurityConfig::from_env();
        assert!(!config.enable_hsts);
        assert_eq!(config.hsts_max_age, 86400);
    }
    
    #[test]
    fn test_csp_building() {
        let csp = build_content_security_policy();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("object-src 'none'"));
    }
    
    #[test]
    fn test_hsts_conditions() {
        // Test production + HTTPS
        std::env::set_var("ENVIRONMENT", "production");
        std::env::set_var("HTTPS", "true");
        assert!(should_add_hsts());
        
        // Test development
        std::env::set_var("ENVIRONMENT", "development");
        assert!(!should_add_hsts());
    }
}