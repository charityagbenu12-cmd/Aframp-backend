//! Integration tests for CORS and Security Headers middleware
//!
//! Tests the implementation of Issue #86 - CORS and Security Headers

use axum::{
    body::Body,
    http::{Request, StatusCode, Method},
    Router,
    routing::get,
    response::IntoResponse,
};
use tower::ServiceExt;
use tower::ServiceBuilder;

// Import the middleware modules
use crate::middleware::cors::{cors_middleware, CorsConfig};
use crate::middleware::security::security_headers_middleware;

async fn test_handler() -> impl IntoResponse {
    "OK"
}

fn create_test_app() -> Router {
    Router::new()
        .route("/test", get(test_handler))
        .layer(
            ServiceBuilder::new()
                .layer(axum::middleware::from_fn_with_state(
                    CorsConfig::from_env(),
                    cors_middleware,
                ))
                .layer(axum::middleware::from_fn(security_headers_middleware))
        )
}

#[tokio::test]
async fn test_cors_preflight_allowed_origin() {
    let app = create_test_app();
    
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/test")
        .header("Origin", "http://localhost:3000")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "Content-Type")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    
    let headers = response.headers();
    assert_eq!(
        headers.get("Access-Control-Allow-Origin").unwrap(),
        "http://localhost:3000"
    );
    assert!(headers.contains_key("Access-Control-Allow-Methods"));
    assert!(headers.contains_key("Access-Control-Allow-Headers"));
    assert_eq!(
        headers.get("Access-Control-Allow-Credentials").unwrap(),
        "true"
    );
}

#[tokio::test]
async fn test_cors_preflight_disallowed_origin() {
    let app = create_test_app();
    
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/test")
        .header("Origin", "https://malicious.com")
        .header("Access-Control-Request-Method", "POST")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    
    let headers = response.headers();
    // Should not have CORS headers for disallowed origin
    assert!(!headers.contains_key("Access-Control-Allow-Origin"));
}

#[tokio::test]
async fn test_cors_simple_request_allowed_origin() {
    let app = create_test_app();
    
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .header("Origin", "http://localhost:3000")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let headers = response.headers();
    assert_eq!(
        headers.get("Access-Control-Allow-Origin").unwrap(),
        "http://localhost:3000"
    );
    assert_eq!(
        headers.get("Access-Control-Allow-Credentials").unwrap(),
        "true"
    );
}

#[tokio::test]
async fn test_security_headers_present() {
    let app = create_test_app();
    
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let headers = response.headers();
    
    // Test security headers
    assert_eq!(headers.get("X-Frame-Options").unwrap(), "DENY");
    assert_eq!(headers.get("X-Content-Type-Options").unwrap(), "nosniff");
    assert_eq!(headers.get("X-XSS-Protection").unwrap(), "1; mode=block");
    assert_eq!(
        headers.get("Referrer-Policy").unwrap(),
        "strict-origin-when-cross-origin"
    );
    assert!(headers.contains_key("Permissions-Policy"));
    assert!(headers.contains_key("Content-Security-Policy"));
    assert_eq!(headers.get("Server").unwrap(), "Aframp API");
    
    // Ensure X-Powered-By is removed
    assert!(!headers.contains_key("X-Powered-By"));
}

#[tokio::test]
async fn test_hsts_not_added_in_development() {
    // Set development environment
    std::env::set_var("ENVIRONMENT", "development");
    
    let app = create_test_app();
    
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    let headers = response.headers();
    
    // HSTS should not be present in development
    assert!(!headers.contains_key("Strict-Transport-Security"));
}

#[tokio::test]
async fn test_cors_config_from_env() {
    // Test development environment
    std::env::set_var("ENVIRONMENT", "development");
    let config = CorsConfig::from_env();
    assert!(config.allowed_origins.contains(&"http://localhost:3000".to_string()));
    assert!(config.allow_credentials);
    
    // Test production environment
    std::env::set_var("ENVIRONMENT", "production");
    let config = CorsConfig::from_env();
    assert!(config.allowed_origins.contains(&"https://app.aframp.com".to_string()));
    assert!(!config.allowed_origins.contains(&"http://localhost:3000".to_string()));
}

#[tokio::test]
async fn test_custom_cors_origins() {
    // Test custom origins via environment variable
    std::env::set_var("CORS_ALLOWED_ORIGINS", "https://custom1.com,https://custom2.com");
    std::env::set_var("ENVIRONMENT", "production");
    
    let config = CorsConfig::from_env();
    assert!(config.allowed_origins.contains(&"https://custom1.com".to_string()));
    assert!(config.allowed_origins.contains(&"https://custom2.com".to_string()));
    assert!(config.allowed_origins.contains(&"https://app.aframp.com".to_string()));
}