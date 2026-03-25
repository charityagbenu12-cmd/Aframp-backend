//! Integration tests for HMAC Request Signing middleware (Issue #139).
//!
//! These tests exercise the full Axum middleware stack using `tower::ServiceExt::oneshot`.
//! No external services are required — the key resolver is an in-memory closure.

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    middleware,
    response::IntoResponse,
    routing::post,
    Router,
};
use tower::ServiceExt;

use Bitmesh_backend::middleware::hmac_signing::{
    hmac_signing_middleware, sign_request, HmacAlgorithm, HmacSigningState,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SECRET: &[u8] = b"integration-test-secret";
const KEY_ID: &str = "key_integration";

fn build_router(enforce: bool) -> Router {
    let state = HmacSigningState {
        key_resolver: Arc::new(|key_id: &str| {
            if key_id == KEY_ID {
                Some(SECRET.to_vec())
            } else {
                None
            }
        }),
        enforce,
    };

    Router::new()
        .route("/transfer", post(|| async { "ok".into_response() }))
        .layer(middleware::from_fn_with_state(state, hmac_signing_middleware))
}

fn signed_request_with_body(body: &[u8], algorithm: HmacAlgorithm) -> Request<Body> {
    let timestamp = "1700000000";
    let headers = &[
        ("content-type", "application/json"),
        ("x-aframp-key-id", KEY_ID),
        ("x-aframp-timestamp", timestamp),
    ];
    let sig = sign_request(algorithm, "POST", "/transfer", "", headers, body, SECRET);

    Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("content-type", "application/json")
        .header("x-aframp-key-id", KEY_ID)
        .header("x-aframp-timestamp", timestamp)
        .header("x-aframp-signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap()
}

async fn response_code(router: Router, req: Request<Body>) -> StatusCode {
    router.oneshot(req).await.unwrap().status()
}

async fn response_error_code(router: Router, req: Request<Body>) -> String {
    let resp = router.oneshot(req).await.unwrap();
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["error"]["code"].as_str().unwrap_or("").to_string()
}

// ---------------------------------------------------------------------------
// Acceptance tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn correctly_signed_sha256_request_is_accepted() {
    let router = build_router(true);
    let req = signed_request_with_body(br#"{"amount":"100"}"#, HmacAlgorithm::Sha256);
    assert_eq!(response_code(router, req).await, StatusCode::OK);
}

#[tokio::test]
async fn correctly_signed_sha512_request_is_accepted() {
    let router = build_router(true);
    let req = signed_request_with_body(br#"{"amount":"100"}"#, HmacAlgorithm::Sha512);
    assert_eq!(response_code(router, req).await, StatusCode::OK);
}

#[tokio::test]
async fn correctly_signed_empty_body_is_accepted() {
    let router = build_router(true);
    let req = signed_request_with_body(b"", HmacAlgorithm::Sha256);
    assert_eq!(response_code(router, req).await, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Tampered body rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_body_is_rejected() {
    let router = build_router(true);

    // Sign with original body, send tampered body
    let timestamp = "1700000000";
    let headers = &[
        ("content-type", "application/json"),
        ("x-aframp-key-id", KEY_ID),
        ("x-aframp-timestamp", timestamp),
    ];
    let sig = sign_request(
        HmacAlgorithm::Sha256, "POST", "/transfer", "", headers,
        br#"{"amount":"100"}"#, SECRET,
    );

    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("content-type", "application/json")
        .header("x-aframp-key-id", KEY_ID)
        .header("x-aframp-timestamp", timestamp)
        .header("x-aframp-signature", sig)
        .body(Body::from(br#"{"amount":"9999"}"#.to_vec()))
        .unwrap();

    let code = response_error_code(router, req).await;
    assert_eq!(code, "SIGNATURE_MISMATCH");
}

// ---------------------------------------------------------------------------
// Tampered header rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_key_id_header_is_rejected() {
    let router = build_router(true);

    let timestamp = "1700000000";
    let body = br#"{"amount":"100"}"#;
    let headers = &[
        ("content-type", "application/json"),
        ("x-aframp-key-id", KEY_ID),
        ("x-aframp-timestamp", timestamp),
    ];
    let sig = sign_request(HmacAlgorithm::Sha256, "POST", "/transfer", "", headers, body, SECRET);

    // Send with a different key-id in the header (tampered)
    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("content-type", "application/json")
        .header("x-aframp-key-id", "key_EVIL")   // tampered
        .header("x-aframp-timestamp", timestamp)
        .header("x-aframp-signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap();

    // key_EVIL is unknown → UNKNOWN_KEY_ID
    let code = response_error_code(router, req).await;
    assert_eq!(code, "UNKNOWN_KEY_ID");
}

#[tokio::test]
async fn tampered_timestamp_header_is_rejected() {
    let router = build_router(true);

    let body = br#"{"amount":"100"}"#;
    let headers = &[
        ("content-type", "application/json"),
        ("x-aframp-key-id", KEY_ID),
        ("x-aframp-timestamp", "1700000000"),
    ];
    let sig = sign_request(HmacAlgorithm::Sha256, "POST", "/transfer", "", headers, body, SECRET);

    // Send with a different timestamp (tampered)
    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("content-type", "application/json")
        .header("x-aframp-key-id", KEY_ID)
        .header("x-aframp-timestamp", "9999999999")  // tampered
        .header("x-aframp-signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap();

    let code = response_error_code(router, req).await;
    assert_eq!(code, "SIGNATURE_MISMATCH");
}

// ---------------------------------------------------------------------------
// Missing / malformed header rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_signature_header_is_rejected() {
    let router = build_router(true);
    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("content-type", "application/json")
        .header("x-aframp-key-id", KEY_ID)
        .header("x-aframp-timestamp", "1700000000")
        .body(Body::empty())
        .unwrap();

    let code = response_error_code(router, req).await;
    assert_eq!(code, "MISSING_SIGNATURE");
}

#[tokio::test]
async fn missing_key_id_header_is_rejected() {
    let router = build_router(true);
    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("content-type", "application/json")
        .header("x-aframp-timestamp", "1700000000")
        .header("x-aframp-signature", "algorithm=HMAC-SHA256,timestamp=1700000000,signature=abc")
        .body(Body::empty())
        .unwrap();

    let code = response_error_code(router, req).await;
    assert_eq!(code, "MISSING_KEY_ID");
}

#[tokio::test]
async fn malformed_signature_header_is_rejected() {
    let router = build_router(true);
    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("content-type", "application/json")
        .header("x-aframp-key-id", KEY_ID)
        .header("x-aframp-timestamp", "1700000000")
        .header("x-aframp-signature", "not-a-valid-format")
        .body(Body::empty())
        .unwrap();

    let code = response_error_code(router, req).await;
    assert_eq!(code, "INVALID_SIGNATURE_FORMAT");
}

#[tokio::test]
async fn unknown_key_id_is_rejected() {
    let router = build_router(true);
    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("content-type", "application/json")
        .header("x-aframp-key-id", "key_unknown")
        .header("x-aframp-timestamp", "1700000000")
        .header("x-aframp-signature", "algorithm=HMAC-SHA256,timestamp=1700000000,signature=abc")
        .body(Body::empty())
        .unwrap();

    let code = response_error_code(router, req).await;
    assert_eq!(code, "UNKNOWN_KEY_ID");
}

// ---------------------------------------------------------------------------
// Enforcement disabled
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unsigned_request_passes_when_enforcement_disabled() {
    let router = build_router(false);
    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("content-type", "application/json")
        .header("x-aframp-key-id", KEY_ID)
        .header("x-aframp-timestamp", "1700000000")
        .body(Body::empty())
        .unwrap();

    assert_eq!(response_code(router, req).await, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Cross-algorithm rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sha512_signature_rejected_when_header_claims_sha256() {
    let router = build_router(true);

    let timestamp = "1700000000";
    let body = br#"{"amount":"100"}"#;
    let headers = &[
        ("content-type", "application/json"),
        ("x-aframp-key-id", KEY_ID),
        ("x-aframp-timestamp", timestamp),
    ];

    // Compute SHA-512 signature but claim SHA-256 in the header
    let real_sig = sign_request(HmacAlgorithm::Sha512, "POST", "/transfer", "", headers, body, SECRET);
    // Extract just the hex part and repackage with wrong algorithm label
    let hex_part = real_sig.split("signature=").nth(1).unwrap();
    let spoofed_header = format!("algorithm=HMAC-SHA256,timestamp={},signature={}", timestamp, hex_part);

    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("content-type", "application/json")
        .header("x-aframp-key-id", KEY_ID)
        .header("x-aframp-timestamp", timestamp)
        .header("x-aframp-signature", spoofed_header)
        .body(Body::from(body.to_vec()))
        .unwrap();

    let code = response_error_code(router, req).await;
    assert_eq!(code, "SIGNATURE_MISMATCH");
}
