use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::post,
    Router,
};
use Bitmesh_backend::middleware::request_integrity::{
    request_integrity_middleware, IntegrityEndpoint, RequestIntegrityState,
};
use serde_json::{json, Value};
use tower::util::ServiceExt;

async fn ok_handler() -> impl IntoResponse {
    StatusCode::OK
}

#[tokio::test]
async fn batch_fiat_unknown_field_is_rejected() {
    let app = Router::new().route(
        "/batch",
        post(ok_handler).route_layer(from_fn_with_state(
            RequestIntegrityState {
                endpoint: IntegrityEndpoint::BatchFiatPayout,
                db: None,
                cache: None,
            },
            request_integrity_middleware,
        )),
    );

    let response = app
        .oneshot(
            Request::post("/batch")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "payouts": [{
                            "bank_account_number": "0123456789",
                            "bank_code": "044",
                            "amount_ngn": "1200.00",
                            "reference": "batch-1",
                            "unexpected": "field"
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"]["code"], "UNEXPECTED_FIELD");
}

#[tokio::test]
async fn batch_fiat_valid_payload_reaches_handler() {
    let app = Router::new().route(
        "/batch",
        post(ok_handler).route_layer(from_fn_with_state(
            RequestIntegrityState {
                endpoint: IntegrityEndpoint::BatchFiatPayout,
                db: None,
                cache: None,
            },
            request_integrity_middleware,
        )),
    );

    let response = app
        .oneshot(
            Request::post("/batch")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "payouts": [{
                            "bank_account_number": "0123456789",
                            "bank_code": "044",
                            "amount_ngn": "1200.00",
                            "reference": "batch-1"
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
