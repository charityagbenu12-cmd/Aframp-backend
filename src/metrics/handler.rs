//! HTTP handler for the Prometheus /metrics scrape endpoint.

use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};

/// GET /metrics — returns all metrics in Prometheus text exposition format.
pub async fn metrics_handler() -> Response {
    let body = super::render();
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}
