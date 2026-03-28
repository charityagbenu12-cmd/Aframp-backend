use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use opentelemetry::trace::Status;
use tracing::Instrument;

use crate::telemetry::propagation::extract_context;

/// Axum middleware that:
///
/// 1. Extracts incoming W3C `traceparent` / `tracestate` headers.
/// 2. Opens a root span for the request labelled with HTTP method and route.
/// 3. Propagates the span through the request so all child spans are nested.
/// 4. Records the final HTTP status code and marks error spans accordingly.
pub async fn tracing_middleware(req: Request<Body>, next: Next) -> Response {
    // Extract upstream trace context (if any) from the inbound headers.
    let parent_cx = extract_context(req.headers());

    let method = req.method().to_string();
    // Use the matched route pattern when available (set by Axum's router).
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|mp| mp.as_str().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned());

    // Create root request span with standard HTTP semantic conventions.
    let span = tracing::info_span!(
        "http_request",
        otel.kind = "server",
        http.method = %method,
        http.route = %route,
        http.status_code = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
    );

    // Attach the upstream context so this span is a child of the caller's trace.
    {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        span.set_parent(parent_cx);
    }

    let response = next.run(req).instrument(span.clone()).await;

    let status = response.status();

    // Record the final status code on the span.
    span.record("http.status_code", status.as_u16());

    if status.is_server_error() {
        span.record("otel.status_code", "ERROR");
    } else {
        span.record("otel.status_code", "OK");
    }

    response
}

/// Re-exported as a named type so callers can reference it without importing
/// the middleware function directly.
pub use axum::middleware::from_fn as TracingMiddlewareLayer;