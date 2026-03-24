//! Prometheus request metrics middleware.
//!
//! Tracks:
//! - `aframp_http_requests_total`          (method, route, status_code)
//! - `aframp_http_request_duration_seconds` (method, route)
//! - `aframp_http_requests_in_flight`       (route)

#[cfg(feature = "database")]
use axum::{
    extract::{MatchedPath, Request},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
#[cfg(feature = "database")]
use std::time::Instant;

#[cfg(feature = "database")]
pub async fn metrics_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    let method = request.method().to_string();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    // Increment in-flight gauge
    crate::metrics::http::requests_in_flight()
        .with_label_values(&[&route])
        .inc();

    let start = Instant::now();
    let response = next.run(request).await;
    let elapsed = start.elapsed().as_secs_f64();

    let status = response.status().as_u16().to_string();

    // Decrement in-flight gauge
    crate::metrics::http::requests_in_flight()
        .with_label_values(&[&route])
        .dec();

    // Increment request counter
    crate::metrics::http::requests_total()
        .with_label_values(&[&method, &route, &status])
        .inc();

    // Observe request duration
    crate::metrics::http::request_duration_seconds()
        .with_label_values(&[&method, &route])
        .observe(elapsed);

    Ok(response)
}
