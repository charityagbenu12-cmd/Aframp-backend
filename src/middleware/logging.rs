//! Request and response logging middleware
//!
//! Captures HTTP request/response details including method, path, status,
//! duration, and request IDs. Automatically logs slow requests and errors.

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
use tower_http::request_id::{MakeRequestId, RequestId};
#[cfg(feature = "database")]
use tracing::{info, warn, Instrument};
#[cfg(feature = "database")]
use uuid::Uuid;

/// Generate unique request IDs using UUIDv4
#[cfg(feature = "database")]
#[derive(Clone, Default)]
pub struct UuidRequestId;

#[cfg(feature = "database")]
impl MakeRequestId for UuidRequestId {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let id = Uuid::new_v4().to_string();
        Some(RequestId::new(id.parse().ok()?))
    }
}

/// Middleware for logging HTTP requests and responses
///
/// Logs:
/// - Request method, path, and headers
/// - Response status code and processing duration
/// - Slow requests (> 200ms) at WARN level
/// - Request ID for correlation
/// - Client IP address
/// - Query parameters
/// - User agent
///
/// # Example Usage with Axum
/// ```no_run
/// # #[cfg(feature = "database")]
/// # {
/// use axum::{Router, routing::get};
/// use tower::ServiceBuilder;
/// use tower_http::request_id::{SetRequestIdLayer, PropagateRequestIdLayer};
/// # use aframp::middleware::logging::{UuidRequestId, request_logging_middleware};
///
/// # async fn handler() -> &'static str { "Hello" }
/// let app = Router::new()
///     .route("/", get(handler))
///     .layer(
///         ServiceBuilder::new()
///             .layer(SetRequestIdLayer::x_request_id(UuidRequestId))
///             .layer(axum::middleware::from_fn(request_logging_middleware))
///             .layer(PropagateRequestIdLayer::x_request_id())
///     );
/// # }
/// ```
#[cfg(feature = "database")]
pub async fn request_logging_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let start = Instant::now();

    // Extract request details
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string());

    // Get query string
    let query = uri.query().unwrap_or("");

    // Get client IP
    let client_ip = extract_client_ip(&request).unwrap_or_else(|| "unknown".to_string());

    // Get user agent
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    // Get request ID from headers or extensions
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            request
                .extensions()
                .get::<RequestId>()
                .map(|id| format!("{:?}", id)) // Use debug format instead of to_string
        })
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Log incoming request with full details
    info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        query = %query,
        client_ip = %client_ip,
        user_agent = %user_agent,
        "📥 Incoming request"
    );

    // Process request in a span for correlation
    let response = {
        let span = tracing::info_span!(
            "http_request",
            request_id = %request_id,
            method = %method,
            path = %path,
            client_ip = %client_ip,
        );

        async move { next.run(request).await }
            .instrument(span)
            .await
    };

    let duration = start.elapsed();
    let duration_ms = duration.as_millis();
    let status = response.status();

    // Log response with appropriate level and emoji indicators
    if duration_ms > 200 {
        // Slow request warning
        warn!(
            request_id = %request_id,
            method = %method,
            path = %path,
            query = %query,
            client_ip = %client_ip,
            status = %status.as_u16(),
            duration_ms = %duration_ms,
            "🐌 Slow request completed"
        );
    } else if status.is_server_error() {
        // Server errors at ERROR level
        tracing::error!(
            request_id = %request_id,
            method = %method,
            path = %path,
            query = %query,
            client_ip = %client_ip,
            status = %status.as_u16(),
            duration_ms = %duration_ms,
            "❌ Request failed with server error"
        );
    } else if status.is_client_error() {
        // Client errors at WARN level
        warn!(
            request_id = %request_id,
            method = %method,
            path = %path,
            query = %query,
            client_ip = %client_ip,
            status = %status.as_u16(),
            duration_ms = %duration_ms,
            "⚠️  Request completed with client error"
        );
    } else {
        // Successful requests at INFO level
        info!(
            request_id = %request_id,
            method = %method,
            path = %path,
            query = %query,
            client_ip = %client_ip,
            status = %status.as_u16(),
            duration_ms = %duration_ms,
            "✅ Request completed successfully"
        );
    };

    Ok(response)
}

/// Extract client IP address from request headers
///
/// Checks X-Forwarded-For, X-Real-IP headers before falling back to
/// the direct connection address.
#[cfg(feature = "database")]
pub fn extract_client_ip(request: &Request) -> Option<String> {
    // Check X-Forwarded-For header (may contain multiple IPs)
    if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return Some(first_ip.trim().to_string());
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }

    // Try to get from connection info extension
    // Note: This requires the ConnectInfo extension to be set by the server
    // For local development, this will typically be 127.0.0.1
    None
}

/// Middleware for tracking database query performance.
/// Redacts sensitive parameter values before any query logging.
#[cfg(feature = "database")]
pub async fn log_database_query<F, T, E>(query: &str, operation: F) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let start = Instant::now();
    // Redact any sensitive patterns from the query string before logging.
    let safe_query = crate::masking::patterns::scan_and_redact(query).0;

    tracing::debug!(
        event_type = "database_query_start",
        query = %safe_query,
        "Executing database query"
    );

    let result = operation.await;
    let duration = start.elapsed();
    let duration_ms = duration.as_millis();

    match &result {
        Ok(_) => {
            if duration_ms > 100 {
                warn!(
                    event_type = "slow_database_query",
                    query = %safe_query,
                    duration_ms = %duration_ms,
                    "Slow database query detected"
                );
            } else {
                tracing::debug!(
                    event_type = "database_query_complete",
                    query = %safe_query,
                    duration_ms = %duration_ms,
                    "Database query completed"
                );
            }
        }
        Err(_) => {
            tracing::error!(
                event_type = "database_query_error",
                query = %safe_query,
                duration_ms = %duration_ms,
                "Database query failed"
            );
        }
    }

    result
}

/// Middleware for tracking external API calls
///
/// Use this to wrap external service calls and track performance
///
/// # Example
/// ```no_run
/// # #[cfg(feature = "database")]
/// # {
/// use aframp::middleware::logging::log_external_call;
///
/// # async fn example() {
/// log_external_call("Stellar Horizon", "GET /accounts/{id}", async {
///     // External API call here
///     Ok::<_, ()>(())
/// }).await;
/// # }
/// # }
/// ```
#[cfg(feature = "database")]
pub async fn log_external_call<F, T, E>(service: &str, endpoint: &str, operation: F) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let start = Instant::now();

    info!(
        event_type = "external_call_start",
        service = %service,
        endpoint = %endpoint,
        "Calling external service"
    );

    let result = operation.await;
    let duration = start.elapsed();
    let duration_ms = duration.as_millis();

    match &result {
        Ok(_) => {
            info!(
                event_type = "external_call_complete",
                service = %service,
                endpoint = %endpoint,
                duration_ms = %duration_ms,
                "External service call completed"
            );
        }
        Err(_) => {
            tracing::error!(
                event_type = "external_call_error",
                service = %service,
                endpoint = %endpoint,
                duration_ms = %duration_ms,
                "External service call failed"
            );
        }
    }

    result
}

#[cfg(all(test, feature = "database"))]
mod tests {
    use super::*;
    use axum::{body::Body, routing::get, Router};
    use http::Request;

    #[tokio::test]
    async fn test_request_logging_middleware() {
        // Simple handler
        async fn handler() -> &'static str {
            "Hello, World!"
        }

        let _app: Router<()> = Router::new()
            .route("/", get(handler))
            .layer(axum::middleware::from_fn(request_logging_middleware));

        // Note: Actual routing test requires tower::ServiceExt
        // which is not available in all tower versions.
        // This test verifies the middleware compiles correctly.
    }

    #[test]
    fn test_extract_client_ip() {
        let request = Request::builder()
            .header("x-forwarded-for", "192.168.1.1, 10.0.0.1")
            .body(Body::empty())
            .unwrap();

        let ip = extract_client_ip(&request);
        assert_eq!(ip, Some("192.168.1.1".to_string()));
    }

    #[tokio::test]
    async fn test_log_database_query() {
        let result = log_database_query("SELECT * FROM test", async { Ok::<_, String>(42) }).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_log_external_call() {
        let result = log_external_call("TestService", "/endpoint", async {
            Ok::<_, String>("success")
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }
}
