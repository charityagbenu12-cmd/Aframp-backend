//! Emergency request queue for essential financial endpoints.
//!
//! In emergency mode, essential endpoint requests are queued up to a
//! configurable maximum depth. When the queue is full, the oldest queued
//! request is shed (FIFO shedding) and a 503 is returned to the shed request.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::json;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tracing::warn;

/// A queued request waiting to be processed.
struct QueuedRequest {
    /// The path of the request (for metrics/logging).
    path: String,
    /// Enqueued at timestamp.
    enqueued_at: chrono::DateTime<Utc>,
    /// Channel to send the response back to the waiting middleware.
    responder: oneshot::Sender<Response>,
    /// The actual request to forward.
    request: Request<Body>,
}

/// Thread-safe emergency request queue.
#[derive(Clone)]
pub struct EmergencyQueue {
    inner: Arc<Mutex<VecDeque<QueuedRequest>>>,
    max_depth: usize,
}

impl EmergencyQueue {
    pub fn new(max_depth: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(max_depth))),
            max_depth,
        }
    }

    /// Enqueue a request. If the queue is full, shed the oldest request first.
    ///
    /// Returns a receiver that will yield the response when the request is processed.
    pub async fn enqueue(
        &self,
        req: Request<Body>,
        path: String,
    ) -> oneshot::Receiver<Response> {
        let (tx, rx) = oneshot::channel();

        let mut queue = self.inner.lock().await;

        // Shed oldest if at capacity
        if queue.len() >= self.max_depth {
            if let Some(oldest) = queue.pop_front() {
                let elapsed_ms = (Utc::now() - oldest.enqueued_at)
                    .num_milliseconds();

                warn!(
                    path = %oldest.path,
                    enqueued_ms_ago = elapsed_ms,
                    "emergency queue full — shedding oldest request"
                );

                crate::adaptive_rate_limit::metrics::request_shedding_total()
                    .with_label_values(&[&oldest.path])
                    .inc();

                // Send 503 to the shed request
                let shed_response = service_unavailable_response(
                    "Request shed from emergency queue due to capacity limit",
                    60,
                );
                let _ = oldest.responder.send(shed_response);
            }
        }

        queue.push_back(QueuedRequest {
            path,
            enqueued_at: Utc::now(),
            responder: tx,
            request: req,
        });

        rx
    }

    /// Current queue depth.
    pub async fn depth(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Drain and process all queued requests using the provided handler.
    ///
    /// Called by the middleware when the platform recovers from emergency mode.
    pub async fn drain_with<F, Fut>(&self, handler: F)
    where
        F: Fn(Request<Body>) -> Fut,
        Fut: std::future::Future<Output = Response>,
    {
        let mut queue = self.inner.lock().await;
        while let Some(queued) = queue.pop_front() {
            let response = handler(queued.request).await;
            let _ = queued.responder.send(response);
        }
    }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

pub fn service_unavailable_response(message: &str, retry_after_secs: u64) -> Response {
    let mut res = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": {
                "code": "SERVICE_UNAVAILABLE",
                "message": message,
                "retry_after": retry_after_secs
            }
        })),
    )
        .into_response();
    res.headers_mut().insert(
        "Retry-After",
        retry_after_secs.to_string().parse().unwrap(),
    );
    res
}
