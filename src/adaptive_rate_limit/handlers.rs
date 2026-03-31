//! Admin HTTP handlers for adaptive rate limiting management.
//!
//! Endpoints:
//!   GET  /api/admin/adaptive-rate-limit/status   — current mode, signals, multipliers
//!   POST /api/admin/adaptive-rate-limit/override  — force a specific mode
//!   DELETE /api/admin/adaptive-rate-limit/override — release manual override

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

use crate::adaptive_rate_limit::{
    engine::AdaptiveRateLimitEngine,
    models::{AdaptationMode, AdminOverride},
};

/// Shared state for adaptive rate limit admin handlers.
#[derive(Clone)]
pub struct AdaptiveRateLimitAdminState {
    pub engine: Arc<AdaptiveRateLimitEngine>,
}

// ---------------------------------------------------------------------------
// GET /api/admin/adaptive-rate-limit/status
// ---------------------------------------------------------------------------

pub async fn get_status(
    State(state): State<AdaptiveRateLimitAdminState>,
) -> impl IntoResponse {
    let status = state.engine.status().await;
    (StatusCode::OK, Json(status))
}

// ---------------------------------------------------------------------------
// POST /api/admin/adaptive-rate-limit/override
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct OverrideRequest {
    /// Target mode: "normal" | "elevated" | "critical" | "emergency"
    pub mode: String,
    /// Identity of the admin setting the override (from auth context).
    pub set_by: Option<String>,
    /// Optional human-readable reason for the override.
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OverrideResponse {
    pub success: bool,
    pub message: String,
    pub mode: String,
}

pub async fn set_override(
    State(state): State<AdaptiveRateLimitAdminState>,
    Json(body): Json<OverrideRequest>,
) -> Response {
    let mode = match body.mode.as_str() {
        "normal" => AdaptationMode::Normal,
        "elevated" => AdaptationMode::Elevated,
        "critical" => AdaptationMode::Critical,
        "emergency" => AdaptationMode::Emergency,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": {
                        "code": "INVALID_MODE",
                        "message": format!(
                            "Unknown adaptation mode '{}'. \
                             Valid values: normal, elevated, critical, emergency",
                            other
                        )
                    }
                })),
            )
                .into_response();
        }
    };

    let set_by = body.set_by.unwrap_or_else(|| "admin".to_string());

    info!(
        mode = %mode,
        set_by = %set_by,
        reason = ?body.reason,
        "admin override requested"
    );

    state
        .engine
        .set_admin_override(AdminOverride {
            mode,
            set_by: set_by.clone(),
            reason: body.reason,
            set_at: chrono::Utc::now(),
        })
        .await;

    (
        StatusCode::OK,
        Json(OverrideResponse {
            success: true,
            message: format!("Adaptation mode forced to '{}'", mode),
            mode: mode.as_str().to_string(),
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/adaptive-rate-limit/override
// ---------------------------------------------------------------------------

pub async fn clear_override(
    State(state): State<AdaptiveRateLimitAdminState>,
) -> impl IntoResponse {
    state.engine.clear_admin_override().await;

    info!("admin override cleared");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "message": "Manual override released. Returning to signal-driven adaptation."
        })),
    )
}
