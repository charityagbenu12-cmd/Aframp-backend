//! HTTP handlers for API key rotation & expiry management (Issue #137).
//!
//! Consumer endpoints:
//!   POST /api/developer/keys/:key_id/rotate
//!   POST /api/developer/keys/:key_id/complete-rotation
//!
//! Admin endpoints:
//!   POST /api/admin/consumers/:consumer_id/keys/:key_id/rotate

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::services::key_rotation::{KeyRotationService, RotationError};

// ─── State ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct KeyRotationState {
    pub db: Arc<PgPool>,
}

// ─── Request / Response types ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AdminRotateRequest {
    /// When true, bypasses grace period and immediately invalidates the old key.
    #[serde(default)]
    pub forced: bool,
}

#[derive(Serialize)]
pub struct RotateResponse {
    pub rotation_id: Uuid,
    pub new_key_id: Uuid,
    /// Plaintext key — returned exactly once.
    pub new_key: String,
    pub grace_period_end: DateTime<Utc>,
    pub message: String,
}

#[derive(Serialize)]
struct ApiError {
    error: ApiErrorDetail,
}

#[derive(Serialize)]
struct ApiErrorDetail {
    code: String,
    message: String,
}

fn err_resp(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(ApiError {
            error: ApiErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
        .into_response()
}

fn map_err(e: RotationError) -> Response {
    match e {
        RotationError::KeyNotFound => {
            err_resp(StatusCode::NOT_FOUND, "KEY_NOT_FOUND", "API key not found")
        }
        RotationError::KeyInactive => err_resp(
            StatusCode::UNPROCESSABLE_ENTITY,
            "KEY_INACTIVE",
            "API key is already inactive",
        ),
        RotationError::RotationAlreadyActive => err_resp(
            StatusCode::CONFLICT,
            "ROTATION_ALREADY_ACTIVE",
            "An active rotation already exists for this key. Complete it first.",
        ),
        RotationError::NoActiveRotation => err_resp(
            StatusCode::NOT_FOUND,
            "NO_ACTIVE_ROTATION",
            "No active rotation found for this key",
        ),
        RotationError::LifetimeExceedsMax { requested, max, consumer_type } => {
            let msg = format!(
                "Requested lifetime of {} days exceeds the maximum of {} days for consumer type '{}'",
                requested, max, consumer_type
            );
            err_resp(StatusCode::UNPROCESSABLE_ENTITY, "LIFETIME_EXCEEDS_MAX", &msg)
        }
        RotationError::MissingExpiry => err_resp(
            StatusCode::UNPROCESSABLE_ENTITY,
            "MISSING_EXPIRY",
            "Every API key must have an explicit expiry",
        ),
        RotationError::Database(_) => err_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "An internal error occurred",
        ),
    }
}

// ─── Consumer: rotate own key ─────────────────────────────────────────────────

/// POST /api/developer/keys/:key_id/rotate
pub async fn rotate_key(
    State(state): State<KeyRotationState>,
    Path(key_id): Path<Uuid>,
) -> Response {
    let service = KeyRotationService::new((*state.db).clone());
    let initiated_by = format!("consumer:key:{}", key_id);

    match service.rotate_key(key_id, &initiated_by, false).await {
        Ok(result) => (
            StatusCode::CREATED,
            Json(RotateResponse {
                rotation_id: result.rotation_id,
                new_key_id: result.new_key_id,
                new_key: result.new_key_plaintext,
                grace_period_end: result.grace_period_end,
                message: format!(
                    "Key rotated. Both keys are valid until {}. \
                     Call complete-rotation to invalidate the old key immediately.",
                    result.grace_period_end.format("%Y-%m-%dT%H:%M:%SZ")
                ),
            }),
        )
            .into_response(),
        Err(e) => map_err(e),
    }
}

/// POST /api/developer/keys/:key_id/complete-rotation
pub async fn complete_rotation(
    State(state): State<KeyRotationState>,
    Path(key_id): Path<Uuid>,
) -> Response {
    let service = KeyRotationService::new((*state.db).clone());
    let initiated_by = format!("consumer:key:{}", key_id);

    match service.complete_rotation(key_id, &initiated_by).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "message": "Rotation completed. The old key has been invalidated."
            })),
        )
            .into_response(),
        Err(e) => map_err(e),
    }
}

// ─── Admin: rotate any consumer key ──────────────────────────────────────────

/// POST /api/admin/consumers/:consumer_id/keys/:key_id/rotate
///
/// Pass `{"forced": true}` to bypass the grace period and immediately
/// invalidate the old key (used in suspected compromise scenarios).
pub async fn admin_rotate_key(
    State(state): State<KeyRotationState>,
    Path((consumer_id, key_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<AdminRotateRequest>,
) -> Response {
    let service = KeyRotationService::new((*state.db).clone());
    let initiated_by = format!("admin:consumer:{}", consumer_id);

    match service.rotate_key(key_id, &initiated_by, body.forced).await {
        Ok(result) => {
            let msg = if body.forced {
                "Forced rotation complete. The old key has been immediately invalidated. \
                 A security notification has been queued for the consumer."
                    .to_string()
            } else {
                format!(
                    "Key rotated. Grace period active until {}.",
                    result.grace_period_end.format("%Y-%m-%dT%H:%M:%SZ")
                )
            };
            (
                StatusCode::CREATED,
                Json(RotateResponse {
                    rotation_id: result.rotation_id,
                    new_key_id: result.new_key_id,
                    new_key: result.new_key_plaintext,
                    grace_period_end: result.grace_period_end,
                    message: msg,
                }),
            )
                .into_response()
        }
        Err(e) => map_err(e),
    }
}

// ─── Routers ──────────────────────────────────────────────────────────────────

pub fn developer_rotation_router(state: KeyRotationState) -> axum::Router {
    use axum::routing::post;
    axum::Router::new()
        .route("/api/developer/keys/:key_id/rotate", post(rotate_key))
        .route(
            "/api/developer/keys/:key_id/complete-rotation",
            post(complete_rotation),
        )
        .with_state(state)
}

pub fn admin_rotation_router(state: KeyRotationState) -> axum::Router {
    use axum::routing::post;
    axum::Router::new()
        .route(
            "/api/admin/consumers/:consumer_id/keys/:key_id/rotate",
            post(admin_rotate_key),
        )
        .with_state(state)
}
