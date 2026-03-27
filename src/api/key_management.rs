//! Admin API endpoints for the platform key management framework.
//!
//! GET  /api/admin/security/keys              — paginated key catalogue
//! GET  /api/admin/security/keys/:key_id      — key detail + rotation history
//! POST /api/admin/security/keys/:key_id/revoke — emergency revocation

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sqlx::PgPool;

use crate::key_management::{
    catalogue::KeyCatalogueRepository,
    emergency::EmergencyRevocationService,
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct KeyManagementState {
    pub pool: Arc<PgPool>,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_per_page")]
    pub per_page: i64,
}

fn default_page() -> i64 { 1 }
fn default_per_page() -> i64 { 20 }

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub reason: String,
    /// Admin ID — in production extracted from the JWT; passed explicitly here.
    pub admin_id: String,
}

#[derive(Serialize)]
struct PaginatedKeys<T> {
    data: Vec<T>,
    total: i64,
    page: i64,
    per_page: i64,
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /api/admin/security/keys
pub async fn list_keys(
    State(state): State<KeyManagementState>,
    Query(params): Query<PaginationParams>,
) -> Response {
    let repo = KeyCatalogueRepository::new((*state.pool).clone());
    match repo.list(params.page, params.per_page).await {
        Ok((keys, total)) => Json(PaginatedKeys {
            data: keys,
            total,
            page: params.page,
            per_page: params.per_page,
        })
        .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// GET /api/admin/security/keys/:key_id
pub async fn get_key(
    State(state): State<KeyManagementState>,
    Path(key_id): Path<String>,
) -> Response {
    let repo = KeyCatalogueRepository::new((*state.pool).clone());

    let key = match repo.get_by_key_id(&key_id).await {
        Ok(k) => k,
        Err(crate::key_management::catalogue::CatalogueError::NotFound(_)) => {
            return err(StatusCode::NOT_FOUND, format!("Key '{key_id}' not found"))
        }
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let events = match repo.events_for_key(key.id).await {
        Ok(e) => e,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    Json(serde_json::json!({
        "key": key,
        "events": events,
    }))
    .into_response()
}

/// POST /api/admin/security/keys/:key_id/revoke
pub async fn revoke_key(
    State(state): State<KeyManagementState>,
    Path(key_id): Path<String>,
    Json(body): Json<RevokeRequest>,
) -> Response {
    if body.reason.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "reason is required");
    }

    let svc = EmergencyRevocationService::new((*state.pool).clone());
    match svc.revoke(&key_id, &body.admin_id, &body.reason).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(crate::key_management::emergency::RevocationError::NotFound(_)) => {
            err(StatusCode::NOT_FOUND, format!("Key '{key_id}' not found"))
        }
        Err(crate::key_management::emergency::RevocationError::AlreadyDestroyed) => {
            err(StatusCode::CONFLICT, "Key is already destroyed")
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
