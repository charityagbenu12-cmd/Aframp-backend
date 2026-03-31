//! HTTP handlers for the Corridor Router API.

use crate::corridors::router::models::*;
use crate::corridors::router::service::{CorridorRouterService, RouterError};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

pub struct CorridorRouterState {
    pub service: Arc<CorridorRouterService>,
}

// ── Generic wrappers ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize)]
pub struct ApiError {
    pub success: bool,
    pub code: String,
    pub error: String,
}

fn ok<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse { success: true, data, message: None })
}

fn ok_msg<T: Serialize>(data: T, msg: &str) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        success: true,
        data,
        message: Some(msg.to_string()),
    })
}

fn map_error(e: RouterError) -> (StatusCode, Json<ApiError>) {
    let (status, code) = match &e {
        RouterError::NotSupported(_, _) => (StatusCode::NOT_FOUND, "CORRIDOR_NOT_SUPPORTED"),
        RouterError::Suspended(_) => (StatusCode::FORBIDDEN, "CORRIDOR_SUSPENDED"),
        RouterError::BelowMinimum(_, _) => (StatusCode::UNPROCESSABLE_ENTITY, "BELOW_MINIMUM"),
        RouterError::ExceedsMaximum(_, _) => (StatusCode::UNPROCESSABLE_ENTITY, "EXCEEDS_MAXIMUM"),
        RouterError::UnsupportedDeliveryMethod(_) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "UNSUPPORTED_DELIVERY_METHOD")
        }
        RouterError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR"),
    };
    (
        status,
        Json(ApiError {
            success: false,
            code: code.to_string(),
            error: e.to_string(),
        }),
    )
}

// ── Public endpoints ──────────────────────────────────────────────────────────

/// POST /api/corridors/route
/// Resolve the best route for a transfer. Returns CORRIDOR_NOT_SUPPORTED
/// with 404 for unsupported country pairs.
pub async fn resolve_route_handler(
    State(state): State<Arc<CorridorRouterState>>,
    Json(req): Json<RouteRequest>,
) -> Result<Json<ApiResponse<RouteResponse>>, (StatusCode, Json<ApiError>)> {
    state
        .service
        .resolve_route(&req)
        .await
        .map(ok)
        .map_err(map_error)
}

/// GET /api/corridors
/// List all corridors (active and inactive).
pub async fn list_corridors_handler(
    State(state): State<Arc<CorridorRouterState>>,
) -> Result<Json<ApiResponse<Vec<CorridorConfig>>>, (StatusCode, Json<ApiError>)> {
    state
        .service
        .list_corridors()
        .await
        .map(ok)
        .map_err(map_error)
}

/// GET /api/corridors/:id
pub async fn get_corridor_handler(
    State(state): State<Arc<CorridorRouterState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<CorridorConfig>>, (StatusCode, Json<ApiError>)> {
    state
        .service
        .get_corridor(id)
        .await
        .map_err(map_error)?
        .map(ok)
        .ok_or_else(|| {
            map_error(RouterError::NotSupported(id.to_string(), String::new()))
        })
}

/// GET /api/corridors/:id/health
pub async fn get_health_handler(
    State(state): State<Arc<CorridorRouterState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<CorridorHealthSummary>>, (StatusCode, Json<ApiError>)> {
    state
        .service
        .get_health(id)
        .await
        .map(ok)
        .map_err(map_error)
}

// ── Admin endpoints ───────────────────────────────────────────────────────────

/// POST /api/admin/corridors
/// Create a new corridor without a service restart.
pub async fn create_corridor_handler(
    State(state): State<Arc<CorridorRouterState>>,
    Json(req): Json<CreateCorridorConfigRequest>,
) -> Result<(StatusCode, Json<ApiResponse<CorridorConfig>>), (StatusCode, Json<ApiError>)> {
    state
        .service
        .create_corridor(&req, None, None)
        .await
        .map(|c| (StatusCode::CREATED, ok_msg(c, "Corridor created")))
        .map_err(map_error)
}

/// PATCH /api/admin/corridors/:id
/// Update corridor config at runtime (no restart).
pub async fn update_corridor_handler(
    State(state): State<Arc<CorridorRouterState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCorridorConfigRequest>,
) -> Result<Json<ApiResponse<CorridorConfig>>, (StatusCode, Json<ApiError>)> {
    state
        .service
        .update_corridor(id, &req, None, None)
        .await
        .map(ok)
        .map_err(map_error)
}

/// POST /api/admin/corridors/:id/toggle
/// Kill-switch: instantly enable or disable a corridor.
pub async fn toggle_corridor_handler(
    State(state): State<Arc<CorridorRouterState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<ToggleCorridorRequest>,
) -> Result<Json<ApiResponse<CorridorConfig>>, (StatusCode, Json<ApiError>)> {
    let msg = if req.enabled {
        "Corridor enabled"
    } else {
        "Corridor suspended (kill-switch activated)"
    };

    state
        .service
        .toggle_corridor(id, &req, None)
        .await
        .map(|c| {
            Json(ApiResponse {
                success: true,
                data: c,
                message: Some(msg.to_string()),
            })
        })
        .map_err(map_error)
}
