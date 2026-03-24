//! Admin endpoints for API key scope management (Issue #132).
//!
//! Routes:
//!   GET  /api/admin/scopes                                         — list all defined scopes
//!   GET  /api/admin/consumers/:consumer_id/keys/:key_id/scopes     — list scopes for a key
//!   PATCH /api/admin/consumers/:consumer_id/keys/:key_id/scopes    — update scopes for a key

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

// ─── State ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ScopesState {
    pub db: Arc<PgPool>,
}

// ─── Models ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ScopeRow {
    pub name: String,
    pub description: String,
    pub category: String,
    pub applicable_consumer_types: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScopesListResponse {
    pub scopes: Vec<ScopeRow>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct KeyScopesResponse {
    pub key_id: Uuid,
    pub consumer_id: Uuid,
    pub consumer_type: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateScopesRequest {
    /// Complete list of scopes to assign — replaces all existing scopes for this key.
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: ErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
        .into_response()
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// GET /api/admin/scopes
///
/// Returns the full platform scope catalogue with descriptions and applicable
/// consumer types. Requires `admin:consumers` scope.
pub async fn list_scopes(State(state): State<ScopesState>) -> Response {
    info!("Admin: listing all platform scopes");

    let rows = sqlx::query!(
        r#"
        SELECT name, description, category, applicable_consumer_types
        FROM scopes
        ORDER BY category, name
        "#
    )
    .fetch_all(state.db.as_ref())
    .await;

    match rows {
        Ok(rows) => {
            let scopes: Vec<ScopeRow> = rows
                .into_iter()
                .map(|r| ScopeRow {
                    name: r.name,
                    description: r.description,
                    category: r.category,
                    applicable_consumer_types: r.applicable_consumer_types.unwrap_or_default(),
                })
                .collect();
            let total = scopes.len();
            (StatusCode::OK, Json(ScopesListResponse { scopes, total })).into_response()
        }
        Err(e) => {
            error!("Failed to fetch scopes: {}", e);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "Failed to retrieve scopes",
            )
        }
    }
}

/// GET /api/admin/consumers/:consumer_id/keys/:key_id/scopes
///
/// Returns scopes granted to a specific API key.
/// Requires `admin:consumers` scope.
pub async fn get_key_scopes(
    State(state): State<ScopesState>,
    Path((consumer_id, key_id)): Path<(Uuid, Uuid)>,
) -> Response {
    info!(
        consumer_id = %consumer_id,
        key_id = %key_id,
        "Admin: fetching scopes for key"
    );

    // Verify the key belongs to the consumer
    let key = sqlx::query!(
        r#"
        SELECT ak.id, ak.consumer_id, c.consumer_type
        FROM api_keys ak
        JOIN consumers c ON c.id = ak.consumer_id
        WHERE ak.id = $1 AND ak.consumer_id = $2 AND ak.is_active = TRUE
        "#,
        key_id,
        consumer_id,
    )
    .fetch_optional(state.db.as_ref())
    .await;

    match key {
        Err(e) => {
            error!("DB error fetching key: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "Database error",
            );
        }
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "KEY_NOT_FOUND",
                "API key not found or does not belong to this consumer",
            );
        }
        Ok(Some(key_row)) => {
            let scopes = sqlx::query_scalar!(
                r#"SELECT scope_name FROM key_scopes WHERE api_key_id = $1 ORDER BY scope_name"#,
                key_id
            )
            .fetch_all(state.db.as_ref())
            .await;

            match scopes {
                Ok(scope_names) => (
                    StatusCode::OK,
                    Json(KeyScopesResponse {
                        key_id: key_row.id,
                        consumer_id: key_row.consumer_id,
                        consumer_type: key_row.consumer_type,
                        scopes: scope_names,
                    }),
                )
                    .into_response(),
                Err(e) => {
                    error!("Failed to fetch key scopes: {}", e);
                    error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "DB_ERROR",
                        "Failed to retrieve key scopes",
                    )
                }
            }
        }
    }
}

/// PATCH /api/admin/consumers/:consumer_id/keys/:key_id/scopes
///
/// Replaces all scope grants for a specific API key.
/// Enforces that no scope beyond the consumer type's permitted scopes can be granted.
/// Requires `admin:consumers` scope.
pub async fn update_key_scopes(
    State(state): State<ScopesState>,
    Path((consumer_id, key_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateScopesRequest>,
) -> Response {
    info!(
        consumer_id = %consumer_id,
        key_id = %key_id,
        requested_scopes = ?body.scopes,
        "Admin: updating scopes for key"
    );

    // Fetch key + consumer type
    let key = sqlx::query!(
        r#"
        SELECT ak.id, c.consumer_type
        FROM api_keys ak
        JOIN consumers c ON c.id = ak.consumer_id
        WHERE ak.id = $1 AND ak.consumer_id = $2 AND ak.is_active = TRUE
        "#,
        key_id,
        consumer_id,
    )
    .fetch_optional(state.db.as_ref())
    .await;

    let key_row = match key {
        Err(e) => {
            error!("DB error: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "Database error",
            );
        }
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "KEY_NOT_FOUND",
                "API key not found or does not belong to this consumer",
            );
        }
        Ok(Some(r)) => r,
    };

    // Fetch permitted scopes for this consumer type
    let permitted: Vec<String> = sqlx::query_scalar!(
        r#"SELECT scope_name FROM consumer_type_profiles WHERE consumer_type = $1"#,
        key_row.consumer_type
    )
    .fetch_all(state.db.as_ref())
    .await
    .unwrap_or_default();

    // Validate — no requested scope may exceed the consumer type's permitted set
    let over_privileged: Vec<&String> = body
        .scopes
        .iter()
        .filter(|s| !permitted.contains(s))
        .collect();

    if !over_privileged.is_empty() {
        warn!(
            consumer_type = %key_row.consumer_type,
            over_privileged = ?over_privileged,
            "Rejected over-privileged scope assignment"
        );
        return error_response(
            StatusCode::FORBIDDEN,
            "OVER_PRIVILEGED_SCOPES",
            &format!(
                "Scopes {:?} are not permitted for consumer type '{}'",
                over_privileged, key_row.consumer_type
            ),
        );
    }

    // Replace scopes atomically
    let mut tx = match state.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to begin transaction: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "Database error",
            );
        }
    };

    // Delete existing scope grants
    if let Err(e) =
        sqlx::query!("DELETE FROM key_scopes WHERE api_key_id = $1", key_id)
            .execute(&mut *tx)
            .await
    {
        error!("Failed to delete existing scopes: {}", e);
        let _ = tx.rollback().await;
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            "Failed to update scopes",
        );
    }

    // Insert new scope grants
    for scope in &body.scopes {
        if let Err(e) = sqlx::query!(
            r#"INSERT INTO key_scopes (api_key_id, scope_name) VALUES ($1, $2)"#,
            key_id,
            scope
        )
        .execute(&mut *tx)
        .await
        {
            error!("Failed to insert scope {}: {}", scope, e);
            let _ = tx.rollback().await;
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                "Failed to update scopes",
            );
        }
    }

    // Audit log — record the grant action
    for scope in &body.scopes {
        let _ = sqlx::query!(
            r#"
            INSERT INTO scope_audit_log (api_key_id, consumer_id, action, scope_name, performed_by)
            VALUES ($1, $2, 'grant', $3, 'admin')
            "#,
            key_id,
            consumer_id,
            scope
        )
        .execute(&mut *tx)
        .await;
    }

    if let Err(e) = tx.commit().await {
        error!("Failed to commit scope update: {}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERROR",
            "Failed to commit scope update",
        );
    }

    info!(
        key_id = %key_id,
        scopes = ?body.scopes,
        "Scopes updated successfully"
    );

    (
        StatusCode::OK,
        Json(KeyScopesResponse {
            key_id,
            consumer_id,
            consumer_type: key_row.consumer_type,
            scopes: body.scopes,
        }),
    )
        .into_response()
}
