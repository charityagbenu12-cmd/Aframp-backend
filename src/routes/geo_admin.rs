//! Geo-Restriction Admin API
//!
//! Admin endpoints for managing geographic access controls.

use crate::error::AppError;
use crate::middleware::auth::AdminAuth;
use crate::services::geo_restriction::GeoRestrictionService;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Admin API state
#[derive(Clone)]
pub struct GeoAdminState {
    pub geo_service: Arc<GeoRestrictionService>,
}

/// Country access policy response
#[derive(Debug, Serialize)]
pub struct CountryPolicyResponse {
    pub country_code: String,
    pub country_name: Option<String>,
    pub policy_type: String,
    pub region_code: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub updated_by: Uuid,
}

/// Consumer override response
#[derive(Debug, Serialize)]
pub struct ConsumerOverrideResponse {
    pub id: Uuid,
    pub consumer_id: Uuid,
    pub country_code: String,
    pub policy_type: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Uuid,
}

/// Update country policy request
#[derive(Debug, Deserialize)]
pub struct UpdateCountryPolicyRequest {
    pub policy_type: String, // "allowed", "restricted", "blocked"
}

/// Create consumer override request
#[derive(Debug, Deserialize)]
pub struct CreateConsumerOverrideRequest {
    pub consumer_id: Uuid,
    pub country_code: String,
    pub policy_type: String, // "allowed", "restricted", "blocked"
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Query parameters for listing policies
#[derive(Debug, Deserialize)]
pub struct ListPoliciesQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub region: Option<String>,
}

/// GET /api/admin/geo/policies - List all country access policies
pub async fn list_country_policies(
    State(state): State<GeoAdminState>,
    _auth: AdminAuth,
    Query(query): Query<ListPoliciesQuery>,
) -> Result<Json<Vec<CountryPolicyResponse>>, AppError> {
    let policies = state.geo_service.get_all_country_policies().await?;

    // Apply filtering if region is specified
    let filtered_policies: Vec<CountryPolicyResponse> = if let Some(region_filter) = query.region {
        policies
            .into_iter()
            .filter(|p| p.region_code.as_ref() == Some(&region_filter))
            .collect()
    } else {
        policies
    };

    // Apply pagination
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);

    let paginated_policies: Vec<CountryPolicyResponse> = filtered_policies
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    Ok(Json(paginated_policies))
}

/// GET /api/admin/geo/policies/{country_code} - Get specific country policy
pub async fn get_country_policy(
    State(state): State<GeoAdminState>,
    _auth: AdminAuth,
    Path(country_code): Path<String>,
) -> Result<Json<CountryPolicyResponse>, AppError> {
    let policies = state.geo_service.get_all_country_policies().await?;

    let policy = policies
        .into_iter()
        .find(|p| p.country_code == country_code)
        .ok_or_else(|| AppError::NotFound(format!("Country policy for {} not found", country_code)))?;

    Ok(Json(policy))
}

/// PUT /api/admin/geo/policies/{country_code} - Update country policy
pub async fn update_country_policy(
    State(state): State<GeoAdminState>,
    auth: AdminAuth,
    Path(country_code): Path<String>,
    Json(request): Json<UpdateCountryPolicyRequest>,
) -> Result<StatusCode, AppError> {
    // Validate policy type
    match request.policy_type.as_str() {
        "allowed" | "restricted" | "blocked" => {}
        _ => return Err(AppError::ValidationError("Invalid policy type. Must be 'allowed', 'restricted', or 'blocked'".to_string())),
    }

    state.geo_service.update_country_policy(
        &country_code,
        &request.policy_type,
        auth.user_id,
    ).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/admin/geo/consumers/{consumer_id}/overrides - List consumer overrides
pub async fn list_consumer_overrides(
    State(state): State<GeoAdminState>,
    _auth: AdminAuth,
    Path(consumer_id): Path<Uuid>,
) -> Result<Json<Vec<ConsumerOverrideResponse>>, AppError> {
    let overrides = state.geo_service.get_consumer_overrides(consumer_id).await?;

    let response: Vec<ConsumerOverrideResponse> = overrides
        .into_iter()
        .map(|o| ConsumerOverrideResponse {
            id: o.id,
            consumer_id: o.consumer_id,
            country_code: o.country_code,
            policy_type: o.policy_type,
            expires_at: o.expires_at,
            created_at: o.created_at,
            created_by: o.created_by,
        })
        .collect();

    Ok(Json(response))
}

/// POST /api/admin/geo/consumers/{consumer_id}/overrides - Create consumer override
pub async fn create_consumer_override(
    State(state): State<GeoAdminState>,
    auth: AdminAuth,
    Path(consumer_id): Path<Uuid>,
    Json(request): Json<CreateConsumerOverrideRequest>,
) -> Result<Json<ConsumerOverrideResponse>, AppError> {
    // Validate policy type
    match request.policy_type.as_str() {
        "allowed" | "restricted" | "blocked" => {}
        _ => return Err(AppError::ValidationError("Invalid policy type. Must be 'allowed', 'restricted', or 'blocked'".to_string())),
    }

    state.geo_service.create_consumer_override(
        consumer_id,
        &request.country_code,
        &request.policy_type,
        request.expires_at,
        auth.user_id,
    ).await?;

    // Get the created override
    let overrides = state.geo_service.get_consumer_overrides(consumer_id).await?;
    let created_override = overrides
        .into_iter()
        .find(|o| o.country_code == request.country_code && o.policy_type == request.policy_type)
        .ok_or_else(|| AppError::InternalError("Failed to retrieve created override".to_string()))?;

    let response = ConsumerOverrideResponse {
        id: created_override.id,
        consumer_id: created_override.consumer_id,
        country_code: created_override.country_code,
        policy_type: created_override.policy_type,
        expires_at: created_override.expires_at,
        created_at: created_override.created_at,
        created_by: created_override.created_by,
    };

    Ok(Json(response))
}

/// DELETE /api/admin/geo/consumers/{consumer_id}/overrides/{override_id} - Delete consumer override
pub async fn delete_consumer_override(
    State(state): State<GeoAdminState>,
    _auth: AdminAuth,
    Path((consumer_id, override_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    // Verify the override belongs to the consumer
    let overrides = state.geo_service.get_consumer_overrides(consumer_id).await?;
    let override_exists = overrides.iter().any(|o| o.id == override_id);

    if !override_exists {
        return Err(AppError::NotFound("Consumer override not found".to_string()));
    }

    state.geo_service.delete_consumer_override(override_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/admin/geo/cache/clear - Clear geo-restriction caches
pub async fn clear_geo_cache(
    State(state): State<GeoAdminState>,
    _auth: AdminAuth,
) -> Result<StatusCode, AppError> {
    state.geo_service.clear_policy_cache().await;
    Ok(StatusCode::NO_CONTENT)
}

/// Create geo-restriction admin router
pub fn create_geo_admin_router(state: GeoAdminState) -> Router {
    Router::new()
        .route("/policies", get(list_country_policies))
        .route("/policies/{country_code}", get(get_country_policy))
        .route("/policies/{country_code}", put(update_country_policy))
        .route("/consumers/{consumer_id}/overrides", get(list_consumer_overrides))
        .route("/consumers/{consumer_id}/overrides", post(create_consumer_override))
        .route("/consumers/{consumer_id}/overrides/{override_id}", delete(delete_consumer_override))
        .route("/cache/clear", post(clear_geo_cache))
        .with_state(state)
}