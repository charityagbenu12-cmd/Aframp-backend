use super::models::*;
use super::services::DeveloperService;
use super::production_access::ProductionAccessService;
use crate::auth::middleware::AuthenticatedAdmin;
use crate::error::AppError;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use utoipa::path;
use utoipa::ToSchema;

/// Shared state tuple injected into admin routes:
/// (DeveloperService, ProductionAccessService)
pub type AdminPortalState = (Arc<DeveloperService>, Arc<ProductionAccessService>);

#[path]
#[utoipa::path(
    get,
    path = "/api/admin/developer-portal/accounts",
    tag = "admin-developer-portal",
    summary = "List developer accounts",
    description = "Get paginated list of all developer accounts",
    security(
        ("admin_auth" = [])
    ),
    params(
        ("page" = Option<i64>, Query, description = "Page number (default: 1)"),
        ("per_page" = Option<i64>, Query, description = "Items per page (default: 20)")
    ),
    responses(
        (status = 200, description = "Developer accounts retrieved", body = AdminDeveloperAccountList),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    )
)]
pub async fn list_developer_accounts(
    State((service, _)): State<AdminPortalState>,
    _auth: AuthenticatedAdmin,
    Query(params): Query<PaginationParams>,
) -> Result<Json<AdminDeveloperAccountList>, AppError> {
    let page = params.page.unwrap_or(1);
    let per_page = params.per_page.unwrap_or(20).min(100);

    let accounts = service
        .list_developer_accounts_for_admin(page, per_page)
        .await?;
    
    Ok(Json(accounts))
}

#[path]
#[utoipa::path(
    get,
    path = "/api/admin/developer-portal/accounts/{account_id}",
    tag = "admin-developer-portal",
    summary = "Get developer account details",
    description = "Get full details of a specific developer account",
    security(
        ("admin_auth" = [])
    ),
    params(
        ("account_id" = Uuid, Path, description = "Developer account ID")
    ),
    responses(
        (status = 200, description = "Account details retrieved", body = DeveloperAccount),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Account not found")
    )
)]
pub async fn get_developer_account_details(
    State((service, _)): State<AdminPortalState>,
    _auth: AuthenticatedAdmin,
    Path(account_id): Path<Uuid>,
) -> Result<Json<DeveloperAccount>, AppError> {
    let account = service.get_developer_account(account_id).await?;
    Ok(Json(account))
}

#[path]
#[utoipa::path(
    post,
    path = "/api/admin/developer-portal/accounts/{account_id}/suspend",
    tag = "admin-developer-portal",
    summary = "Suspend developer account",
    description = "Suspend a developer account and revoke all credentials",
    security(
        ("admin_auth" = [])
    ),
    params(
        ("account_id" = Uuid, Path, description = "Developer account ID")
    ),
    request_body = SuspendAccountRequest,
    responses(
        (status = 200, description = "Account suspended successfully", body = DeveloperAccount),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Account not found")
    )
)]
pub async fn suspend_developer_account(
    State((service, _)): State<AdminPortalState>,
    _auth: AuthenticatedAdmin,
    Path(account_id): Path<Uuid>,
    Json(request): Json<SuspendAccountRequest>,
) -> Result<Json<DeveloperAccount>, AppError> {
    let account = service.suspend_account(account_id, &request.reason).await?;
    Ok(Json(account))
}

#[path]
#[utoipa::path(
    post,
    path = "/api/admin/developer-portal/accounts/{account_id}/reinstate",
    tag = "admin-developer-portal",
    summary = "Reinstate developer account",
    description = "Reinstate a suspended developer account",
    security(
        ("admin_auth" = [])
    ),
    params(
        ("account_id" = Uuid, Path, description = "Developer account ID")
    ),
    responses(
        (status = 200, description = "Account reinstated successfully", body = DeveloperAccount),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Account not found")
    )
)]
pub async fn reinstate_developer_account(
    State((service, _)): State<AdminPortalState>,
    _auth: AuthenticatedAdmin,
    Path(account_id): Path<Uuid>,
) -> Result<Json<DeveloperAccount>, AppError> {
    let account = service.reinstate_account(account_id).await?;
    Ok(Json(account))
}

#[path]
#[utoipa::path(
    get,
    path = "/api/admin/developer-portal/production-requests",
    tag = "admin-developer-portal",
    summary = "Get production access requests queue",
    description = "Get queue of production access requests awaiting review",
    security(
        ("admin_auth" = [])
    ),
    params(
        ("status" = Option<String>, Query, description = "Filter by status (pending, approved, rejected)"),
        ("page" = Option<i64>, Query, description = "Page number (default: 1)"),
        ("per_page" = Option<i64>, Query, description = "Items per page (default: 20)")
    ),
    responses(
        (status = 200, description = "Production access requests retrieved", body = AdminProductionAccessQueue),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden")
    )
)]
pub async fn get_production_access_requests(
    State((_, prod_service)): State<AdminPortalState>,
    _auth: AuthenticatedAdmin,
    Query(params): Query<ProductionRequestsQueryParams>,
) -> Result<Json<AdminProductionAccessQueue>, AppError> {
    let page = params.page.unwrap_or(1);
    let per_page = params.per_page.unwrap_or(20).min(100);
    let queue = prod_service
        .get_admin_production_queue(params.status, page, per_page)
        .await?;
    Ok(Json(queue))
}

#[path]
#[utoipa::path(
    post,
    path = "/api/admin/developer-portal/production-requests/{request_id}/approve",
    tag = "admin-developer-portal",
    summary = "Approve production access request",
    description = "Approve a production access request and issue production credentials",
    security(
        ("admin_auth" = [])
    ),
    params(
        ("request_id" = Uuid, Path, description = "Production access request ID")
    ),
    request_body = AdminProductionAccessReview,
    responses(
        (status = 200, description = "Production access request approved", body = ProductionAccessRequest),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Request not found")
    )
)]
pub async fn approve_production_access_request(
    State((_, prod_service)): State<AdminPortalState>,
    _auth: AuthenticatedAdmin,
    Path(request_id): Path<Uuid>,
    Json(request): Json<AdminProductionAccessReview>,
) -> Result<Json<ProductionAccessRequest>, AppError> {
    // Use a placeholder admin_id since we don't yet carry structured admin claims
    let admin_id = Uuid::nil();
    let result = prod_service
        .approve_production_access_request(request_id, admin_id, request.review_notes)
        .await?;
    Ok(Json(result))
}

#[path]
#[utoipa::path(
    post,
    path = "/api/admin/developer-portal/production-requests/{request_id}/reject",
    tag = "admin-developer-portal",
    summary = "Reject production access request",
    description = "Reject a production access request",
    security(
        ("admin_auth" = [])
    ),
    params(
        ("request_id" = Uuid, Path, description = "Production access request ID")
    ),
    request_body = AdminProductionAccessReview,
    responses(
        (status = 200, description = "Production access request rejected", body = ProductionAccessRequest),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Request not found")
    )
)]
pub async fn reject_production_access_request(
    State((_, prod_service)): State<AdminPortalState>,
    _auth: AuthenticatedAdmin,
    Path(request_id): Path<Uuid>,
    Json(request): Json<AdminProductionAccessReview>,
) -> Result<Json<ProductionAccessRequest>, AppError> {
    let admin_id = Uuid::nil();
    let result = prod_service
        .reject_production_access_request(request_id, admin_id, request.review_notes)
        .await?;
    Ok(Json(result))
}

#[path]
#[utoipa::path(
    post,
    path = "/api/admin/developer-portal/accounts/{account_id}/identity-verification/approve",
    tag = "admin-developer-portal",
    summary = "Approve identity verification",
    description = "Approve identity verification for a developer account",
    security(
        ("admin_auth" = [])
    ),
    params(
        ("account_id" = Uuid, Path, description = "Developer account ID")
    ),
    responses(
        (status = 200, description = "Identity verification approved", body = DeveloperAccount),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Account not found")
    )
)]
pub async fn approve_identity_verification(
    State((service, _)): State<AdminPortalState>,
    _auth: AuthenticatedAdmin,
    Path(account_id): Path<Uuid>,
) -> Result<Json<DeveloperAccount>, AppError> {
    let account = service.approve_identity_verification(account_id).await?;
    Ok(Json(account))
}

#[path]
#[utoipa::path(
    post,
    path = "/api/admin/developer-portal/accounts/{account_id}/identity-verification/reject",
    tag = "admin-developer-portal",
    summary = "Reject identity verification",
    description = "Reject identity verification for a developer account",
    security(
        ("admin_auth" = [])
    ),
    params(
        ("account_id" = Uuid, Path, description = "Developer account ID")
    ),
    responses(
        (status = 200, description = "Identity verification rejected", body = DeveloperAccount),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Account not found")
    )
)]
pub async fn reject_identity_verification(
    State((service, _)): State<AdminPortalState>,
    _auth: AuthenticatedAdmin,
    Path(account_id): Path<Uuid>,
) -> Result<Json<DeveloperAccount>, AppError> {
    let account = service.reject_identity_verification(account_id).await?;
    Ok(Json(account))
}

#[path]
#[utoipa::path(
    post,
    path = "/api/admin/developer-portal/accounts/{account_id}/upgrade-tier",
    tag = "admin-developer-portal",
    summary = "Upgrade access tier",
    description = "Upgrade a developer account to a higher access tier",
    security(
        ("admin_auth" = [])
    ),
    params(
        ("account_id" = Uuid, Path, description = "Developer account ID")
    ),
    request_body = UpgradeTierRequest,
    responses(
        (status = 200, description = "Access tier upgraded successfully", body = DeveloperAccount),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Account not found"),
        (status = 400, description = "Invalid tier or requirements not met")
    )
)]
pub async fn upgrade_access_tier(
    State((service, _)): State<AdminPortalState>,
    _auth: AuthenticatedAdmin,
    Path(account_id): Path<Uuid>,
    Json(request): Json<UpgradeTierRequest>,
) -> Result<Json<DeveloperAccount>, AppError> {
    let account = match request.tier.as_str() {
        "standard" => service.upgrade_to_standard_tier(account_id).await?,
        "partner" => service.upgrade_to_partner_tier(account_id).await?,
        _ => return Err(AppError::new(crate::error::AppErrorKind::Validation(
            crate::error::ValidationError::InvalidAmount {
                amount: request.tier.clone(),
                reason: "Tier must be 'standard' or 'partner'".to_string(),
            }
        ))),
    };
    
    Ok(Json(account))
}

// ─── DTOs ────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct PaginationParams {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct SuspendAccountRequest {
    pub reason: String,
}

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct ProductionRequestsQueryParams {
    pub status: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct UpgradeTierRequest {
    pub tier: String, // "standard" or "partner"
}

pub fn admin_developer_portal_routes() -> Router<AdminPortalState> {
    Router::new()
        .route("/accounts", get(list_developer_accounts))
        .route("/accounts/:account_id", get(get_developer_account_details))
        .route("/accounts/:account_id/suspend", post(suspend_developer_account))
        .route("/accounts/:account_id/reinstate", post(reinstate_developer_account))
        .route("/accounts/:account_id/identity-verification/approve", post(approve_identity_verification))
        .route("/accounts/:account_id/identity-verification/reject", post(reject_identity_verification))
        .route("/accounts/:account_id/upgrade-tier", post(upgrade_access_tier))
        .route("/production-requests", get(get_production_access_requests))
        .route("/production-requests/:request_id/approve", post(approve_production_access_request))
        .route("/production-requests/:request_id/reject", post(reject_production_access_request))
}
