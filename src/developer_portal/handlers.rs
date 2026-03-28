use super::models::*;
use super::services::DeveloperService;
use super::production_access::ProductionAccessService;
use super::sandbox_service::SandboxService;
use crate::auth::middleware::AuthenticatedDeveloper;
use crate::error::AppError;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, patch, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use utoipa::path;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct PaginationParams {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UsageQueryParams {
    pub environment: Option<String>,
    pub start_date: Option<chrono::DateTime<chrono::Utc>>,
    pub end_date: Option<chrono::DateTime<chrono::Utc>>,
    pub time_range: Option<String>, // "daily", "weekly", "monthly"
}

#[path]
#[utoipa::path(
    post,
    path = "/api/developer/register",
    tag = "developer-portal",
    summary = "Register developer account",
    description = "Register a new developer account with email verification",
    request_body = CreateDeveloperAccountRequest,
    responses(
        (status = 201, description = "Developer account created successfully", body = DeveloperAccount),
        (status = 400, description = "Invalid request"),
        (status = 409, description = "Email already registered"),
        (status = 422, description = "Geo-restricted country")
    )
)]
pub async fn register_developer(
    State(service): State<Arc<DeveloperService>>,
    Json(request): Json<CreateDeveloperAccountRequest>,
) -> Result<(StatusCode, Json<DeveloperAccount>), AppError> {
    let account = service.register_developer(request).await?;
    Ok((StatusCode::CREATED, Json(account)))
}

#[path]
#[utoipa::path(
    get,
    path = "/api/developer/verify-email/{token}",
    tag = "developer-portal",
    summary = "Verify email address",
    description = "Verify developer email address using verification token",
    params(
        ("token" = String, Path, description = "Email verification token")
    ),
    responses(
        (status = 200, description = "Email verified successfully", body = DeveloperAccount),
        (status = 400, description = "Invalid or expired token")
    )
)]
pub async fn verify_email(
    State(service): State<Arc<DeveloperService>>,
    Path(token): Path<String>,
) -> Result<Json<DeveloperAccount>, AppError> {
    let account = service.verify_email(&token).await?;
    Ok(Json(account))
}

#[path]
#[utoipa::path(
    post,
    path = "/api/developer/identity-verification",
    tag = "developer-portal",
    summary = "Submit identity verification",
    description = "Submit identity verification documents for production access",
    security(
        ("developer_auth" = [])
    ),
    request_body = IdentityVerificationRequest,
    responses(
        (status = 200, description = "Identity verification submitted", body = DeveloperAccount),
        (status = 400, description = "Invalid request or verification already submitted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Account not found")
    )
)]
pub async fn submit_identity_verification(
    State(service): State<Arc<DeveloperService>>,
    auth: AuthenticatedDeveloper,
    Json(request): Json<IdentityVerificationRequest>,
) -> Result<Json<DeveloperAccount>, AppError> {
    let account = service
        .submit_identity_verification(auth.developer_account_id, request)
        .await?;
    Ok(Json(account))
}

#[path]
#[utoipa::path(
    post,
    path = "/api/developer/applications",
    tag = "developer-portal",
    summary = "Create application",
    description = "Create a new application under the developer account",
    security(
        ("developer_auth" = [])
    ),
    request_body = CreateApplicationRequest,
    responses(
        (status = 201, description = "Application created successfully", body = DeveloperApplication),
        (status = 400, description = "Invalid request or application limit reached"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Account not found")
    )
)]
pub async fn create_application(
    State(service): State<Arc<DeveloperService>>,
    auth: AuthenticatedDeveloper,
    Json(request): Json<CreateApplicationRequest>,
) -> Result<(StatusCode, Json<DeveloperApplication>), AppError> {
    let application = service
        .create_application(auth.developer_account_id, request)
        .await?;
    Ok((StatusCode::CREATED, Json(application)))
}

#[path]
#[utoipa::path(
    get,
    path = "/api/developer/applications",
    tag = "developer-portal",
    summary = "List applications",
    description = "List all applications for the authenticated developer",
    security(
        ("developer_auth" = [])
    ),
    responses(
        (status = 200, description = "Applications retrieved successfully", body = Vec<DeveloperApplication>),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn list_applications(
    State(service): State<Arc<DeveloperService>>,
    auth: AuthenticatedDeveloper,
) -> Result<Json<Vec<DeveloperApplication>>, AppError> {
    let applications = service.get_applications(auth.developer_account_id).await?;
    Ok(Json(applications))
}

#[path]
#[utoipa::path(
    get,
    path = "/api/developer/applications/{app_id}",
    tag = "developer-portal",
    summary = "Get application details",
    description = "Get detailed information about a specific application",
    security(
        ("developer_auth" = [])
    ),
    params(
        ("app_id" = Uuid, Path, description = "Application ID")
    ),
    responses(
        (status = 200, description = "Application details retrieved", body = DeveloperApplication),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found")
    )
)]
pub async fn get_application(
    State(service): State<Arc<DeveloperService>>,
    auth: AuthenticatedDeveloper,
    Path(app_id): Path<Uuid>,
) -> Result<Json<DeveloperApplication>, AppError> {
    let application = service.get_application(app_id).await?;
    
    // Verify ownership
    if application.developer_account_id != auth.developer_account_id {
        return Err(AppError::Unauthorized);
    }
    
    Ok(Json(application))
}

#[path]
#[utoipa::path(
    patch,
    path = "/api/developer/applications/{app_id}",
    tag = "developer-portal",
    summary = "Update application",
    description = "Update application name and description",
    security(
        ("developer_auth" = [])
    ),
    params(
        ("app_id" = Uuid, Path, description = "Application ID")
    ),
    request_body = UpdateApplicationRequest,
    responses(
        (status = 200, description = "Application updated successfully", body = DeveloperApplication),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found")
    )
)]
pub async fn update_application(
    State(service): State<Arc<DeveloperService>>,
    auth: AuthenticatedDeveloper,
    Path(app_id): Path<Uuid>,
    Json(request): Json<UpdateApplicationRequest>,
) -> Result<Json<DeveloperApplication>, AppError> {
    // Verify ownership first
    let application = service.get_application(app_id).await?;
    if application.developer_account_id != auth.developer_account_id {
        return Err(AppError::Unauthorized);
    }

    let updated_application = service.update_application(app_id, request).await?;
    Ok(Json(updated_application))
}

#[path]
#[utoipa::path(
    delete,
    path = "/api/developer/applications/{app_id}",
    tag = "developer-portal",
    summary = "Delete application",
    description = "Soft delete an application and revoke all credentials",
    security(
        ("developer_auth" = [])
    ),
    params(
        ("app_id" = Uuid, Path, description = "Application ID")
    ),
    responses(
        (status = 204, description = "Application deleted successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found")
    )
)]
pub async fn delete_application(
    State(service): State<Arc<DeveloperService>>,
    auth: AuthenticatedDeveloper,
    Path(app_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    // Verify ownership first
    let application = service.get_application(app_id).await?;
    if application.developer_account_id != auth.developer_account_id {
        return Err(AppError::Unauthorized);
    }

    service.delete_application(app_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[path]
#[utoipa::path(
    post,
    path = "/api/developer/applications/{app_id}/api-keys",
    tag = "developer-portal",
    summary = "Create API key",
    description = "Create a new API key for an application",
    security(
        ("developer_auth" = [])
    ),
    params(
        ("app_id" = Uuid, Path, description = "Application ID")
    ),
    request_body = CreateApiKeyRequest,
    responses(
        (status = 201, description = "API key created successfully", body = ApiKeyCreationResponse),
        (status = 400, description = "Invalid request or insufficient permissions"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found")
    )
)]
pub async fn create_api_key(
    State(service): State<Arc<DeveloperService>>,
    auth: AuthenticatedDeveloper,
    Path(app_id): Path<Uuid>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<ApiKeyCreationResponse>), AppError> {
    // Verify ownership first
    let application = service.get_application(app_id).await?;
    if application.developer_account_id != auth.developer_account_id {
        return Err(AppError::Unauthorized);
    }

    let (api_key, raw_key) = service.create_api_key(app_id, request).await?;
    
    let response = ApiKeyCreationResponse {
        api_key,
        raw_key, // Only returned once during creation
    };
    
    Ok((StatusCode::CREATED, Json(response)))
}

#[path]
#[utoipa::path(
    get,
    path = "/api/developer/applications/{app_id}/api-keys",
    tag = "developer-portal",
    summary = "List API keys",
    description = "List all API keys for an application",
    security(
        ("developer_auth" = [])
    ),
    params(
        ("app_id" = Uuid, Path, description = "Application ID")
    ),
    responses(
        (status = 200, description = "API keys retrieved successfully", body = Vec<ApiKey>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found")
    )
)]
pub async fn list_api_keys(
    State(service): State<Arc<DeveloperService>>,
    auth: AuthenticatedDeveloper,
    Path(app_id): Path<Uuid>,
) -> Result<Json<Vec<ApiKey>>, AppError> {
    // Verify ownership first
    let application = service.get_application(app_id).await?;
    if application.developer_account_id != auth.developer_account_id {
        return Err(AppError::Unauthorized);
    }

    let api_keys = service.get_api_keys(app_id).await?;
    Ok(Json(api_keys))
}

#[path]
#[utoipa::path(
    delete,
    path = "/api/developer/api-keys/{key_id}",
    tag = "developer-portal",
    summary = "Revoke API key",
    description = "Revoke an API key",
    security(
        ("developer_auth" = [])
    ),
    params(
        ("key_id" = Uuid, Path, description = "API key ID")
    ),
    responses(
        (status = 204, description = "API key revoked successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "API key not found")
    )
)]
pub async fn revoke_api_key(
    State(service): State<Arc<DeveloperService>>,
    auth: AuthenticatedDeveloper,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    // Verify ownership through the API key's application
    let api_key = service.api_key_repo.find_by_id(key_id).await
        .map_err(|_| AppError::NotFound)?
        .ok_or(AppError::NotFound)?;
    
    let application = service.get_application(api_key.application_id).await?;
    if application.developer_account_id != auth.developer_account_id {
        return Err(AppError::Unauthorized);
    }

    service.revoke_api_key(key_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[path]
#[utoipa::path(
    post,
    path = "/api/developer/sandbox/reset",
    tag = "developer-portal",
    summary = "Reset sandbox environment",
    description = "Reset sandbox environment and provision fresh credentials",
    security(
        ("developer_auth" = [])
    ),
    responses(
        (status = 200, description = "Sandbox environment reset successfully", body = SandboxEnvironment),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Account not found")
    )
)]
pub async fn reset_sandbox_environment(
    State((dev_service, _)): State<(Arc<DeveloperService>, Arc<ProductionAccessService>)>,
    auth: AuthenticatedDeveloper,
) -> Result<Json<SandboxEnvironment>, AppError> {
    // Verify account has at least one application — pick the first if no specific app_id
    let applications = dev_service
        .get_applications(auth.developer_account_id)
        .await
        .map_err(AppError::from)?;

    let application = applications
        .into_iter()
        .next()
        .ok_or_else(|| AppError::new(crate::error::AppErrorKind::Domain(
            crate::error::DomainError::TransactionNotFound {
                transaction_id: "no_application".to_string(),
            }
        )))?;

    let sandbox_env = dev_service
        .developer_account_repo
        .reset_sandbox_environment(application.id)
        .await
        .map_err(AppError::from)?;

    Ok(Json(sandbox_env))
}

#[path]
#[utoipa::path(
    post,
    path = "/api/developer/applications/{app_id}/production-access",
    tag = "developer-portal",
    summary = "Request production access",
    description = "Submit a production access request for an application",
    security(
        ("developer_auth" = [])
    ),
    params(
        ("app_id" = Uuid, Path, description = "Application ID")
    ),
    request_body = CreateProductionAccessRequest,
    responses(
        (status = 201, description = "Production access request submitted", body = ProductionAccessRequest),
        (status = 400, description = "Invalid request or identity verification required"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found")
    )
)]
pub async fn request_production_access(
    State(services): State<(Arc<DeveloperService>, Arc<ProductionAccessService>)>,
    auth: AuthenticatedDeveloper,
    Path(app_id): Path<Uuid>,
    Json(request): Json<CreateProductionAccessRequest>,
) -> Result<(StatusCode, Json<ProductionAccessRequest>), AppError> {
    let production_request = services
        .1
        .create_production_access_request(app_id, auth.developer_account_id, request)
        .await?;
    Ok((StatusCode::CREATED, Json(production_request)))
}

#[path]
#[utoipa::path(
    get,
    path = "/api/developer/applications/{app_id}/usage",
    tag = "developer-portal",
    summary = "Get usage statistics",
    description = "Get usage statistics for an application",
    security(
        ("developer_auth" = [])
    ),
    params(
        ("app_id" = Uuid, Path, description = "Application ID"),
        ("environment" = Option<String>, Query, description = "Filter by environment"),
        ("start_date" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "Start date for usage data"),
        ("end_date" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "End date for usage data"),
        ("time_range" = Option<String>, Query, description = "Time range: daily, weekly, monthly")
    ),
    responses(
        (status = 200, description = "Usage statistics retrieved", body = ApplicationUsageSummary),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found")
    )
)]
pub async fn get_usage_statistics(
    State((dev_service, _)): State<(Arc<DeveloperService>, Arc<ProductionAccessService>)>,
    auth: AuthenticatedDeveloper,
    Path(app_id): Path<Uuid>,
    Query(params): Query<UsageQueryParams>,
) -> Result<Json<ApplicationUsageSummary>, AppError> {
    // Verify the application belongs to this developer
    let application = dev_service
        .get_application(app_id)
        .await
        .map_err(AppError::from)?;

    if application.developer_account_id != auth.developer_account_id {
        return Err(AppError::new(crate::error::AppErrorKind::Domain(
            crate::error::DomainError::TransactionNotFound {
                transaction_id: app_id.to_string(),
            }
        )));
    }

    let summary = dev_service
        .get_usage_statistics(
            app_id,
            params.time_range.as_deref(),
            params.start_date,
            params.end_date,
            params.environment.as_deref(),
        )
        .await
        .map_err(AppError::from)?;

    Ok(Json(summary))
}

#[path]
#[utoipa::path(
    get,
    path = "/api/developer/account",
    tag = "developer-portal",
    summary = "Get developer account",
    description = "Get current developer account information",
    security(
        ("developer_auth" = [])
    ),
    responses(
        (status = 200, description = "Account information retrieved", body = DeveloperAccount),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_developer_account(
    State(service): State<Arc<DeveloperService>>,
    auth: AuthenticatedDeveloper,
) -> Result<Json<DeveloperAccount>, AppError> {
    let account = service.get_developer_account(auth.developer_account_id).await?;
    Ok(Json(account))
}

#[path]
#[utoipa::path(
    patch,
    path = "/api/developer/account",
    tag = "developer-portal",
    summary = "Update developer account",
    description = "Update developer account information",
    security(
        ("developer_auth" = [])
    ),
    request_body = UpdateDeveloperAccountRequest,
    responses(
        (status = 200, description = "Account updated successfully", body = DeveloperAccount),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn update_developer_account(
    State(service): State<Arc<DeveloperService>>,
    auth: AuthenticatedDeveloper,
    Json(request): Json<UpdateDeveloperAccountRequest>,
) -> Result<Json<DeveloperAccount>, AppError> {
    let account = service
        .update_developer_account(auth.developer_account_id, request)
        .await?;
    Ok(Json(account))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyCreationResponse {
    pub api_key: ApiKey,
    pub raw_key: String,
}

pub fn developer_portal_routes() -> Router<(Arc<DeveloperService>, Arc<ProductionAccessService>)> {
    Router::new()
        .route("/register", post(register_developer))
        .route("/verify-email/:token", get(verify_email))
        .route("/identity-verification", post(submit_identity_verification))
        .route("/applications", post(create_application).get(list_applications))
        .route("/applications/:app_id", get(get_application).patch(update_application).delete(delete_application))
        .route("/applications/:app_id/api-keys", post(create_api_key).get(list_api_keys))
        .route("/api-keys/:key_id", delete(revoke_api_key))
        .route("/sandbox/reset", post(reset_sandbox_environment))
        .route("/applications/:app_id/production-access", post(request_production_access))
        .route("/applications/:app_id/usage", get(get_usage_statistics))
        .route("/account", get(get_developer_account).patch(update_developer_account))
}
