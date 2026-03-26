use crate::admin::models::*;
use crate::admin::services::*;
use crate::admin::middleware::{get_auth_context, has_permission};
use crate::error::Error;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub admin_id: Option<Uuid>,
    pub action_type: Option<String>,
    pub target_resource_type: Option<String>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: T,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub success: bool,
    pub data: Vec<T>,
    pub pagination: Pagination,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Pagination {
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    pub has_next: bool,
    pub has_prev: bool,
}

// Admin Authentication Handlers
pub async fn login_handler(
    State(state): State<Arc<AdminAuthState>>,
    Json(request): Json<AdminLoginRequest>,
) -> Result<Json<ApiResponse<AdminLoginResponse>>, Error> {
    let ip_address = "127.0.0.1"; // Extract from request in real implementation
    let user_agent = "Unknown"; // Extract from request in real implementation

    let response = state.auth_service.authenticate(request, ip_address, user_agent).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: response,
        message: None,
    }))
}

pub async fn verify_mfa_handler(
    State(state): State<Arc<AdminAuthState>>,
    Path(session_id): Path<Uuid>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<()>>, Error> {
    let totp_code = request.get("totp_code").and_then(|v| v.as_str()).map(|s| s.to_string());
    let fido2_assertion = request.get("fido2_assertion").cloned();

    state.auth_service.verify_mfa(session_id, totp_code, fido2_assertion).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("MFA verification successful".to_string()),
    }))
}

pub async fn setup_mfa_handler(
    State(state): State<Arc<AdminAuthState>>,
    Json(request): Json<MfaSetupRequest>,
) -> Result<Json<ApiResponse<MfaSetupResponse>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    
    let response = state.auth_service.setup_mfa(auth_context.admin_id, request).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: response,
        message: None,
    }))
}

pub async fn confirm_mfa_setup_handler(
    State(state): State<Arc<AdminAuthState>>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<()>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    
    let method = request.get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::BadRequest("Method required".to_string()))?;
    
    let verification_data = request.get("verification_data")
        .cloned()
        .ok_or_else(|| Error::BadRequest("Verification data required".to_string()))?;

    state.auth_service.confirm_mfa_setup(auth_context.admin_id, method, verification_data).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("MFA setup completed successfully".to_string()),
    }))
}

pub async fn change_password_handler(
    State(state): State<Arc<AdminAuthState>>,
    Json(request): Json<PasswordChangeRequest>,
) -> Result<Json<ApiResponse<()>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    
    state.auth_service.change_password(auth_context.admin_id, request).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("Password changed successfully".to_string()),
    }))
}

// Admin Account Management Handlers
pub async fn create_admin_account_handler(
    State(services): State<Arc<AdminServices>>,
    Json(request): Json<CreateAdminAccountRequest>,
) -> Result<Json<ApiResponse<AdminAccount>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    let ip_address = "127.0.0.1";
    let user_agent = "Unknown";

    let admin = services.account_service.create_admin_account(
        request,
        auth_context.admin_id,
        ip_address,
        user_agent,
    ).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: admin,
        message: Some("Admin account created successfully".to_string()),
    }))
}

pub async fn update_admin_role_handler(
    State(services): State<Arc<AdminServices>>,
    Path(admin_id): Path<Uuid>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<()>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    let ip_address = "127.0.0.1";
    let user_agent = "Unknown";

    let new_role = request.get("role")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::BadRequest("Role required".to_string()))?;

    let role = match new_role {
        "super_admin" => AdminRole::SuperAdmin,
        "operations_admin" => AdminRole::OperationsAdmin,
        "security_admin" => AdminRole::SecurityAdmin,
        "compliance_admin" => AdminRole::ComplianceAdmin,
        "read_only_admin" => AdminRole::ReadOnlyAdmin,
        _ => return Err(Error::BadRequest("Invalid role".to_string())),
    };

    services.account_service.update_admin_role(
        admin_id,
        role,
        auth_context.admin_id,
        ip_address,
        user_agent,
    ).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("Admin role updated successfully".to_string()),
    }))
}

pub async fn suspend_admin_account_handler(
    State(services): State<Arc<AdminServices>>,
    Path(admin_id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    let ip_address = "127.0.0.1";
    let user_agent = "Unknown";

    services.account_service.suspend_admin_account(
        admin_id,
        auth_context.admin_id,
        ip_address,
        user_agent,
    ).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("Admin account suspended successfully".to_string()),
    }))
}

pub async fn reinstate_admin_account_handler(
    State(services): State<Arc<AdminServices>>,
    Path(admin_id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    let ip_address = "127.0.0.1";
    let user_agent = "Unknown";

    services.account_service.reinstate_admin_account(
        admin_id,
        auth_context.admin_id,
        ip_address,
        user_agent,
    ).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("Admin account reinstated successfully".to_string()),
    }))
}

pub async fn get_admin_account_handler(
    State(services): State<Arc<AdminServices>>,
    Path(admin_id): Path<Uuid>,
) -> Result<Json<ApiResponse<AdminAccount>>, Error> {
    let admin = services.account_service.get_admin_account(admin_id).await?
        .ok_or_else(|| Error::NotFound("Admin account not found".to_string()))?;

    Ok(Json(ApiResponse {
        success: true,
        data: admin,
        message: None,
    }))
}

pub async fn list_admin_accounts_handler(
    State(services): State<Arc<AdminServices>>,
    Query(query): Query<ListQuery>,
) -> Result<Json<PaginatedResponse<AdminAccount>>, Error> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let accounts = services.account_service.list_admin_accounts(limit, offset).await?;

    Ok(Json(PaginatedResponse {
        success: true,
        data: accounts,
        pagination: Pagination {
            total: accounts.len() as i64, // Get actual count in real implementation
            limit,
            offset,
            has_next: accounts.len() == limit as usize,
            has_prev: offset > 0,
        },
        message: None,
    }))
}

pub async fn get_admin_statistics_handler(
    State(services): State<Arc<AdminServices>>,
) -> Result<Json<ApiResponse<AdminStatistics>>, Error> {
    let stats = services.account_service.get_admin_statistics().await?;

    Ok(Json(ApiResponse {
        success: true,
        data: stats,
        message: None,
    }))
}

// Session Management Handlers
pub async fn get_active_sessions_handler(
    State(services): State<Arc<AdminServices>>,
) -> Result<Json<ApiResponse<Vec<ActiveAdminSession>>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;

    let sessions = services.session_service.get_active_sessions(auth_context.admin_id).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: sessions,
        message: None,
    }))
}

pub async fn terminate_session_handler(
    State(services): State<Arc<AdminServices>>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    let ip_address = "127.0.0.1";
    let user_agent = "Unknown";

    services.session_service.terminate_session(
        session_id,
        auth_context.admin_id,
        ip_address,
        user_agent,
    ).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("Session terminated successfully".to_string()),
    }))
}

pub async fn terminate_all_sessions_handler(
    State(services): State<Arc<AdminServices>>,
) -> Result<Json<ApiResponse<()>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    let ip_address = "127.0.0.1";
    let user_agent = "Unknown";

    services.session_service.terminate_all_sessions(
        auth_context.admin_id,
        Some(auth_context.session_id),
        auth_context.admin_id,
        ip_address,
        user_agent,
    ).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("All sessions terminated successfully".to_string()),
    }))
}

// Audit Trail Handlers
pub async fn get_audit_trail_handler(
    State(services): State<Arc<AdminServices>>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<PaginatedResponse<AdminAuditTrailDetailed>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    
    // Only super admins can access audit trail
    if auth_context.role != AdminRole::SuperAdmin {
        return Err(Error::Forbidden("Super admin access required".to_string()));
    }

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let action_type = query.action_type
        .and_then(|s| match s.as_str() {
            "account_created" => Some(AuditActionType::AccountCreated),
            "account_suspended" => Some(AuditActionType::AccountSuspended),
            "account_reinstated" => Some(AuditActionType::AccountReinstated),
            "role_updated" => Some(AuditActionType::RoleUpdated),
            "password_changed" => Some(AuditActionType::PasswordChanged),
            "mfa_configured" => Some(AuditActionType::MfaConfigured),
            "mfa_disabled" => Some(AuditActionType::MfaDisabled),
            "session_created" => Some(AuditActionType::SessionCreated),
            "session_terminated" => Some(AuditActionType::SessionTerminated),
            "permission_granted" => Some(AuditActionType::PermissionGranted),
            "permission_revoked" => Some(AuditActionType::PermissionRevoked),
            "sensitive_action_executed" => Some(AuditActionType::SensitiveActionExecuted),
            "login_attempt" => Some(AuditActionType::LoginAttempt),
            "login_success" => Some(AuditActionType::LoginSuccess),
            "login_failure" => Some(AuditActionType::LoginFailure),
            "account_locked" => Some(AuditActionType::AccountLocked),
            "account_unlocked" => Some(AuditActionType::AccountUnlocked),
            _ => None,
        });

    let audit_entries = services.audit_repo.get_audit_trail(
        query.admin_id,
        action_type,
        query.target_resource_type,
        query.date_from,
        query.date_to,
        limit,
        offset,
    ).await?;

    Ok(Json(PaginatedResponse {
        success: true,
        data: audit_entries,
        pagination: Pagination {
            total: audit_entries.len() as i64, // Get actual count in real implementation
            limit,
            offset,
            has_next: audit_entries.len() == limit as usize,
            has_prev: offset > 0,
        },
        message: None,
    }))
}

pub async fn verify_audit_trail_handler(
    State(services): State<Arc<AdminServices>>,
) -> Result<Json<ApiResponse<AuditTrailVerificationResult>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    
    // Only super admins can verify audit trail
    if auth_context.role != AdminRole::SuperAdmin {
        return Err(Error::Forbidden("Super admin access required".to_string()));
    }

    let verification_result = services.audit_repo.verify_audit_trail_integrity().await?;

    Ok(Json(ApiResponse {
        success: true,
        data: verification_result,
        message: None,
    }))
}

// Sensitive Action Handlers
pub async fn request_sensitive_action_confirmation_handler(
    State(services): State<Arc<AdminServices>>,
    Json(request): Json<SensitiveActionConfirmationRequest>,
) -> Result<Json<ApiResponse<AdminSensitiveConfirmation>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;

    let confirmation = services.sensitive_action_service.request_confirmation(
        auth_context.admin_id,
        auth_context.session_id,
        request,
    ).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: confirmation,
        message: Some("Sensitive action confirmation requested".to_string()),
    }))
}

pub async fn execute_sensitive_action_handler(
    State(services): State<Arc<AdminServices>>,
    Path(action_type): Path<String>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<()>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;

    // This would execute the actual sensitive action
    // For now, we'll just confirm and log it
    services.sensitive_action_service.confirm_and_execute(
        auth_context.admin_id,
        auth_context.session_id,
        &action_type,
        request,
        async { Ok(()) }, // Placeholder action
    ).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("Sensitive action executed successfully".to_string()),
    }))
}

// Security Monitoring Handlers
pub async fn get_security_events_handler(
    State(services): State<Arc<AdminServices>>,
    Query(query): Query<serde_json::Value>,
) -> Result<Json<ApiResponse<Vec<AdminSecurityEvent>>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    
    // Only security admins and super admins can access security events
    if !matches!(auth_context.role, AdminRole::SecurityAdmin | AdminRole::SuperAdmin) {
        return Err(Error::Forbidden("Security admin access required".to_string()));
    }

    let severity_filter = query.get("severity").and_then(|v| v.as_str());

    let events = services.security_service.get_unresolved_security_events(severity_filter).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: events,
        message: None,
    }))
}

pub async fn resolve_security_event_handler(
    State(services): State<Arc<AdminServices>>,
    Path(event_id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;

    services.security_service.resolve_security_event(event_id, auth_context.admin_id).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: (),
        message: Some("Security event resolved successfully".to_string()),
    }))
}

pub async fn get_security_statistics_handler(
    State(services): State<Arc<AdminServices>>,
) -> Result<Json<ApiResponse<SecurityMonitoringStats>>, Error> {
    let auth_context = get_auth_context(&axum::extract::Request::builder().body(()).unwrap())?;
    
    // Only security admins and super admins can access security statistics
    if !matches!(auth_context.role, AdminRole::SecurityAdmin | AdminRole::SuperAdmin) {
        return Err(Error::Forbidden("Security admin access required".to_string()));
    }

    let stats = services.security_service.get_security_statistics().await?;

    Ok(Json(ApiResponse {
        success: true,
        data: stats,
        message: None,
    }))
}

// Permission Management Handlers
pub async fn get_permissions_handler(
    State(state): State<Arc<AdminAuthState>>,
) -> Result<Json<ApiResponse<Vec<AdminPermission>>>, Error> {
    let permissions = state.permission_repo.get_all_permissions().await?;

    Ok(Json(ApiResponse {
        success: true,
        data: permissions,
        message: None,
    }))
}

pub async fn get_role_permissions_handler(
    State(state): State<Arc<AdminAuthState>>,
    Path(role): Path<String>,
) -> Result<Json<ApiResponse<Vec<AdminPermission>>>, Error> {
    let admin_role = match role.as_str() {
        "super_admin" => AdminRole::SuperAdmin,
        "operations_admin" => AdminRole::OperationsAdmin,
        "security_admin" => AdminRole::SecurityAdmin,
        "compliance_admin" => AdminRole::ComplianceAdmin,
        "read_only_admin" => AdminRole::ReadOnlyAdmin,
        _ => return Err(Error::BadRequest("Invalid role".to_string())),
    };

    let permissions = state.permission_repo.get_permissions_by_role(admin_role).await?;

    Ok(Json(ApiResponse {
        success: true,
        data: permissions,
        message: None,
    }))
}

pub async fn get_role_configs_handler(
    State(state): State<Arc<AdminAuthState>>,
) -> Result<Json<ApiResponse<Vec<AdminRoleConfig>>>, Error> {
    let configs = state.permission_repo.get_all_role_configs().await?;

    Ok(Json(ApiResponse {
        success: true,
        data: configs,
        message: None,
    }))
}

// Service state container
#[derive(Clone)]
pub struct AdminServices {
    pub account_service: AdminAccountService,
    pub session_service: AdminSessionService,
    pub audit_repo: crate::admin::repositories::AdminAuditRepository,
    pub sensitive_action_service: SensitiveActionService,
    pub security_service: SecurityMonitoringService,
}

impl AdminServices {
    pub fn new(pool: sqlx::PgPool, auth_service: AdminAuthService, config: AdminSecurityConfig) -> Self {
        Self {
            account_service: AdminAccountService::new(pool.clone(), auth_service.clone()),
            session_service: AdminSessionService::new(pool.clone()),
            audit_repo: crate::admin::repositories::AdminAuditRepository::new(pool.clone()),
            sensitive_action_service: SensitiveActionService::new(pool.clone(), config.clone()),
            security_service: SecurityMonitoringService::new(pool),
        }
    }
}
