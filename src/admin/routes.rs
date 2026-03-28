use crate::admin::handlers::*;
use crate::admin::middleware::*;
use axum::{
    middleware::{self},
    routing::{get, post, delete, patch},
    Router,
};
use std::sync::Arc;

pub fn admin_routes() -> Router<Arc<AdminAuthState>> {
    Router::new()
        // Authentication routes
        .route("/login", post(login_handler))
        .route("/mfa/verify/:session_id", post(verify_mfa_handler))
        .route("/mfa/setup", post(setup_mfa_handler))
        .route("/mfa/confirm", post(confirm_mfa_setup_handler))
        .route("/password/change", post(change_password_handler))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()), // This would be properly initialized
            admin_auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()),
            session_activity_middleware,
        ))
}

pub fn admin_account_routes() -> Router<Arc<AdminServices>> {
    Router::new()
        // Account management routes
        .route("/accounts", post(create_admin_account_handler))
        .route("/accounts", get(list_admin_accounts_handler))
        .route("/accounts/statistics", get(get_admin_statistics_handler))
        .route("/accounts/:admin_id", get(get_admin_account_handler))
        .route("/accounts/:admin_id/role", patch(update_admin_role_handler))
        .route("/accounts/:admin_id/suspend", post(suspend_admin_account_handler))
        .route("/accounts/:admin_id/reinstate", post(reinstate_admin_account_handler))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()),
            require_permission!("admin.create"),
        ))
}

pub fn admin_session_routes() -> Router<Arc<AdminServices>> {
    Router::new()
        // Session management routes
        .route("/sessions", get(get_active_sessions_handler))
        .route("/sessions", delete(terminate_all_sessions_handler))
        .route("/sessions/:session_id", delete(terminate_session_handler))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()),
            require_permission!("security.session_manage"),
        ))
}

pub fn admin_audit_routes() -> Router<Arc<AdminServices>> {
    Router::new()
        // Audit trail routes (super admin only)
        .route("/audit", get(get_audit_trail_handler))
        .route("/audit/verify", get(verify_audit_trail_handler))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()),
            require_super_admin_middleware,
        ))
}

pub fn admin_security_routes() -> Router<Arc<AdminServices>> {
    Router::new()
        // Security monitoring routes
        .route("/security/events", get(get_security_events_handler))
        .route("/security/events/:event_id/resolve", post(resolve_security_event_handler))
        .route("/security/statistics", get(get_security_statistics_handler))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()),
            require_security_admin_middleware,
        ))
}

pub fn admin_sensitive_action_routes() -> Router<Arc<AdminServices>> {
    Router::new()
        // Sensitive action routes
        .route("/sensitive-actions/confirm", post(request_sensitive_action_confirmation_handler))
        .route("/sensitive-actions/:action_type/execute", post(execute_sensitive_action_handler))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()),
            sensitive_action_middleware,
        ))
}

pub fn admin_permission_routes() -> Router<Arc<AdminAuthState>> {
    Router::new()
        // Permission management routes
        .route("/permissions", get(get_permissions_handler))
        .route("/permissions/:role", get(get_role_permissions_handler))
        .route("/roles/config", get(get_role_configs_handler))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()),
            require_permission!("security.audit_view"),
        ))
}

pub fn operations_routes() -> Router<Arc<AdminServices>> {
    Router::new()
        // Operations admin routes
        .route("/transactions", get(|| async { axum::Json("Transactions list") }))
        .route("/transactions/:id", post(|| async { axum::Json("Transaction managed") }))
        .route("/kyc/review", get(|| async { axum::Json("KYC review list") }))
        .route("/kyc/:id/approve", post(|| async { axum::Json("KYC approved") }))
        .route("/kyc/:id/reject", post(|| async { axum::Json("KYC rejected") }))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()),
            require_operations_admin_middleware,
        ))
}

pub fn compliance_routes() -> Router<Arc<AdminServices>> {
    Router::new()
        // Compliance admin routes
        .route("/reports", get(|| async { axum::Json("Compliance reports") }))
        .route("/regulatory", get(|| async { axum::Json("Regulatory data") }))
        .route("/audit/export", get(|| async { axum::Json("Audit export") }))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()),
            require_compliance_admin_middleware,
        ))
}

pub fn system_routes() -> Router<Arc<AdminServices>> {
    Router::new()
        // System management routes
        .route("/config", get(|| async { axum::Json("System config") }))
        .route("/config", patch(|| async { axum::Json("Config updated") }))
        .route("/metrics", get(|| async { axum::Json("System metrics") }))
        .route("/health", get(|| async { axum::Json("System health") }))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()),
            require_permission!("system.config_view"),
        ))
}

// Combine all admin routes
pub fn all_admin_routes() -> Router<Arc<AdminServices>> {
    Router::new()
        .merge(admin_routes())
        .merge(admin_account_routes())
        .merge(admin_session_routes())
        .merge(admin_audit_routes())
        .merge(admin_security_routes())
        .merge(admin_sensitive_action_routes())
        .merge(admin_permission_routes())
        .merge(operations_routes())
        .merge(compliance_routes())
        .merge(system_routes())
        .route("/metrics", get(|| async {
            // Prometheus metrics endpoint
            axum::response::Html("Prometheus metrics would be here")
        }))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminAuthState::default()),
            endpoint_permission_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::new(AdminRateLimiter::new(100, 60)), // 100 requests per minute
            admin_rate_limit_middleware,
        ))
}

// Route organization by category
pub mod auth_routes {
    use super::*;
    
    pub fn routes() -> Router<Arc<AdminAuthState>> {
        Router::new()
            .route("/auth/login", post(login_handler))
            .route("/auth/mfa/setup", post(setup_mfa_handler))
            .route("/auth/mfa/confirm", post(confirm_mfa_setup_handler))
            .route("/auth/mfa/verify/:session_id", post(verify_mfa_handler))
            .route("/auth/password/change", post(change_password_handler))
    }
}

pub mod account_routes {
    use super::*;
    
    pub fn routes() -> Router<Arc<AdminServices>> {
        Router::new()
            .route("/accounts", post(create_admin_account_handler))
            .route("/accounts", get(list_admin_accounts_handler))
            .route("/accounts/:id", get(get_admin_account_handler))
            .route("/accounts/:id/role", patch(update_admin_role_handler))
            .route("/accounts/:id/suspend", post(suspend_admin_account_handler))
            .route("/accounts/:id/reinstate", post(reinstate_admin_account_handler))
            .route("/accounts/statistics", get(get_admin_statistics_handler))
    }
}

pub mod session_routes {
    use super::*;
    
    pub fn routes() -> Router<Arc<AdminServices>> {
        Router::new()
            .route("/sessions", get(get_active_sessions_handler))
            .route("/sessions", delete(terminate_all_sessions_handler))
            .route("/sessions/:id", delete(terminate_session_handler))
    }
}

pub mod audit_routes {
    use super::*;
    
    pub fn routes() -> Router<Arc<AdminServices>> {
        Router::new()
            .route("/audit", get(get_audit_trail_handler))
            .route("/audit/verify", get(verify_audit_trail_handler))
    }
}

pub mod security_routes {
    use super::*;
    
    pub fn routes() -> Router<Arc<AdminServices>> {
        Router::new()
            .route("/security/events", get(get_security_events_handler))
            .route("/security/events/:id/resolve", post(resolve_security_event_handler))
            .route("/security/statistics", get(get_security_statistics_handler))
            .route("/security/monitoring", get(|| async { axum::Json("Security monitoring dashboard") }))
    }
}

pub mod permission_routes {
    use super::*;
    
    pub fn routes() -> Router<Arc<AdminAuthState>> {
        Router::new()
            .route("/permissions", get(get_permissions_handler))
            .route("/permissions/roles/:role", get(get_role_permissions_handler))
            .route("/permissions/roles", get(get_role_configs_handler))
    }
}

// API versioning support
pub fn v1_admin_routes() -> Router<Arc<AdminServices>> {
    Router::new()
        .nest("/api/v1/admin", all_admin_routes())
}

pub fn v2_admin_routes() -> Router<Arc<AdminServices>> {
    // Future v2 routes with potentially different handlers
    Router::new()
        .nest("/api/v2/admin", all_admin_routes())
}

// Route documentation
pub const ADMIN_API_DOCS: &str = r#"
# Admin Access Control API Documentation

## Authentication Endpoints
- POST /api/admin/auth/login - Admin login
- POST /api/admin/auth/mfa/setup - Setup MFA
- POST /api/admin/auth/mfa/confirm - Confirm MFA setup
- POST /api/admin/auth/mfa/verify/:session_id - Verify MFA
- POST /api/admin/auth/password/change - Change password

## Account Management Endpoints
- POST /api/admin/accounts - Create admin account (Super Admin only)
- GET /api/admin/accounts - List admin accounts
- GET /api/admin/accounts/:id - Get admin account details
- PATCH /api/admin/accounts/:id/role - Update admin role (Super Admin only)
- POST /api/admin/accounts/:id/suspend - Suspend admin account (Super Admin only)
- POST /api/admin/accounts/:id/reinstate - Reinstate admin account (Super Admin only)
- GET /api/admin/accounts/statistics - Get admin statistics

## Session Management Endpoints
- GET /api/admin/sessions - Get active sessions
- DELETE /api/admin/sessions/:id - Terminate specific session
- DELETE /api/admin/sessions - Terminate all sessions except current

## Audit Trail Endpoints
- GET /api/admin/audit - Get audit trail (Super Admin only)
- GET /api/admin/audit/verify - Verify audit trail integrity (Super Admin only)

## Security Monitoring Endpoints
- GET /api/admin/security/events - Get security events
- POST /api/admin/security/events/:id/resolve - Resolve security event
- GET /api/admin/security/statistics - Get security statistics

## Permission Management Endpoints
- GET /api/admin/permissions - Get all permissions
- GET /api/admin/permissions/roles/:role - Get permissions for role
- GET /api/admin/permissions/roles - Get role configurations

## Operations Endpoints
- GET /api/admin/operations/transactions - View transactions
- POST /api/admin/operations/transactions/:id - Manage transaction
- GET /api/admin/operations/kyc/review - Review KYC submissions
- POST /api/admin/operations/kyc/:id/approve - Approve KYC
- POST /api/admin/operations/kyc/:id/reject - Reject KYC

## Compliance Endpoints
- GET /api/admin/compliance/reports - Generate compliance reports
- GET /api/admin/compliance/regulatory - Access regulatory data
- GET /api/admin/compliance/audit/export - Export audit data

## System Endpoints
- GET /api/admin/system/config - View system configuration
- PATCH /api/admin/system/config - Update system configuration
- GET /api/admin/system/metrics - View system metrics
- GET /api/admin/system/health - System health check

## Sensitive Action Endpoints
- POST /api/admin/sensitive-actions/confirm - Request sensitive action confirmation
- POST /api/admin/sensitive-actions/:action_type/execute - Execute sensitive action

## Headers
- Authorization: Bearer <session_token> - Required for all authenticated endpoints
- X-Sensitive-Action-Confirmation: <confirmation_id> - Required for sensitive actions
- X-Forwarded-For: <ip_address> - Client IP address
- User-Agent: <user_agent> - Client user agent

## Response Format
All endpoints return JSON in the following format:
```json
{
  "success": true,
  "data": {},
  "message": "Optional message"
}
```

## Error Responses
- 401 Unauthorized - Authentication required or invalid
- 403 Forbidden - Insufficient permissions
- 404 Not Found - Resource not found
- 429 Too Many Requests - Rate limit exceeded
- 500 Internal Server Error - Server error
"#;
