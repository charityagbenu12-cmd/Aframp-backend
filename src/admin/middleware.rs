use crate::admin::models::*;
use crate::admin::repositories::AdminPermissionRepository;
use crate::admin::auth::AdminAuthService;
use crate::error::Error;
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone)]
pub struct AdminAuthState {
    pub auth_service: AdminAuthService,
    pub permission_repo: AdminPermissionRepository,
    pub pool: sqlx::PgPool,
}

impl AdminAuthState {
    pub fn pool(&self) -> sqlx::PgPool {
        self.pool.clone()
    }
}

#[derive(Clone)]
pub struct AdminAuthContext {
    pub admin_id: Uuid,
    pub session_id: Uuid,
    pub role: AdminRole,
    pub permissions: Vec<String>,
}

pub async fn admin_auth_middleware(
    State(state): State<Arc<AdminAuthState>>,
    request: Request,
    next: Next,
) -> Result<Response, Error> {
    // Extract session token from Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let session_token = auth_header.ok_or_else(|| {
        Error::Authentication("Missing authorization token".to_string())
    })?;

    // Parse session token as UUID
    let session_id = Uuid::parse_str(session_token)
        .map_err(|_| Error::Authentication("Invalid session token".to_string()))?;

    // Extract IP address and user agent
    let ip_address = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.split(',').next())
        .unwrap_or("127.0.0.1")
        .trim();

    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown");

    // Validate session and get admin account
    let admin = state
        .auth_service
        .validate_session(session_id, ip_address, user_agent)
        .await?
        .ok_or_else(|| Error::Authentication("Invalid or expired session".to_string()))?;

    // Get admin permissions
    let permissions = if admin.role == AdminRole::SuperAdmin {
        // Super admin has all permissions
        state.permission_repo.get_all_permissions().await?
            .into_iter()
            .map(|p| p.name)
            .collect()
    } else {
        state.permission_repo.get_permissions_by_role(admin.role).await?
            .into_iter()
            .map(|p| p.name)
            .collect()
    };

    // Create auth context
    let auth_context = AdminAuthContext {
        admin_id: admin.id,
        session_id,
        role: admin.role,
        permissions,
    };

    // Add auth context to request extensions
    let mut request = request;
    request.extensions_mut().insert(auth_context);

    // Continue with the request
    Ok(next.run(request).await)
}

pub async fn require_permission_middleware(
    permission: &'static str,
    State(state): State<Arc<AdminAuthState>>,
    request: Request,
    next: Next,
) -> Result<Response, Error> {
    // Get auth context from request extensions
    let auth_context = request.extensions().get::<AdminAuthContext>()
        .ok_or_else(|| Error::Authentication("Authentication required".to_string()))?;

    // Check if admin has the required permission
    let has_permission = if auth_context.role == AdminRole::SuperAdmin {
        true // Super admin has all permissions
    } else {
        state.permission_repo.check_permission(auth_context.role, permission).await?
    };

    if !has_permission {
        return Err(Error::Forbidden(format!(
            "Insufficient permissions. Required: {}",
            permission
        )));
    }

    // Continue with the request
    Ok(next.run(request).await)
}

pub async fn require_role_middleware(
    required_role: AdminRole,
    request: Request,
    next: Next,
) -> Result<Response, Error> {
    // Get auth context from request extensions
    let auth_context = request.extensions().get::<AdminAuthContext>()
        .ok_or_else(|| Error::Authentication("Authentication required".to_string()))?;

    // Check if admin has the required role
    match required_role {
        AdminRole::SuperAdmin => {
            if auth_context.role != AdminRole::SuperAdmin {
                return Err(Error::Forbidden("Super admin access required".to_string()));
            }
        }
        AdminRole::SecurityAdmin => {
            if !matches!(auth_context.role, AdminRole::SecurityAdmin | AdminRole::SuperAdmin) {
                return Err(Error::Forbidden("Security admin access required".to_string()));
            }
        }
        AdminRole::OperationsAdmin => {
            if !matches!(auth_context.role, AdminRole::OperationsAdmin | AdminRole::SuperAdmin) {
                return Err(Error::Forbidden("Operations admin access required".to_string()));
            }
        }
        AdminRole::ComplianceAdmin => {
            if !matches!(auth_context.role, AdminRole::ComplianceAdmin | AdminRole::SuperAdmin) {
                return Err(Error::Forbidden("Compliance admin access required".to_string()));
            }
        }
        AdminRole::ReadOnlyAdmin => {
            // All roles have at least read access
        }
    }

    // Continue with the request
    Ok(next.run(request).await)
}

pub async fn require_super_admin_middleware(
    request: Request,
    next: Next,
) -> Result<Response, Error> {
    require_role_middleware(AdminRole::SuperAdmin, request, next).await
}

pub async fn require_security_admin_middleware(
    request: Request,
    next: Next,
) -> Result<Response, Error> {
    require_role_middleware(AdminRole::SecurityAdmin, request, next).await
}

pub async fn require_operations_admin_middleware(
    request: Request,
    next: Next,
) -> Result<Response, Error> {
    require_role_middleware(AdminRole::OperationsAdmin, request, next).await
}

pub async fn require_compliance_admin_middleware(
    request: Request,
    next: Next,
) -> Result<Response, Error> {
    require_role_middleware(AdminRole::ComplianceAdmin, request, next).await
}

// Macro to create permission middleware
#[macro_export]
macro_rules! require_permission {
    ($permission:expr) => {
        |State(state): State<Arc<AdminAuthState>>, request: Request, next: Next| async move {
            $crate::admin::middleware::require_permission_middleware($permission, State(state), request, next).await
        }
    };
}

// Helper function to extract auth context from request
pub fn get_auth_context(request: &Request) -> Result<&AdminAuthContext, Error> {
    request.extensions().get::<AdminAuthContext>()
        .ok_or_else(|| Error::Authentication("Authentication required".to_string()))
}

// Helper function to check if current admin has specific permission
pub fn has_permission(auth_context: &AdminAuthContext, permission: &str) -> bool {
    auth_context.role == AdminRole::SuperAdmin || 
    auth_context.permissions.contains(&permission.to_string())
}

// Helper function to check if current admin has any of the specified permissions
pub fn has_any_permission(auth_context: &AdminAuthContext, permissions: &[&str]) -> bool {
    auth_context.role == AdminRole::SuperAdmin || 
    permissions.iter().any(|p| auth_context.permissions.contains(&p.to_string()))
}

// Helper function to check if current admin has all of the specified permissions
pub fn has_all_permissions(auth_context: &AdminAuthContext, permissions: &[&str]) -> bool {
    if auth_context.role == AdminRole::SuperAdmin {
        return true;
    }
    
    permissions.iter().all(|p| auth_context.permissions.contains(&p.to_string()))
}

// Permission check middleware that can be used with specific endpoint patterns
pub async fn endpoint_permission_middleware(
    State(state): State<Arc<AdminAuthState>>,
    request: Request,
    next: Next,
) -> Result<Response, Error> {
    // Get auth context from request extensions
    let auth_context = request.extensions().get::<AdminAuthContext>()
        .ok_or_else(|| Error::Authentication("Authentication required".to_string()))?;

    // Extract endpoint and method
    let path = request.uri().path();
    let method = request.method().as_str();

    // Get required permission for this endpoint
    let required_permission = get_required_permission(path, method)
        .ok_or_else(|| Error::Forbidden("Endpoint not found in permission catalog".to_string()))?;

    // Check if admin has the required permission
    let has_permission = if auth_context.role == AdminRole::SuperAdmin {
        true
    } else {
        state.permission_repo.check_permission(auth_context.role, required_permission).await?
    };

    if !has_permission {
        return Err(Error::Forbidden(format!(
            "Insufficient permissions for {} {}. Required: {}",
            method, path, required_permission
        )));
    }

    // Continue with the request
    Ok(next.run(request).await)
}

// Sensitive action confirmation middleware
pub async fn sensitive_action_middleware(
    State(state): State<Arc<AdminAuthState>>,
    request: Request,
    next: Next,
) -> Result<Response, Error> {
    // Get auth context from request extensions
    let auth_context = request.extensions().get::<AdminAuthContext>()
        .ok_or_else(|| Error::Authentication("Authentication required".to_string()))?;

    // Extract endpoint and method
    let path = request.uri().path();
    let method = request.method().as_str();

    // Check if this is a sensitive action
    let action_type = format!("{}_{}", method.to_lowercase(), path.trim_start_matches("/api/admin/"));
    
    if is_sensitive_action(&action_type) {
        // Check for sensitive action confirmation header
        let confirmation_header = request
            .headers()
            .get("X-Sensitive-Action-Confirmation")
            .and_then(|h| h.to_str().ok());

        let confirmation_id = confirmation_header
            .and_then(|h| Uuid::parse_str(h).ok())
            .ok_or_else(|| {
                Error::BadRequest("Sensitive action confirmation required".to_string())
            })?;

        // Verify the confirmation is valid
        // This would involve checking the confirmation repository
        // For now, we'll just check if the header exists
    }

    // Continue with the request
    Ok(next.run(request).await)
}

// Session activity tracking middleware
pub async fn session_activity_middleware(
    State(state): State<Arc<AdminAuthState>>,
    request: Request,
    next: Next,
) -> Result<Response, Error> {
    // Get auth context from request extensions
    let auth_context = request.extensions().get::<AdminAuthContext>()
        .ok_or_else(|| Error::Authentication("Authentication required".to_string()))?;

    // Update session last activity
    state.auth_service.session_repo.update_last_activity(auth_context.session_id).await?;

    // Continue with the request
    Ok(next.run(request).await)
}

// Rate limiting middleware for admin endpoints
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AdminRateLimiter {
    requests: Arc<RwLock<HashMap<Uuid, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl AdminRateLimiter {
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_seconds),
        }
    }

    pub async fn check_rate_limit(&self, admin_id: Uuid) -> Result<(), Error> {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        
        let admin_requests = requests.entry(admin_id).or_insert_with(Vec::new);
        
        // Remove old requests outside the window
        admin_requests.retain(|&timestamp| now.duration_since(timestamp) < self.window);
        
        // Check if limit exceeded
        if admin_requests.len() >= self.max_requests {
            return Err(Error::TooManyRequests("Rate limit exceeded".to_string()));
        }
        
        // Add current request
        admin_requests.push(now);
        
        Ok(())
    }
}

pub async fn admin_rate_limit_middleware(
    State(rate_limiter): State<Arc<AdminRateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, Error> {
    // Get auth context from request extensions
    let auth_context = request.extensions().get::<AdminAuthContext>()
        .ok_or_else(|| Error::Authentication("Authentication required".to_string()))?;

    // Check rate limit
    rate_limiter.check_rate_limit(auth_context.admin_id).await?;

    // Continue with the request
    Ok(next.run(request).await)
}