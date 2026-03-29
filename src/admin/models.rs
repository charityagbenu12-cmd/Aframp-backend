use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use std::collections::HashMap;

// Admin role enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "admin_role", rename_all = "snake_case")]
pub enum AdminRole {
    SuperAdmin,
    OperationsAdmin,
    SecurityAdmin,
    ComplianceAdmin,
    ReadOnlyAdmin,
}

impl AdminRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            AdminRole::SuperAdmin => "super_admin",
            AdminRole::OperationsAdmin => "operations_admin",
            AdminRole::SecurityAdmin => "security_admin",
            AdminRole::ComplianceAdmin => "compliance_admin",
            AdminRole::ReadOnlyAdmin => "read_only_admin",
        }
    }
}

// Admin status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "admin_status", rename_all = "snake_case")]
pub enum AdminStatus {
    PendingSetup,
    Active,
    Suspended,
    Locked,
}

// MFA status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "mfa_status", rename_all = "snake_case")]
pub enum MfaStatus {
    NotConfigured,
    Configured,
    RequiredReconfigure,
}

// Session status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "session_status", rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Expired,
    Terminated,
    Revoked,
}

// Audit action type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "audit_action_type", rename_all = "snake_case")]
pub enum AuditActionType {
    AccountCreated,
    AccountSuspended,
    AccountReinstated,
    RoleUpdated,
    PasswordChanged,
    MfaConfigured,
    MfaDisabled,
    SessionCreated,
    SessionTerminated,
    PermissionGranted,
    PermissionRevoked,
    SensitiveActionExecuted,
    LoginAttempt,
    LoginSuccess,
    LoginFailure,
    AccountLocked,
    AccountUnlocked,
    // Transaction operation actions
    TransactionRetry,
    TransactionRefund,
    TransactionViewed,
}

// Admin role configuration
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminRoleConfig {
    pub id: AdminRole,
    pub description: String,
    pub max_accounts: i32,
    pub session_lifetime_minutes: i32,
    pub inactivity_timeout_minutes: i32,
    pub max_concurrent_sessions: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Permission model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminPermission {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub category: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Role permission mapping
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminRolePermission {
    pub role: AdminRole,
    pub permission_id: Uuid,
    pub granted_at: DateTime<Utc>,
    pub granted_by: Option<Uuid>,
}

// Admin account model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminAccount {
    pub id: Uuid,
    pub full_name: String,
    pub email: String,
    pub password_hash: String,
    pub role: AdminRole,
    pub status: AdminStatus,
    pub mfa_status: MfaStatus,
    pub mfa_secret: Option<String>,
    pub fido2_credentials: Option<serde_json::Value>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
    pub failed_login_count: i32,
    pub account_locked_until: Option<DateTime<Utc>>,
    pub password_changed_at: DateTime<Utc>,
    pub mfa_configured_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
}

// Admin account creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAdminAccountRequest {
    pub full_name: String,
    pub email: String,
    pub role: AdminRole,
    pub temporary_password: String,
}

// Admin account update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAdminAccountRequest {
    pub full_name: Option<String>,
    pub email: Option<String>,
    pub role: Option<AdminRole>,
}

// Admin session model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminSession {
    pub id: Uuid,
    pub admin_id: Uuid,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub mfa_verified: bool,
    pub status: SessionStatus,
    pub termination_reason: Option<String>,
    pub terminated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// Active admin session view
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ActiveAdminSession {
    pub id: Uuid,
    pub admin_id: Uuid,
    pub full_name: String,
    pub email: String,
    pub role: AdminRole,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub mfa_verified: bool,
}

// Admin audit trail entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminAuditTrail {
    pub id: Uuid,
    pub admin_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub action_type: AuditActionType,
    pub target_resource_type: Option<String>,
    pub target_resource_id: Option<Uuid>,
    pub action_detail: Option<serde_json::Value>,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub previous_entry_hash: Option<String>,
    pub current_entry_hash: String,
    pub sequence_number: i64,
}

// Detailed audit trail view
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminAuditTrailDetailed {
    pub id: Uuid,
    pub admin_id: Option<Uuid>,
    pub full_name: Option<String>,
    pub email: Option<String>,
    pub role: Option<AdminRole>,
    pub session_id: Option<Uuid>,
    pub action_type: AuditActionType,
    pub target_resource_type: Option<String>,
    pub target_resource_id: Option<Uuid>,
    pub action_detail: Option<serde_json::Value>,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub sequence_number: i64,
    pub previous_entry_hash: Option<String>,
    pub current_entry_hash: String,
}

// Sensitive action confirmation
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminSensitiveConfirmation {
    pub id: Uuid,
    pub admin_id: Uuid,
    pub session_id: Uuid,
    pub action_type: String,
    pub target_resource_type: Option<String>,
    pub target_resource_id: Option<Uuid>,
    pub confirmation_method: String,
    pub confirmation_data: Option<serde_json::Value>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// Permission escalation request
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminPermissionEscalation {
    pub id: Uuid,
    pub requester_id: Uuid,
    pub requested_permission_id: Uuid,
    pub reason: String,
    pub duration_minutes: i32,
    pub status: String,
    pub approved_by: Option<Uuid>,
    pub approved_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// Security event
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminSecurityEvent {
    pub id: Uuid,
    pub admin_id: Option<Uuid>,
    pub event_type: String,
    pub event_data: serde_json::Value,
    pub severity: String,
    pub resolved: bool,
    pub resolved_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// Login request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminLoginRequest {
    pub email: String,
    pub password: String,
    pub totp_code: Option<String>,
    pub fido2_assertion: Option<serde_json::Value>,
}

// Login response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminLoginResponse {
    pub session_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub admin: AdminAccount,
    pub requires_mfa: bool,
    pub mfa_methods: Vec<String>,
}

// MFA setup request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSetupRequest {
    pub method: String, // 'totp' or 'fido2'
    pub totp_code: Option<String>,
    pub fido2_credential: Option<serde_json::Value>,
}

// MFA setup response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSetupResponse {
    pub qr_code_url: Option<String>, // For TOTP
    pub secret: Option<String>, // For TOTP
    pub challenge: Option<serde_json::Value>, // For FIDO2
}

// Password change request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordChangeRequest {
    pub current_password: String,
    pub new_password: String,
}

// Sensitive action confirmation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveActionConfirmationRequest {
    pub action_type: String,
    pub target_resource_type: Option<String>,
    pub target_resource_id: Option<Uuid>,
    pub confirmation_method: String, // 'password', 'totp', 'fido2'
    pub confirmation_data: serde_json::Value,
}

// Permission escalation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionEscalationRequest {
    pub permission_name: String,
    pub reason: String,
    pub duration_minutes: i32,
}

// Admin statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminStatistics {
    pub total_accounts: i64,
    pub active_accounts: i64,
    pub suspended_accounts: i64,
    pub locked_accounts: i64,
    pub active_sessions: i64,
    pub accounts_by_role: HashMap<AdminRole, i64>,
    pub recent_logins: i64,
    pub failed_login_attempts: i64,
}

// Security monitoring statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMonitoringStats {
    pub impossible_travel_events: i64,
    pub new_device_events: i64,
    pub unusual_hours_events: i64,
    pub failed_login_spike_events: i64,
    pub unresolved_events: i64,
    pub high_severity_events: i64,
}

// Audit trail verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrailVerificationResult {
    pub is_valid: bool,
    pub total_entries: i64,
    pub first_sequence: i64,
    pub last_sequence: i64,
    pub tampered_entries: Vec<TamperedEntry>,
    pub verification_timestamp: DateTime<Utc>,
}

// Tampered entry information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperedEntry {
    pub sequence_number: i64,
    pub entry_id: Uuid,
    pub expected_hash: String,
    pub actual_hash: String,
}

// Configuration for admin security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSecurityConfig {
    pub max_failed_login_attempts: i32,
    pub account_lockout_duration_minutes: i32,
    pub password_min_length: i32,
    pub password_require_uppercase: bool,
    pub password_require_lowercase: bool,
    pub password_require_numbers: bool,
    pub password_require_symbols: bool,
    pub session_lifetime_minutes: HashMap<AdminRole, i32>,
    pub inactivity_timeout_minutes: HashMap<AdminRole, i32>,
    pub max_concurrent_sessions: HashMap<AdminRole, i32>,
    pub mfa_required_for_all_roles: bool,
    pub fido2_required_for_super_admin: bool,
    pub sensitive_action_confirmation_window_minutes: i32,
    pub audit_trail_replication_enabled: bool,
    pub audit_trail_replication_bucket: Option<String>,
}

impl Default for AdminSecurityConfig {
    fn default() -> Self {
        let mut session_lifetime = HashMap::new();
        session_lifetime.insert(AdminRole::SuperAdmin, 60);
        session_lifetime.insert(AdminRole::OperationsAdmin, 240);
        session_lifetime.insert(AdminRole::SecurityAdmin, 180);
        session_lifetime.insert(AdminRole::ComplianceAdmin, 240);
        session_lifetime.insert(AdminRole::ReadOnlyAdmin, 480);

        let mut inactivity_timeout = HashMap::new();
        inactivity_timeout.insert(AdminRole::SuperAdmin, 15);
        inactivity_timeout.insert(AdminRole::OperationsAdmin, 30);
        inactivity_timeout.insert(AdminRole::SecurityAdmin, 20);
        inactivity_timeout.insert(AdminRole::ComplianceAdmin, 30);
        inactivity_timeout.insert(AdminRole::ReadOnlyAdmin, 60);

        let mut max_sessions = HashMap::new();
        max_sessions.insert(AdminRole::SuperAdmin, 2);
        max_sessions.insert(AdminRole::OperationsAdmin, 3);
        max_sessions.insert(AdminRole::SecurityAdmin, 2);
        max_sessions.insert(AdminRole::ComplianceAdmin, 3);
        max_sessions.insert(AdminRole::ReadOnlyAdmin, 5);

        Self {
            max_failed_login_attempts: 5,
            account_lockout_duration_minutes: 30,
            password_min_length: 12,
            password_require_uppercase: true,
            password_require_lowercase: true,
            password_require_numbers: true,
            password_require_symbols: true,
            session_lifetime_minutes: session_lifetime,
            inactivity_timeout_minutes: inactivity_timeout,
            max_concurrent_sessions: max_sessions,
            mfa_required_for_all_roles: true,
            fido2_required_for_super_admin: false,
            sensitive_action_confirmation_window_minutes: 5,
            audit_trail_replication_enabled: false,
            audit_trail_replication_bucket: None,
        }
    }
}

// Helper functions for password validation
pub fn validate_password_complexity(password: &str, config: &AdminSecurityConfig) -> Result<(), String> {
    if password.len() < config.password_min_length as usize {
        return Err(format!("Password must be at least {} characters long", config.password_min_length));
    }

    if config.password_require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return Err("Password must contain at least one uppercase letter".to_string());
    }

    if config.password_require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        return Err("Password must contain at least one lowercase letter".to_string());
    }

    if config.password_require_numbers && !password.chars().any(|c| c.is_numeric()) {
        return Err("Password must contain at least one number".to_string());
    }

    if config.password_require_symbols && !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err("Password must contain at least one special character".to_string());
    }

    Ok(())
}

// Helper function to check if an action is sensitive
pub fn is_sensitive_action(action_type: &str) -> bool {
    matches!(
        action_type,
        "account_suspend" | "account_reinstate" | "role_update" |
        "mfa_disable" | "permission_grant" | "permission_revoke" |
        "system_config_update" | "security_policy_update"
    )
}

// Helper function to get required permission for an endpoint
pub fn get_required_permission(endpoint: &str, method: &str) -> Option<&'static str> {
    match (endpoint, method) {
        // Admin account management
        ("/api/admin/accounts", "POST") => Some("admin.create"),
        ("/api/admin/accounts", "GET") => Some("admin.list"),
        ("/api/admin/accounts/{id}", "GET") => Some("admin.view"),
        ("/api/admin/accounts/{id}/role", "PATCH") => Some("admin.update_role"),
        ("/api/admin/accounts/{id}/suspend", "POST") => Some("admin.suspend"),
        ("/api/admin/accounts/{id}/reinstate", "POST") => Some("admin.reinstate"),

        // Security management
        ("/api/admin/sessions", "GET") => Some("security.session_manage"),
        ("/api/admin/sessions/{id}", "DELETE") => Some("security.session_manage"),
        ("/api/admin/audit", "GET") => Some("security.audit_view"),
        ("/api/admin/audit/verify", "GET") => Some("security.audit_verify"),
        ("/api/admin/security/monitoring", "GET") => Some("security.monitoring"),

        // Operations
        ("/api/operations/transactions", "GET") => Some("operations.transaction_view"),
        ("/api/operations/transactions/{id}", "POST") => Some("operations.transaction_manage"),
        ("/api/operations/kyc/review", "GET") => Some("operations.kyc_review"),
        ("/api/operations/kyc/{id}/approve", "POST") => Some("operations.kyc_approve"),
        ("/api/operations/kyc/{id}/reject", "POST") => Some("operations.kyc_reject"),

        // Compliance
        ("/api/compliance/reports", "GET") => Some("compliance.reporting"),
        ("/api/compliance/regulatory", "GET") => Some("compliance.regulatory_view"),
        ("/api/compliance/audit/export", "GET") => Some("compliance.audit_export"),

        // System
        ("/api/system/config", "GET") => Some("system.config_view"),
        ("/api/system/config", "PATCH") => Some("system.config_update"),
        ("/api/system/metrics", "GET") => Some("system.metrics_view"),
        ("/api/system/health", "GET") => Some("system.health_check"),

        _ => None,
    }
}