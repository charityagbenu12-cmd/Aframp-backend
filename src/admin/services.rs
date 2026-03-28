use crate::admin::models::*;
use crate::admin::repositories::*;
use crate::admin::auth::AdminAuthService;
use crate::database::error::DatabaseError;
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

pub struct AdminAccountService {
    account_repo: AdminAccountRepository,
    audit_repo: AdminAuditRepository,
    permission_repo: AdminPermissionRepository,
    auth_service: AdminAuthService,
}

impl AdminAccountService {
    pub fn new(
        pool: sqlx::PgPool,
        auth_service: AdminAuthService,
    ) -> Self {
        Self {
            account_repo: AdminAccountRepository::new(pool.clone()),
            audit_repo: AdminAuditRepository::new(pool.clone()),
            permission_repo: AdminPermissionRepository::new(pool.clone()),
            auth_service,
        }
    }

    pub async fn create_admin_account(
        &self,
        request: CreateAdminAccountRequest,
        created_by: Uuid,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<AdminAccount, crate::error::Error> {
        // Verify that the creator is a super admin
        let creator = self.account_repo.get_by_id(created_by).await?
            .ok_or_else(|| crate::error::Error::NotFound("Creator not found".to_string()))?;

        if creator.role != AdminRole::SuperAdmin {
            return Err(crate::error::Error::Forbidden("Only super admins can create admin accounts".to_string()));
        }

        // Check if we can create another account for this role
        if !self.permission_repo.can_create_account_for_role(request.role).await? {
            return Err(crate::error::Error::BadRequest("Maximum number of accounts for this role reached".to_string()));
        }

        // Check if email already exists
        if self.account_repo.get_by_email(&request.email).await?.is_some() {
            return Err(crate::error::Error::Conflict("Email already exists".to_string()));
        }

        // Create the account
        let admin = self.account_repo.create_account(request, Some(created_by)).await?;

        // Log the creation
        self.audit_repo.create_audit_entry(
            Some(created_by),
            None,
            AuditActionType::AccountCreated,
            Some("admin_account".to_string()),
            Some(admin.id),
            Some(json!({
                "email": admin.email,
                "role": admin.role.as_str(),
                "full_name": admin.full_name
            })),
            None,
            Some(json!({
                "status": "pending_setup",
                "mfa_status": "not_configured"
            })),
            Some(ip_address.to_string()),
            Some(user_agent.to_string()),
        ).await?;

        Ok(admin)
    }

    pub async fn update_admin_role(
        &self,
        admin_id: Uuid,
        new_role: AdminRole,
        updated_by: Uuid,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<(), crate::error::Error> {
        // Verify that the updater is a super admin
        let updater = self.account_repo.get_by_id(updated_by).await?
            .ok_or_else(|| crate::error::Error::NotFound("Updater not found".to_string()))?;

        if updater.role != AdminRole::SuperAdmin {
            return Err(crate::error::Error::Forbidden("Only super admins can update admin roles".to_string()));
        }

        // Get the admin account to update
        let admin = self.account_repo.get_by_id(admin_id).await?
            .ok_or_else(|| crate::error::Error::NotFound("Admin account not found".to_string()))?;

        // Cannot change role of super admin (except by another super admin)
        if admin.role == AdminRole::SuperAdmin && updater.id != admin.id {
            return Err(crate::error::Error::Forbidden("Cannot change role of another super admin".to_string()));
        }

        // Check if we can create another account for the new role
        if !self.permission_repo.can_create_account_for_role(new_role).await? {
            return Err(crate::error::Error::BadRequest("Maximum number of accounts for this role reached".to_string()));
        }

        // Store old state for audit
        let before_state = json!({
            "role": admin.role.as_str()
        });

        // Update the role
        self.account_repo.update_role(admin_id, new_role).await?;

        // Terminate all active sessions for the admin (force re-login with new permissions)
        self.auth_service.session_repo.terminate_all_sessions(admin_id, None).await?;

        // Log the role update
        self.audit_repo.create_audit_entry(
            Some(updated_by),
            None,
            AuditActionType::RoleUpdated,
            Some("admin_account".to_string()),
            Some(admin_id),
            Some(json!({
                "old_role": admin.role.as_str(),
                "new_role": new_role.as_str(),
                "admin_email": admin.email
            })),
            Some(before_state),
            Some(json!({
                "role": new_role.as_str()
            })),
            Some(ip_address.to_string()),
            Some(user_agent.to_string()),
        ).await?;

        Ok(())
    }

    pub async fn suspend_admin_account(
        &self,
        admin_id: Uuid,
        suspended_by: Uuid,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<(), crate::error::Error> {
        // Verify that the suspender is a super admin
        let suspender = self.account_repo.get_by_id(suspended_by).await?
            .ok_or_else(|| crate::error::Error::NotFound("Suspender not found".to_string()))?;

        if suspender.role != AdminRole::SuperAdmin {
            return Err(crate::error::Error::Forbidden("Only super admins can suspend admin accounts".to_string()));
        }

        // Get the admin account to suspend
        let admin = self.account_repo.get_by_id(admin_id).await?
            .ok_or_else(|| crate::error::Error::NotFound("Admin account not found".to_string()))?;

        // Cannot suspend another super admin
        if admin.role == AdminRole::SuperAdmin {
            return Err(crate::error::Error::Forbidden("Cannot suspend a super admin account".to_string()));
        }

        // Cannot suspend yourself
        if admin_id == suspended_by {
            return Err(crate::error::Error::BadRequest("Cannot suspend your own account".to_string()));
        }

        // Store old state for audit
        let before_state = json!({
            "status": admin.status.as_str()
        });

        // Suspend the account
        self.account_repo.suspend_account(admin_id).await?;

        // Terminate all active sessions
        self.auth_service.session_repo.terminate_all_sessions(admin_id, None).await?;

        // Log the suspension
        self.audit_repo.create_audit_entry(
            Some(suspended_by),
            None,
            AuditActionType::AccountSuspended,
            Some("admin_account".to_string()),
            Some(admin_id),
            Some(json!({
                "admin_email": admin.email,
                "admin_role": admin.role.as_str()
            })),
            Some(before_state),
            Some(json!({
                "status": "suspended"
            })),
            Some(ip_address.to_string()),
            Some(user_agent.to_string()),
        ).await?;

        Ok(())
    }

    pub async fn reinstate_admin_account(
        &self,
        admin_id: Uuid,
        reinstated_by: Uuid,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<(), crate::error::Error> {
        // Verify that the reinstater is a super admin
        let reinstater = self.account_repo.get_by_id(reinstated_by).await?
            .ok_or_else(|| crate::error::Error::NotFound("Reinstater not found".to_string()))?;

        if reinstater.role != AdminRole::SuperAdmin {
            return Err(crate::error::Error::Forbidden("Only super admins can reinstate admin accounts".to_string()));
        }

        // Get the admin account to reinstate
        let admin = self.account_repo.get_by_id(admin_id).await?
            .ok_or_else(|| crate::error::Error::NotFound("Admin account not found".to_string()))?;

        // Store old state for audit
        let before_state = json!({
            "status": admin.status.as_str(),
            "mfa_status": admin.mfa_status.as_str()
        });

        // Reinstate the account (requires MFA reconfiguration)
        self.account_repo.reinstate_account(admin_id).await?;

        // Log the reinstatement
        self.audit_repo.create_audit_entry(
            Some(reinstated_by),
            None,
            AuditActionType::AccountReinstated,
            Some("admin_account".to_string()),
            Some(admin_id),
            Some(json!({
                "admin_email": admin.email,
                "admin_role": admin.role.as_str()
            })),
            Some(before_state),
            Some(json!({
                "status": "active",
                "mfa_status": "required_reconfigure"
            })),
            Some(ip_address.to_string()),
            Some(user_agent.to_string()),
        ).await?;

        Ok(())
    }

    pub async fn get_admin_account(&self, admin_id: Uuid) -> Result<Option<AdminAccount>, crate::error::Error> {
        Ok(self.account_repo.get_by_id(admin_id).await?)
    }

    pub async fn list_admin_accounts(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AdminAccount>, crate::error::Error> {
        Ok(self.account_repo.list_all(limit, offset).await?)
    }

    pub async fn get_admin_statistics(&self) -> Result<AdminStatistics, crate::error::Error> {
        Ok(self.account_repo.get_statistics().await?)
    }
}

pub struct AdminSessionService {
    session_repo: AdminSessionRepository,
    account_repo: AdminAccountRepository,
    audit_repo: AdminAuditRepository,
}

impl AdminSessionService {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            session_repo: AdminSessionRepository::new(pool.clone()),
            account_repo: AdminAccountRepository::new(pool.clone()),
            audit_repo: AdminAuditRepository::new(pool.clone()),
        }
    }

    pub async fn get_active_sessions(&self, admin_id: Uuid) -> Result<Vec<ActiveAdminSession>, crate::error::Error> {
        Ok(self.session_repo.get_active_sessions(admin_id).await?)
    }

    pub async fn terminate_session(
        &self,
        session_id: Uuid,
        terminated_by: Uuid,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<(), crate::error::Error> {
        // Get the session to terminate
        let session = self.session_repo.get_by_id(session_id).await?
            .ok_or_else(|| crate::error::Error::NotFound("Session not found".to_string()))?;

        // Verify that the terminator owns the session or is a super admin
        let terminator = self.account_repo.get_by_id(terminated_by).await?
            .ok_or_else(|| crate::error::Error::NotFound("Terminator not found".to_string()))?;

        if session.admin_id != terminated_by && terminator.role != AdminRole::SuperAdmin {
            return Err(crate::error::Error::Forbidden("You can only terminate your own sessions".to_string()));
        }

        // Terminate the session
        self.session_repo.terminate_session(session_id, "manual_termination").await?;

        // Log the termination
        self.audit_repo.create_audit_entry(
            Some(terminated_by),
            Some(session_id),
            AuditActionType::SessionTerminated,
            Some("admin_session".to_string()),
            Some(session_id),
            Some(json!({
                "terminated_by": terminated_by,
                "session_owner": session.admin_id
            })),
            None,
            None,
            Some(ip_address.to_string()),
            Some(user_agent.to_string()),
        ).await?;

        Ok(())
    }

    pub async fn terminate_all_sessions(
        &self,
        admin_id: Uuid,
        exclude_current_session: Option<Uuid>,
        terminated_by: Uuid,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<(), crate::error::Error> {
        // Verify that the terminator owns the sessions or is a super admin
        let terminator = self.account_repo.get_by_id(terminated_by).await?
            .ok_or_else(|| crate::error::Error::NotFound("Terminator not found".to_string()))?;

        if admin_id != terminated_by && terminator.role != AdminRole::SuperAdmin {
            return Err(crate::error::Error::Forbidden("You can only terminate your own sessions".to_string()));
        }

        // Get active sessions before termination for audit
        let active_sessions = self.session_repo.get_active_sessions(admin_id).await?;

        // Terminate all sessions (except current if specified)
        self.session_repo.terminate_all_sessions(admin_id, exclude_current_session).await?;

        // Log the batch termination
        self.audit_repo.create_audit_entry(
            Some(terminated_by),
            exclude_current_session,
            AuditActionType::SessionTerminated,
            Some("admin_account".to_string()),
            Some(admin_id),
            Some(json!({
                "terminated_sessions": active_sessions.len(),
                "excluded_session": exclude_current_session
            })),
            None,
            None,
            Some(ip_address.to_string()),
            Some(user_agent.to_string()),
        ).await?;

        Ok(())
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<i64, crate::error::Error> {
        Ok(self.session_repo.cleanup_expired_sessions().await?)
    }

    pub async fn enforce_session_limits(&self) -> Result<(), crate::error::Error> {
        // Get all role configurations
        let role_configs = self.permission_repo.get_all_role_configs().await?;

        for config in role_configs {
            // Get all active sessions for admins with this role
            let admins = sqlx::query!(
                "SELECT DISTINCT admin_id FROM admin_sessions WHERE status = 'active' AND expires_at > NOW()"
            )
            .fetch_all(&self.session_repo.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;

            for admin_row in admins {
                // Enforce concurrent session limit
                self.session_repo.enforce_concurrent_session_limit(
                    admin_row.admin_id,
                    config.max_concurrent_sessions,
                ).await?;
            }
        }

        Ok(())
    }
}

pub struct SensitiveActionService {
    confirmation_repo: AdminSensitiveConfirmationRepository,
    audit_repo: AdminAuditRepository,
    account_repo: AdminAccountRepository,
    config: AdminSecurityConfig,
}

impl SensitiveActionService {
    pub fn new(pool: sqlx::PgPool, config: AdminSecurityConfig) -> Self {
        Self {
            confirmation_repo: AdminSensitiveConfirmationRepository::new(pool.clone()),
            audit_repo: AdminAuditRepository::new(pool.clone()),
            account_repo: AdminAccountRepository::new(pool.clone()),
            config,
        }
    }

    pub async fn request_confirmation(
        &self,
        admin_id: Uuid,
        session_id: Uuid,
        request: SensitiveActionConfirmationRequest,
    ) -> Result<AdminSensitiveConfirmation, crate::error::Error> {
        // Verify the action is sensitive
        if !is_sensitive_action(&request.action_type) {
            return Err(crate::error::Error::BadRequest("Action is not classified as sensitive".to_string()));
        }

        // Verify admin exists
        let _admin = self.account_repo.get_by_id(admin_id).await?
            .ok_or_else(|| crate::error::Error::NotFound("Admin not found".to_string()))?;

        // Create confirmation request
        let expires_at = Utc::now() + Duration::minutes(self.config.sensitive_action_confirmation_window_minutes as i64);

        let confirmation = self.confirmation_repo.create_confirmation(
            admin_id,
            session_id,
            &request.action_type,
            request.target_resource_type,
            request.target_resource_id,
            &request.confirmation_method,
            request.confirmation_data,
            expires_at,
        ).await?;

        Ok(confirmation)
    }

    pub async fn confirm_and_execute<F, Fut>(
        &self,
        admin_id: Uuid,
        session_id: Uuid,
        action_type: &str,
        confirmation_data: serde_json::Value,
        action: F,
    ) -> Result<(), crate::error::Error>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), crate::error::Error>>,
    {
        // Get valid confirmation
        let confirmation = self.confirmation_repo.get_valid_confirmation(
            admin_id,
            session_id,
            action_type,
        ).await?
        .ok_or_else(|| crate::error::Error::BadRequest("No valid confirmation found".to_string()))?;

        // Verify confirmation data
        if let Some(stored_data) = &confirmation.confirmation_data {
            if stored_data != &confirmation_data {
                return Err(crate::error::Error::BadRequest("Invalid confirmation data".to_string()));
            }
        }

        // Mark confirmation as used
        self.confirmation_repo.mark_as_used(confirmation.id).await?;

        // Execute the action
        action.await?;

        // Log the sensitive action execution
        self.audit_repo.create_audit_entry(
            Some(admin_id),
            Some(session_id),
            AuditActionType::SensitiveActionExecuted,
            confirmation.target_resource_type,
            confirmation.target_resource_id,
            Some(json!({
                "action_type": action_type,
                "confirmation_method": confirmation.confirmation_method
            })),
            None,
            None,
            None,
            None,
        ).await?;

        Ok(())
    }

    pub async fn cleanup_expired_confirmations(&self) -> Result<i64, crate::error::Error> {
        Ok(self.confirmation_repo.cleanup_expired_confirmations().await?)
    }
}

pub struct SecurityMonitoringService {
    security_event_repo: AdminSecurityEventRepository,
    account_repo: AdminAccountRepository,
}

impl SecurityMonitoringService {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            security_event_repo: AdminSecurityEventRepository::new(pool.clone()),
            account_repo: AdminAccountRepository::new(pool.clone()),
        }
    }

    pub async fn get_unresolved_security_events(
        &self,
        severity_filter: Option<&str>,
    ) -> Result<Vec<AdminSecurityEvent>, crate::error::Error> {
        Ok(self.security_event_repo.get_unresolved_events(severity_filter).await?)
    }

    pub async fn resolve_security_event(
        &self,
        event_id: Uuid,
        resolved_by: Uuid,
    ) -> Result<(), crate::error::Error> {
        // Verify resolver is a security admin or super admin
        let resolver = self.account_repo.get_by_id(resolved_by).await?
            .ok_or_else(|| crate::error::Error::NotFound("Resolver not found".to_string()))?;

        if !matches!(resolver.role, AdminRole::SecurityAdmin | AdminRole::SuperAdmin) {
            return Err(crate::error::Error::Forbidden("Only security admins and super admins can resolve security events".to_string()));
        }

        self.security_event_repo.resolve_security_event(event_id, resolved_by).await?;
        Ok(())
    }

    pub async fn get_security_statistics(&self) -> Result<SecurityMonitoringStats, crate::error::Error> {
        Ok(self.security_event_repo.get_security_statistics().await?)
    }

    pub async fn detect_failed_login_spike(&self) -> Result<Vec<AdminSecurityEvent>, crate::error::Error> {
        // Check for failed login spike in the last hour
        let spike_threshold = 10; // Configurable threshold
        
        let recent_failures = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)
            FROM admin_audit_trail 
            WHERE action_type = 'login_failure' 
            AND timestamp > NOW() - INTERVAL '1 hour'
            "#
        )
        .fetch_one(&self.security_event_repo.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(0);

        if recent_failures > spike_threshold {
            // Create a security event for the spike
            let event = self.security_event_repo.create_security_event(
                None,
                "failed_login_spike",
                json!({
                    "failed_count": recent_failures,
                    "threshold": spike_threshold,
                    "time_window": "1 hour"
                }),
                "high",
            ).await?;

            Ok(vec![event])
        } else {
            Ok(vec![])
        }
    }
}
