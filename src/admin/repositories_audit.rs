use crate::admin::models::*;
use crate::database::error::DatabaseError;
use chrono::Utc;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub struct AdminAuditRepository {
    pool: PgPool,
}

impl AdminAuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_audit_entry(
        &self,
        admin_id: Option<Uuid>,
        session_id: Option<Uuid>,
        action_type: AuditActionType,
        target_resource_type: Option<String>,
        target_resource_id: Option<Uuid>,
        action_detail: Option<serde_json::Value>,
        before_state: Option<serde_json::Value>,
        after_state: Option<serde_json::Value>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<AdminAuditTrail, DatabaseError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO admin_audit_trail (
                admin_id, session_id, action_type, target_resource_type, target_resource_id,
                action_detail, before_state, after_state, ip_address, user_agent
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING 
                id, admin_id, session_id, action_type as "action_type: AuditActionType",
                target_resource_type, target_resource_id, action_detail, before_state, after_state,
                ip_address, user_agent, timestamp, previous_entry_hash, current_entry_hash, sequence_number
            "#,
            admin_id,
            session_id,
            action_type as AuditActionType,
            target_resource_type,
            target_resource_id,
            action_detail,
            before_state,
            after_state,
            ip_address,
            user_agent
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(AdminAuditTrail {
            id: row.id,
            admin_id: row.admin_id,
            session_id: row.session_id,
            action_type: row.action_type,
            target_resource_type: row.target_resource_type,
            target_resource_id: row.target_resource_id,
            action_detail: row.action_detail,
            before_state: row.before_state,
            after_state: row.after_state,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            timestamp: row.timestamp,
            previous_entry_hash: row.previous_entry_hash,
            current_entry_hash: row.current_entry_hash,
            sequence_number: row.sequence_number,
        })
    }

    pub async fn get_audit_trail(
        &self,
        admin_id: Option<Uuid>,
        action_type: Option<AuditActionType>,
        target_resource_type: Option<String>,
        date_from: Option<chrono::DateTime<Utc>>,
        date_to: Option<chrono::DateTime<Utc>>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AdminAuditTrailDetailed>, DatabaseError> {
        let mut query = r#"
            SELECT 
                at.id, at.admin_id, a.full_name, a.email, a.role as "role: AdminRole",
                at.session_id, at.action_type as "action_type: AuditActionType",
                at.target_resource_type, at.target_resource_id, at.action_detail,
                at.before_state, at.after_state, at.ip_address, at.user_agent,
                at.timestamp, at.sequence_number, at.previous_entry_hash, at.current_entry_hash
            FROM admin_audit_trail at
            LEFT JOIN admin_accounts a ON at.admin_id = a.id
            WHERE 1=1
        "#.to_string();

        let mut params = Vec::new();
        let mut param_index = 1;

        if admin_id.is_some() {
            query.push_str(&format!(" AND at.admin_id = ${}", param_index));
            param_index += 1;
        }
        if action_type.is_some() {
            query.push_str(&format!(" AND at.action_type = ${}", param_index));
            param_index += 1;
        }
        if target_resource_type.is_some() {
            query.push_str(&format!(" AND at.target_resource_type = ${}", param_index));
            param_index += 1;
        }
        if date_from.is_some() {
            query.push_str(&format!(" AND at.timestamp >= ${}", param_index));
            param_index += 1;
        }
        if date_to.is_some() {
            query.push_str(&format!(" AND at.timestamp <= ${}", param_index));
            param_index += 1;
        }

        query.push_str(" ORDER BY at.timestamp DESC");
        query.push_str(&format!(" LIMIT ${} OFFSET ${}", param_index, param_index + 1));

        let mut query_builder = sqlx::query_as::<_, AdminAuditTrailDetailed>(&query);

        if let Some(admin_id) = admin_id {
            query_builder = query_builder.bind(admin_id);
        }
        if let Some(action_type) = action_type {
            query_builder = query_builder.bind(action_type as AuditActionType);
        }
        if let Some(target_resource_type) = target_resource_type {
            query_builder = query_builder.bind(target_resource_type);
        }
        if let Some(date_from) = date_from {
            query_builder = query_builder.bind(date_from);
        }
        if let Some(date_to) = date_to {
            query_builder = query_builder.bind(date_to);
        }

        query_builder = query_builder.bind(limit).bind(offset);

        let results = query_builder
            .fetch_all(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;

        Ok(results)
    }

    pub async fn verify_audit_trail_integrity(&self) -> Result<AuditTrailVerificationResult, DatabaseError> {
        let total_entries = sqlx::query_scalar!("SELECT COUNT(*) FROM admin_audit_trail")
            .fetch_one(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?
            .unwrap_or(0);

        if total_entries == 0 {
            return Ok(AuditTrailVerificationResult {
                is_valid: true,
                total_entries: 0,
                first_sequence: 0,
                last_sequence: 0,
                tampered_entries: Vec::new(),
                verification_timestamp: Utc::now(),
            });
        }

        let first_sequence = sqlx::query_scalar!("SELECT MIN(sequence_number) FROM admin_audit_trail")
            .fetch_one(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?
            .unwrap_or(0);

        let last_sequence = sqlx::query_scalar!("SELECT MAX(sequence_number) FROM admin_audit_trail")
            .fetch_one(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?
            .unwrap_or(0);

        // Check hash chain integrity
        let tampered_entries = sqlx::query_as!(
            TamperedEntry,
            r#"
            WITH integrity_check AS (
                SELECT 
                    at1.sequence_number,
                    at1.id as entry_id,
                    at1.current_entry_hash as actual_hash,
                    COALESCE(at2.current_entry_hash, '0') as expected_hash
                FROM admin_audit_trail at1
                LEFT JOIN admin_audit_trail at2 ON at1.previous_entry_hash = at2.current_entry_hash
                WHERE at1.sequence_number > 1 
                AND at1.previous_entry_hash IS NOT NULL
                AND at1.previous_entry_hash != COALESCE(at2.current_entry_hash, '0')
            )
            SELECT 
                sequence_number as "sequence_number: i64",
                entry_id as "entry_id: Uuid",
                expected_hash,
                actual_hash
            FROM integrity_check
            ORDER BY sequence_number
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(AuditTrailVerificationResult {
            is_valid: tampered_entries.is_empty(),
            total_entries,
            first_sequence,
            last_sequence,
            tampered_entries,
            verification_timestamp: Utc::now(),
        })
    }

    pub async fn replicate_audit_entry(&self, entry_id: Uuid) -> Result<(), DatabaseError> {
        // This would replicate the audit entry to an external immutable store
        // For now, we'll just mark it as replicated in a separate table
        sqlx::query!(
            "INSERT INTO audit_replication_log (entry_id, replicated_at) VALUES ($1, NOW()) ON CONFLICT (entry_id) DO NOTHING",
            entry_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }
}

pub struct AdminPermissionRepository {
    pool: PgPool,
}

impl AdminPermissionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_all_permissions(&self) -> Result<Vec<AdminPermission>, DatabaseError> {
        let permissions = sqlx::query_as!(
            AdminPermission,
            "SELECT id, name, description, category, created_at, updated_at FROM admin_permissions ORDER BY category, name"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(permissions)
    }

    pub async fn get_permissions_by_role(&self, role: AdminRole) -> Result<Vec<AdminPermission>, DatabaseError> {
        let permissions = sqlx::query_as!(
            AdminPermission,
            r#"
            SELECT p.id, p.name, p.description, p.category, p.created_at, p.updated_at
            FROM admin_permissions p
            JOIN admin_role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role = $1
            ORDER BY p.category, p.name
            "#,
            role as AdminRole
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(permissions)
    }

    pub async fn check_permission(&self, role: AdminRole, permission_name: &str) -> Result<bool, DatabaseError> {
        // Super admin has all permissions
        if matches!(role, AdminRole::SuperAdmin) {
            return Ok(true);
        }

        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)
            FROM admin_permissions p
            JOIN admin_role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role = $1 AND p.name = $2
            "#,
            role as AdminRole,
            permission_name
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(0);

        Ok(count > 0)
    }

    pub async fn get_role_config(&self, role: AdminRole) -> Result<AdminRoleConfig, DatabaseError> {
        let config = sqlx::query_as!(
            AdminRoleConfig,
            r#"
            SELECT 
                id as "id: AdminRole", description, max_accounts, session_lifetime_minutes,
                inactivity_timeout_minutes, max_concurrent_sessions, created_at, updated_at
            FROM admin_roles
            WHERE id = $1
            "#,
            role as AdminRole
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(config)
    }

    pub async fn get_all_role_configs(&self) -> Result<Vec<AdminRoleConfig>, DatabaseError> {
        let configs = sqlx::query_as!(
            AdminRoleConfig,
            r#"
            SELECT 
                id as "id: AdminRole", description, max_accounts, session_lifetime_minutes,
                inactivity_timeout_minutes, max_concurrent_sessions, created_at, updated_at
            FROM admin_roles
            ORDER BY id
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(configs)
    }

    pub async fn grant_permission(&self, role: AdminRole, permission_id: Uuid, granted_by: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "INSERT INTO admin_role_permissions (role, permission_id, granted_by) VALUES ($1, $2, $3) ON CONFLICT (role, permission_id) DO NOTHING",
            role as AdminRole,
            permission_id,
            granted_by
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn revoke_permission(&self, role: AdminRole, permission_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "DELETE FROM admin_role_permissions WHERE role = $1 AND permission_id = $2",
            role as AdminRole,
            permission_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn count_accounts_by_role(&self, role: AdminRole) -> Result<i64, DatabaseError> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM admin_accounts WHERE role = $1",
            role as AdminRole
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(0);

        Ok(count)
    }

    pub async fn can_create_account_for_role(&self, role: AdminRole) -> Result<bool, DatabaseError> {
        let config = self.get_role_config(role).await?;
        let current_count = self.count_accounts_by_role(role).await?;
        Ok(current_count < config.max_accounts as i64)
    }
}

pub struct AdminSecurityEventRepository {
    pool: PgPool,
}

impl AdminSecurityEventRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_security_event(
        &self,
        admin_id: Option<Uuid>,
        event_type: &str,
        event_data: serde_json::Value,
        severity: &str,
    ) -> Result<AdminSecurityEvent, DatabaseError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO admin_security_events (admin_id, event_type, event_data, severity)
            VALUES ($1, $2, $3, $4)
            RETURNING 
                id, admin_id, event_type, event_data, severity, resolved,
                resolved_by, resolved_at, created_at
            "#,
            admin_id,
            event_type,
            event_data,
            severity
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(AdminSecurityEvent {
            id: row.id,
            admin_id: row.admin_id,
            event_type: row.event_type,
            event_data: row.event_data,
            severity: row.severity,
            resolved: row.resolved,
            resolved_by: row.resolved_by,
            resolved_at: row.resolved_at,
            created_at: row.created_at,
        })
    }

    pub async fn get_unresolved_events(&self, severity_filter: Option<&str>) -> Result<Vec<AdminSecurityEvent>, DatabaseError> {
        let mut query = r#"
            SELECT id, admin_id, event_type, event_data, severity, resolved, resolved_by, resolved_at, created_at
            FROM admin_security_events
            WHERE resolved = false
        "#.to_string();

        if let Some(severity) = severity_filter {
            query.push_str(&format!(" AND severity = '{}'", severity));
        }

        query.push_str(" ORDER BY created_at DESC");

        let events = sqlx::query_as(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;

        Ok(events)
    }

    pub async fn resolve_security_event(&self, event_id: Uuid, resolved_by: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE admin_security_events SET resolved = true, resolved_by = $1, resolved_at = NOW() WHERE id = $2",
            resolved_by,
            event_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn get_security_statistics(&self) -> Result<SecurityMonitoringStats, DatabaseError> {
        let impossible_travel_events = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM admin_security_events WHERE event_type = 'impossible_travel'"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(0);

        let new_device_events = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM admin_security_events WHERE event_type = 'new_device'"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(0);

        let unusual_hours_events = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM admin_security_events WHERE event_type = 'unusual_hours'"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(0);

        let failed_login_spike_events = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM admin_security_events WHERE event_type = 'failed_login_spike'"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(0);

        let unresolved_events = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM admin_security_events WHERE resolved = false"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(0);

        let high_severity_events = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM admin_security_events WHERE severity = 'high' OR severity = 'critical'"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(0);

        Ok(SecurityMonitoringStats {
            impossible_travel_events,
            new_device_events,
            unusual_hours_events,
            failed_login_spike_events,
            unresolved_events,
            high_severity_events,
        })
    }
}

pub struct AdminSensitiveConfirmationRepository {
    pool: PgPool,
}

impl AdminSensitiveConfirmationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_confirmation(
        &self,
        admin_id: Uuid,
        session_id: Uuid,
        action_type: &str,
        target_resource_type: Option<String>,
        target_resource_id: Option<Uuid>,
        confirmation_method: &str,
        confirmation_data: serde_json::Value,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<AdminSensitiveConfirmation, DatabaseError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO admin_sensitive_confirmations (
                admin_id, session_id, action_type, target_resource_type, target_resource_id,
                confirmation_method, confirmation_data, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING 
                id, admin_id, session_id, action_type, target_resource_type, target_resource_id,
                confirmation_method, confirmation_data, expires_at, used_at, created_at
            "#,
            admin_id,
            session_id,
            action_type,
            target_resource_type,
            target_resource_id,
            confirmation_method,
            confirmation_data,
            expires_at
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(AdminSensitiveConfirmation {
            id: row.id,
            admin_id: row.admin_id,
            session_id: row.session_id,
            action_type: row.action_type,
            target_resource_type: row.target_resource_type,
            target_resource_id: row.target_resource_id,
            confirmation_method: row.confirmation_method,
            confirmation_data: row.confirmation_data,
            expires_at: row.expires_at,
            used_at: row.used_at,
            created_at: row.created_at,
        })
    }

    pub async fn get_valid_confirmation(
        &self,
        admin_id: Uuid,
        session_id: Uuid,
        action_type: &str,
    ) -> Result<Option<AdminSensitiveConfirmation>, DatabaseError> {
        let confirmation = sqlx::query_as!(
            AdminSensitiveConfirmation,
            r#"
            SELECT 
                id, admin_id, session_id, action_type, target_resource_type, target_resource_id,
                confirmation_method, confirmation_data, expires_at, used_at, created_at
            FROM admin_sensitive_confirmations
            WHERE admin_id = $1 AND session_id = $2 AND action_type = $3 
            AND used_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            admin_id,
            session_id,
            action_type
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(confirmation)
    }

    pub async fn mark_as_used(&self, confirmation_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE admin_sensitive_confirmations SET used_at = NOW() WHERE id = $1",
            confirmation_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn cleanup_expired_confirmations(&self) -> Result<i64, DatabaseError> {
        let result = sqlx::query!(
            "DELETE FROM admin_sensitive_confirmations WHERE expires_at <= NOW() AND used_at IS NULL"
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected())
    }
}
