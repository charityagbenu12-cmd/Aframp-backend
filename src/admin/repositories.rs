use crate::admin::models::*;
use crate::database::error::DatabaseError;
use chrono::Utc;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use uuid::Uuid;

pub use super::repositories_audit::*;

pub struct AdminAccountRepository {
    pool: PgPool,
}

impl AdminAccountRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_account(
        &self,
        request: CreateAdminAccountRequest,
        created_by: Option<Uuid>,
    ) -> Result<AdminAccount, DatabaseError> {
        let password_hash = bcrypt::hash(&request.temporary_password, bcrypt::DEFAULT_COST)
            .map_err(|e| DatabaseError::Unknown(e.to_string()))?;

        let row = sqlx::query!(
            r#"
            INSERT INTO admin_accounts (full_name, email, password_hash, role, status, created_by)
            VALUES ($1, $2, $3, $4, 'pending_setup', $5)
            RETURNING 
                id, full_name, email, password_hash, role as "role: AdminRole", 
                status as "status: AdminStatus", mfa_status as "mfa_status: MfaStatus",
                mfa_secret, fido2_credentials, last_login_at, last_login_ip,
                failed_login_count, account_locked_until, password_changed_at,
                mfa_configured_at, created_at, updated_at, created_by
            "#,
            request.full_name,
            request.email,
            password_hash,
            request.role as AdminRole,
            created_by
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(AdminAccount {
            id: row.id,
            full_name: row.full_name,
            email: row.email,
            password_hash: row.password_hash,
            role: row.role,
            status: row.status,
            mfa_status: row.mfa_status,
            mfa_secret: row.mfa_secret,
            fido2_credentials: row.fido2_credentials,
            last_login_at: row.last_login_at,
            last_login_ip: row.last_login_ip,
            failed_login_count: row.failed_login_count,
            account_locked_until: row.account_locked_until,
            password_changed_at: row.password_changed_at,
            mfa_configured_at: row.mfa_configured_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            created_by: row.created_by,
        })
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<AdminAccount>, DatabaseError> {
        let row = sqlx::query!(
            r#"
            SELECT 
                id, full_name, email, password_hash, role as "role: AdminRole", 
                status as "status: AdminStatus", mfa_status as "mfa_status: MfaStatus",
                mfa_secret, fido2_credentials, last_login_at, last_login_ip,
                failed_login_count, account_locked_until, password_changed_at,
                mfa_configured_at, created_at, updated_at, created_by
            FROM admin_accounts 
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row.map(|row| AdminAccount {
            id: row.id,
            full_name: row.full_name,
            email: row.email,
            password_hash: row.password_hash,
            role: row.role,
            status: row.status,
            mfa_status: row.mfa_status,
            mfa_secret: row.mfa_secret,
            fido2_credentials: row.fido2_credentials,
            last_login_at: row.last_login_at,
            last_login_ip: row.last_login_ip,
            failed_login_count: row.failed_login_count,
            account_locked_until: row.account_locked_until,
            password_changed_at: row.password_changed_at,
            mfa_configured_at: row.mfa_configured_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            created_by: row.created_by,
        }))
    }

    pub async fn get_by_email(&self, email: &str) -> Result<Option<AdminAccount>, DatabaseError> {
        let row = sqlx::query!(
            r#"
            SELECT 
                id, full_name, email, password_hash, role as "role: AdminRole", 
                status as "status: AdminStatus", mfa_status as "mfa_status: MfaStatus",
                mfa_secret, fido2_credentials, last_login_at, last_login_ip,
                failed_login_count, account_locked_until, password_changed_at,
                mfa_configured_at, created_at, updated_at, created_by
            FROM admin_accounts 
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row.map(|row| AdminAccount {
            id: row.id,
            full_name: row.full_name,
            email: row.email,
            password_hash: row.password_hash,
            role: row.role,
            status: row.status,
            mfa_status: row.mfa_status,
            mfa_secret: row.mfa_secret,
            fido2_credentials: row.fido2_credentials,
            last_login_at: row.last_login_at,
            last_login_ip: row.last_login_ip,
            failed_login_count: row.failed_login_count,
            account_locked_until: row.account_locked_until,
            password_changed_at: row.password_changed_at,
            mfa_configured_at: row.mfa_configured_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            created_by: row.created_by,
        }))
    }

    pub async fn update_role(&self, admin_id: Uuid, new_role: AdminRole) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE admin_accounts SET role = $1, updated_at = NOW() WHERE id = $2",
            new_role as AdminRole,
            admin_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn suspend_account(&self, admin_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE admin_accounts SET status = 'suspended', updated_at = NOW() WHERE id = $1",
            admin_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn reinstate_account(&self, admin_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            UPDATE admin_accounts 
            SET status = 'active', mfa_status = 'required_reconfigure', updated_at = NOW() 
            WHERE id = $1
            "#,
            admin_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn update_password(&self, admin_id: Uuid, new_password: &str) -> Result<(), DatabaseError> {
        let password_hash = bcrypt::hash(new_password, bcrypt::DEFAULT_COST)
            .map_err(|e| DatabaseError::Unknown(e.to_string()))?;

        sqlx::query!(
            r#"
            UPDATE admin_accounts 
            SET password_hash = $1, password_changed_at = NOW(), updated_at = NOW() 
            WHERE id = $2
            "#,
            password_hash,
            admin_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn update_mfa_secret(&self, admin_id: Uuid, secret: &str) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            UPDATE admin_accounts 
            SET mfa_secret = $1, mfa_status = 'configured', mfa_configured_at = NOW(), updated_at = NOW() 
            WHERE id = $2
            "#,
            secret,
            admin_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn update_fido2_credentials(&self, admin_id: Uuid, credentials: serde_json::Value) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            UPDATE admin_accounts 
            SET fido2_credentials = $1, mfa_status = 'configured', mfa_configured_at = NOW(), updated_at = NOW() 
            WHERE id = $2
            "#,
            credentials,
            admin_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn increment_failed_login(&self, admin_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE admin_accounts SET failed_login_count = failed_login_count + 1, updated_at = NOW() WHERE id = $1",
            admin_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn reset_failed_login(&self, admin_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE admin_accounts SET failed_login_count = 0, updated_at = NOW() WHERE id = $1",
            admin_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn lock_account(&self, admin_id: Uuid, lock_duration_minutes: i32) -> Result<(), DatabaseError> {
        let locked_until = Utc::now() + chrono::Duration::minutes(lock_duration_minutes as i64);
        
        sqlx::query!(
            r#"
            UPDATE admin_accounts 
            SET status = 'locked', account_locked_until = $1, updated_at = NOW() 
            WHERE id = $2
            "#,
            locked_until,
            admin_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn unlock_account(&self, admin_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            UPDATE admin_accounts 
            SET status = 'active', account_locked_until = NULL, failed_login_count = 0, updated_at = NOW() 
            WHERE id = $1
            "#,
            admin_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn update_last_login(&self, admin_id: Uuid, ip_address: &str) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            UPDATE admin_accounts 
            SET last_login_at = NOW(), last_login_ip = $1, updated_at = NOW() 
            WHERE id = $2
            "#,
            ip_address,
            admin_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<AdminAccount>, DatabaseError> {
        let rows = sqlx::query!(
            r#"
            SELECT 
                id, full_name, email, password_hash, role as "role: AdminRole", 
                status as "status: AdminStatus", mfa_status as "mfa_status: MfaStatus",
                mfa_secret, fido2_credentials, last_login_at, last_login_ip,
                failed_login_count, account_locked_until, password_changed_at,
                mfa_configured_at, created_at, updated_at, created_by
            FROM admin_accounts 
            ORDER BY created_at DESC 
            LIMIT $1 OFFSET $2
            "#,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(rows.into_iter().map(|row| AdminAccount {
            id: row.id,
            full_name: row.full_name,
            email: row.email,
            password_hash: row.password_hash,
            role: row.role,
            status: row.status,
            mfa_status: row.mfa_status,
            mfa_secret: row.mfa_secret,
            fido2_credentials: row.fido2_credentials,
            last_login_at: row.last_login_at,
            last_login_ip: row.last_login_ip,
            failed_login_count: row.failed_login_count,
            account_locked_until: row.account_locked_until,
            password_changed_at: row.password_changed_at,
            mfa_configured_at: row.mfa_configured_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            created_by: row.created_by,
        }).collect())
    }

    pub async fn count_by_role(&self) -> Result<HashMap<AdminRole, i64>, DatabaseError> {
        let rows = sqlx::query!(
            "SELECT role as \"role: AdminRole\", COUNT(*) as count FROM admin_accounts GROUP BY role"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        let mut counts = HashMap::new();
        for row in rows {
            counts.insert(row.role, row.count);
        }

        Ok(counts)
    }

    pub async fn get_statistics(&self) -> Result<AdminStatistics, DatabaseError> {
        let total_accounts = sqlx::query_scalar!("SELECT COUNT(*) FROM admin_accounts")
            .fetch_one(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?
            .unwrap_or(0);

        let active_accounts = sqlx::query_scalar!("SELECT COUNT(*) FROM admin_accounts WHERE status = 'active'")
            .fetch_one(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?
            .unwrap_or(0);

        let suspended_accounts = sqlx::query_scalar!("SELECT COUNT(*) FROM admin_accounts WHERE status = 'suspended'")
            .fetch_one(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?
            .unwrap_or(0);

        let locked_accounts = sqlx::query_scalar!("SELECT COUNT(*) FROM admin_accounts WHERE status = 'locked'")
            .fetch_one(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?
            .unwrap_or(0);

        let active_sessions = sqlx::query_scalar!("SELECT COUNT(*) FROM admin_sessions WHERE status = 'active' AND expires_at > NOW()")
            .fetch_one(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?
            .unwrap_or(0);

        let recent_logins = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM admin_accounts WHERE last_login_at > NOW() - INTERVAL '24 hours'"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?
        .unwrap_or(0);

        let failed_login_attempts = sqlx::query_scalar!("SELECT SUM(failed_login_count) FROM admin_accounts")
            .fetch_one(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?
            .unwrap_or(0);

        let accounts_by_role = self.count_by_role().await?;

        Ok(AdminStatistics {
            total_accounts,
            active_accounts,
            suspended_accounts,
            locked_accounts,
            active_sessions,
            accounts_by_role,
            recent_logins,
            failed_login_attempts,
        })
    }
}

pub struct AdminSessionRepository {
    pool: PgPool,
}

impl AdminSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_session(
        &self,
        admin_id: Uuid,
        expires_at: chrono::DateTime<Utc>,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<AdminSession, DatabaseError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO admin_sessions (admin_id, expires_at, ip_address, user_agent)
            VALUES ($1, $2, $3, $4)
            RETURNING 
                id, admin_id, issued_at, expires_at, last_activity_at,
                ip_address, user_agent, mfa_verified, status as "status: SessionStatus",
                termination_reason, terminated_at, created_at
            "#,
            admin_id,
            expires_at,
            ip_address,
            user_agent
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(AdminSession {
            id: row.id,
            admin_id: row.admin_id,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            last_activity_at: row.last_activity_at,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            mfa_verified: row.mfa_verified,
            status: row.status,
            termination_reason: row.termination_reason,
            terminated_at: row.terminated_at,
            created_at: row.created_at,
        })
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<AdminSession>, DatabaseError> {
        let row = sqlx::query!(
            r#"
            SELECT 
                id, admin_id, issued_at, expires_at, last_activity_at,
                ip_address, user_agent, mfa_verified, status as "status: SessionStatus",
                termination_reason, terminated_at, created_at
            FROM admin_sessions 
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row.map(|row| AdminSession {
            id: row.id,
            admin_id: row.admin_id,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            last_activity_at: row.last_activity_at,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            mfa_verified: row.mfa_verified,
            status: row.status,
            termination_reason: row.termination_reason,
            terminated_at: row.terminated_at,
            created_at: row.created_at,
        }))
    }

    pub async fn update_mfa_verified(&self, session_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE admin_sessions SET mfa_verified = true WHERE id = $1",
            session_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn update_last_activity(&self, session_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE admin_sessions SET last_activity_at = NOW() WHERE id = $1",
            session_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn terminate_session(&self, session_id: Uuid, reason: &str) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            UPDATE admin_sessions 
            SET status = 'terminated', termination_reason = $1, terminated_at = NOW() 
            WHERE id = $2
            "#,
            reason,
            session_id
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }

    pub async fn terminate_all_sessions(&self, admin_id: Uuid, exclude_session_id: Option<Uuid>) -> Result<(), DatabaseError> {
        if let Some(exclude_id) = exclude_session_id {
            sqlx::query!(
                r#"
                UPDATE admin_sessions 
                SET status = 'terminated', termination_reason = 'All sessions terminated', terminated_at = NOW() 
                WHERE admin_id = $1 AND id != $2 AND status = 'active'
                "#,
                admin_id,
                exclude_id
            )
            .execute(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;
        } else {
            sqlx::query!(
                r#"
                UPDATE admin_sessions 
                SET status = 'terminated', termination_reason = 'All sessions terminated', terminated_at = NOW() 
                WHERE admin_id = $1 AND status = 'active'
                "#,
                admin_id
            )
            .execute(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;
        }

        Ok(())
    }

    pub async fn get_active_sessions(&self, admin_id: Uuid) -> Result<Vec<ActiveAdminSession>, DatabaseError> {
        let rows = sqlx::query_as!(
            ActiveAdminSession,
            r#"
            SELECT 
                s.id, s.admin_id, a.full_name, a.email, a.role as "role: AdminRole",
                s.issued_at, s.expires_at, s.last_activity_at, s.ip_address, 
                s.user_agent, s.mfa_verified
            FROM admin_sessions s
            JOIN admin_accounts a ON s.admin_id = a.id
            WHERE s.admin_id = $1 AND s.status = 'active' AND s.expires_at > NOW()
            ORDER BY s.last_activity_at DESC
            "#,
            admin_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(rows)
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<i64, DatabaseError> {
        let result = sqlx::query!(
            r#"
            UPDATE admin_sessions 
            SET status = 'expired', terminated_at = NOW() 
            WHERE status = 'active' AND expires_at <= NOW()
            "#
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(result.rows_affected())
    }

    pub async fn enforce_concurrent_session_limit(&self, admin_id: Uuid, max_sessions: i32) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"
            WITH ranked_sessions AS (
                SELECT id, ROW_NUMBER() OVER (ORDER BY last_activity_at DESC) as rn
                FROM admin_sessions 
                WHERE admin_id = $1 AND status = 'active' AND expires_at > NOW()
            )
            UPDATE admin_sessions 
            SET status = 'terminated', termination_reason = 'Concurrent session limit exceeded', terminated_at = NOW()
            WHERE id IN (SELECT id FROM ranked_sessions WHERE rn > $2)
            "#,
            admin_id,
            max_sessions
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(())
    }
}
