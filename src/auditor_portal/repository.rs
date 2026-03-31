use crate::auditor_portal::models::*;
use crate::database::error::DatabaseError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct AuditorRepository {
    pool: PgPool,
}

impl AuditorRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ── Account ───────────────────────────────────────────────────────────────

    pub async fn create_account(
        &self,
        req: &CreateAuditorRequest,
        password_hash: &str,
    ) -> Result<AuditorAccount, DatabaseError> {
        let row = sqlx::query!(
            r#"INSERT INTO auditor_accounts (email, display_name, organisation, password_hash)
               VALUES ($1, $2, $3, $4)
               RETURNING id, email, display_name, organisation, mfa_enabled, is_active, created_at"#,
            req.email,
            req.display_name,
            req.organisation,
            password_hash,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(AuditorAccount {
            id: row.id,
            email: row.email,
            display_name: row.display_name,
            organisation: row.organisation,
            mfa_enabled: row.mfa_enabled,
            is_active: row.is_active,
            created_at: row.created_at,
        })
    }

    pub async fn find_account_by_email(
        &self,
        email: &str,
    ) -> Result<Option<(AuditorAccount, String, Option<String>)>, DatabaseError> {
        let row = sqlx::query!(
            r#"SELECT id, email, display_name, organisation, password_hash,
                      totp_secret_enc, mfa_enabled, is_active, created_at
               FROM auditor_accounts WHERE email = $1"#,
            email,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row.map(|r| {
            (
                AuditorAccount {
                    id: r.id,
                    email: r.email,
                    display_name: r.display_name,
                    organisation: r.organisation,
                    mfa_enabled: r.mfa_enabled,
                    is_active: r.is_active,
                    created_at: r.created_at,
                },
                r.password_hash,
                r.totp_secret_enc,
            )
        }))
    }

    pub async fn set_totp_secret(
        &self,
        auditor_id: Uuid,
        encrypted_secret: &str,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE auditor_accounts SET totp_secret_enc = $1, mfa_enabled = TRUE, updated_at = NOW()
             WHERE id = $2",
            encrypted_secret,
            auditor_id,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    // ── IP whitelist ──────────────────────────────────────────────────────────

    pub async fn add_ip_whitelist(
        &self,
        req: &AddIpWhitelistRequest,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            "INSERT INTO auditor_ip_whitelist (auditor_id, cidr, label) VALUES ($1, $2::inet, $3)",
            req.auditor_id,
            req.cidr,
            req.label,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    /// Returns true if `ip` falls within any whitelisted CIDR for this auditor.
    pub async fn is_ip_allowed(
        &self,
        auditor_id: Uuid,
        ip: &str,
    ) -> Result<bool, DatabaseError> {
        let allowed = sqlx::query_scalar!(
            "SELECT EXISTS(
                SELECT 1 FROM auditor_ip_whitelist
                WHERE auditor_id = $1 AND $2::inet <<= cidr
             )",
            auditor_id,
            ip,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(allowed.unwrap_or(false))
    }

    // ── Access windows ────────────────────────────────────────────────────────

    pub async fn create_access_window(
        &self,
        req: &CreateAccessWindowRequest,
        granted_by: Uuid,
    ) -> Result<AuditorAccessWindow, DatabaseError> {
        let row = sqlx::query!(
            r#"INSERT INTO auditor_access_windows
               (auditor_id, scope_label, data_from, data_to, access_from, access_to, granted_by)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id, auditor_id, scope_label, data_from, data_to, access_from, access_to"#,
            req.auditor_id,
            req.scope_label,
            req.data_from,
            req.data_to,
            req.access_from,
            req.access_to,
            granted_by,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(AuditorAccessWindow {
            id: row.id,
            auditor_id: row.auditor_id,
            scope_label: row.scope_label,
            data_from: row.data_from,
            data_to: row.data_to,
            access_from: row.access_from,
            access_to: row.access_to,
        })
    }

    /// Find the active access window for an auditor (access_from <= now <= access_to).
    pub async fn find_active_window(
        &self,
        auditor_id: Uuid,
    ) -> Result<Option<AuditorAccessWindow>, DatabaseError> {
        let now = Utc::now();
        let row = sqlx::query!(
            r#"SELECT id, auditor_id, scope_label, data_from, data_to, access_from, access_to
               FROM auditor_access_windows
               WHERE auditor_id = $1 AND access_from <= $2 AND access_to >= $2
               ORDER BY access_to DESC LIMIT 1"#,
            auditor_id,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row.map(|r| AuditorAccessWindow {
            id: r.id,
            auditor_id: r.auditor_id,
            scope_label: r.scope_label,
            data_from: r.data_from,
            data_to: r.data_to,
            access_from: r.access_from,
            access_to: r.access_to,
        }))
    }

    // ── Sessions ──────────────────────────────────────────────────────────────

    pub async fn create_session(
        &self,
        auditor_id: Uuid,
        window_id: Uuid,
        token: &str,
        ip: &str,
        user_agent: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, DatabaseError> {
        let id = sqlx::query_scalar!(
            r#"INSERT INTO auditor_sessions (auditor_id, window_id, session_token, ip_address, user_agent, expires_at)
               VALUES ($1, $2, $3, $4::inet, $5, $6)
               RETURNING id"#,
            auditor_id,
            window_id,
            token,
            ip,
            user_agent,
            expires_at,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(id)
    }

    pub async fn find_session(&self, token: &str) -> Result<Option<AuditorSession>, DatabaseError> {
        let row = sqlx::query!(
            r#"SELECT s.id, s.auditor_id, s.window_id, s.session_token,
                      s.ip_address::text as ip_address, s.expires_at, s.terminated_at,
                      w.data_from, w.data_to
               FROM auditor_sessions s
               JOIN auditor_access_windows w ON w.id = s.window_id
               WHERE s.session_token = $1"#,
            token,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(row.and_then(|r| {
            // Reject terminated or expired sessions
            if r.terminated_at.is_some() || r.expires_at < Utc::now() {
                return None;
            }
            Some(AuditorSession {
                id: r.id,
                auditor_id: r.auditor_id,
                window_id: r.window_id,
                session_token: r.session_token,
                ip_address: r.ip_address.unwrap_or_default(),
                expires_at: r.expires_at,
                data_from: r.data_from,
                data_to: r.data_to,
            })
        }))
    }

    pub async fn terminate_session(&self, session_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE auditor_sessions SET terminated_at = NOW() WHERE id = $1",
            session_id,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    // ── Access log ────────────────────────────────────────────────────────────

    pub async fn log_access(
        &self,
        session_id: Uuid,
        auditor_id: Uuid,
        action: &str,
        query_params: Option<serde_json::Value>,
        row_count: Option<i64>,
        file_checksum: Option<&str>,
        file_name: Option<&str>,
        ip: &str,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"INSERT INTO auditor_access_log
               (session_id, auditor_id, action, query_params, row_count, file_checksum, file_name, ip_address)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet)"#,
            session_id,
            auditor_id,
            action,
            query_params,
            row_count,
            file_checksum,
            file_name,
            ip,
        )
        .execute(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn list_access_log(
        &self,
        auditor_id: Option<Uuid>,
        session_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditorAccessLogEntry>, DatabaseError> {
        // Build dynamic query
        use sqlx::QueryBuilder;
        let mut qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
            "SELECT id, session_id, auditor_id, action, query_params, row_count,
                    file_checksum, file_name, ip_address::text as ip_address, created_at
             FROM auditor_access_log",
        );
        let mut first = true;
        if let Some(aid) = auditor_id {
            qb.push(" WHERE auditor_id = ").push_bind(aid);
            first = false;
        }
        if let Some(sid) = session_id {
            if first { qb.push(" WHERE "); } else { qb.push(" AND "); }
            qb.push("session_id = ").push_bind(sid);
        }
        qb.push(" ORDER BY created_at DESC LIMIT ").push_bind(limit)
          .push(" OFFSET ").push_bind(offset);

        let rows = qb
            .build_query_as::<AccessLogRow>()
            .fetch_all(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;

        Ok(rows.into_iter().map(|r| AuditorAccessLogEntry {
            id: r.id,
            session_id: r.session_id,
            auditor_id: r.auditor_id,
            action: r.action,
            query_params: r.query_params,
            row_count: r.row_count,
            file_checksum: r.file_checksum,
            file_name: r.file_name,
            ip_address: r.ip_address.unwrap_or_default(),
            created_at: r.created_at,
        }).collect())
    }

    // ── Quarterly packets ─────────────────────────────────────────────────────

    pub async fn upsert_quarterly_packet(
        &self,
        quarter_label: &str,
        data_from: DateTime<Utc>,
        data_to: DateTime<Utc>,
        checksum: &str,
        row_count: i64,
        generated_by: &str,
    ) -> Result<QuarterlyPacket, DatabaseError> {
        let row = sqlx::query!(
            r#"INSERT INTO auditor_quarterly_packets
               (quarter_label, data_from, data_to, checksum, row_count, generated_by)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (quarter_label) DO UPDATE
               SET checksum = EXCLUDED.checksum,
                   row_count = EXCLUDED.row_count,
                   generated_at = NOW(),
                   generated_by = EXCLUDED.generated_by
               RETURNING id, quarter_label, data_from, data_to, checksum, row_count, generated_at"#,
            quarter_label,
            data_from,
            data_to,
            checksum,
            row_count,
            generated_by,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(QuarterlyPacket {
            id: row.id,
            quarter_label: row.quarter_label,
            data_from: row.data_from,
            data_to: row.data_to,
            checksum: row.checksum,
            row_count: row.row_count,
            generated_at: row.generated_at,
        })
    }

    pub async fn list_quarterly_packets(&self) -> Result<Vec<QuarterlyPacket>, DatabaseError> {
        let rows = sqlx::query!(
            "SELECT id, quarter_label, data_from, data_to, checksum, row_count, generated_at
             FROM auditor_quarterly_packets ORDER BY data_from DESC"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)?;

        Ok(rows.into_iter().map(|r| QuarterlyPacket {
            id: r.id,
            quarter_label: r.quarter_label,
            data_from: r.data_from,
            data_to: r.data_to,
            checksum: r.checksum,
            row_count: r.row_count,
            generated_at: r.generated_at,
        }).collect())
    }
}

// ── Internal row type for sqlx mapping ───────────────────────────────────────

#[derive(sqlx::FromRow)]
struct AccessLogRow {
    id: Uuid,
    session_id: Uuid,
    auditor_id: Uuid,
    action: String,
    query_params: Option<serde_json::Value>,
    row_count: Option<i64>,
    file_checksum: Option<String>,
    file_name: Option<String>,
    ip_address: Option<String>,
    created_at: DateTime<Utc>,
}
