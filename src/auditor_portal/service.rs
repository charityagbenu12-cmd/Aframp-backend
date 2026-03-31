//! Core business logic for the external auditor portal.
//!
//! Responsibilities:
//! - Authenticate auditors (password + TOTP MFA)
//! - Enforce IP whitelist and time-limited access windows
//! - Export evidence packages (mint events, burn events, bank snapshots)
//! - Verify Stellar ledger hash integrity
//! - Generate quarterly audit packets with SHA-256 checksums
//! - Log every auditor action (audit-of-the-auditor)

use crate::audit::repository::AuditLogRepository;
use crate::auditor_portal::{
    models::*,
    repository::AuditorRepository,
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::{DateTime, Datelike, Duration, Utc};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

#[derive(Clone)]
pub struct AuditorService {
    repo: Arc<AuditorRepository>,
    audit_repo: Arc<AuditLogRepository>,
    /// Session lifetime in hours (default 48)
    session_hours: i64,
}

impl AuditorService {
    pub fn new(
        repo: Arc<AuditorRepository>,
        audit_repo: Arc<AuditLogRepository>,
    ) -> Self {
        let session_hours = std::env::var("AUDITOR_SESSION_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(48);
        Self { repo, audit_repo, session_hours }
    }

    // ── Authentication ────────────────────────────────────────────────────────

    pub async fn login(
        &self,
        req: &AuditorLoginRequest,
        ip: &str,
        user_agent: Option<&str>,
    ) -> Result<AuditorLoginResponse, AuditorError> {
        // 1. Load account
        let (account, password_hash, totp_secret_enc) = self
            .repo
            .find_account_by_email(&req.email)
            .await
            .map_err(AuditorError::Db)?
            .ok_or(AuditorError::InvalidCredentials)?;

        if !account.is_active {
            return Err(AuditorError::AccountDisabled);
        }

        // 2. Verify password (Argon2id)
        let parsed = PasswordHash::new(&password_hash)
            .map_err(|_| AuditorError::InvalidCredentials)?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed)
            .map_err(|_| AuditorError::InvalidCredentials)?;

        // 3. Verify TOTP (MFA mandatory)
        let secret_enc = totp_secret_enc.ok_or(AuditorError::MfaNotConfigured)?;
        let totp = build_totp(&secret_enc)?;
        if !totp.check_current(&req.totp_code).map_err(|_| AuditorError::InvalidTotp)? {
            return Err(AuditorError::InvalidTotp);
        }

        // 4. Check IP whitelist
        let allowed = self
            .repo
            .is_ip_allowed(account.id, ip)
            .await
            .map_err(AuditorError::Db)?;
        if !allowed {
            tracing::warn!(auditor_id = %account.id, ip, "Auditor login blocked: IP not whitelisted");
            return Err(AuditorError::IpNotAllowed);
        }

        // 5. Find active access window
        let window = self
            .repo
            .find_active_window(account.id)
            .await
            .map_err(AuditorError::Db)?
            .ok_or(AuditorError::NoActiveWindow)?;

        // 6. Create session
        let token = generate_token();
        let expires_at = Utc::now() + Duration::hours(self.session_hours);
        self.repo
            .create_session(account.id, window.id, &token, ip, user_agent, expires_at)
            .await
            .map_err(AuditorError::Db)?;

        tracing::info!(auditor_id = %account.id, scope = %window.scope_label, "Auditor session created");

        Ok(AuditorLoginResponse {
            session_token: token,
            expires_at,
            scope_label: window.scope_label,
            data_from: window.data_from,
            data_to: window.data_to,
        })
    }

    pub async fn logout(&self, session: &AuditorSession) -> Result<(), AuditorError> {
        self.repo
            .terminate_session(session.id)
            .await
            .map_err(AuditorError::Db)
    }

    /// Validate a session token and return the session (enforces IP match).
    pub async fn validate_session(
        &self,
        token: &str,
        ip: &str,
    ) -> Result<AuditorSession, AuditorError> {
        let session = self
            .repo
            .find_session(token)
            .await
            .map_err(AuditorError::Db)?
            .ok_or(AuditorError::SessionInvalid)?;

        // Enforce IP consistency within a session
        if session.ip_address != ip {
            tracing::warn!(
                session_id = %session.id,
                expected_ip = %session.ip_address,
                actual_ip = ip,
                "Auditor session IP mismatch"
            );
            return Err(AuditorError::IpNotAllowed);
        }

        Ok(session)
    }

    // ── Evidence export ───────────────────────────────────────────────────────

    /// Export audit events within the session's permitted date range.
    /// Returns (entries, sha256_checksum, filename).
    pub async fn export_evidence(
        &self,
        session: &AuditorSession,
        query: &AuditExportQuery,
    ) -> Result<(Vec<serde_json::Value>, String, String), AuditorError> {
        // Clamp requested range to the window's permitted range
        let from = query.date_from.unwrap_or(session.data_from).max(session.data_from);
        let to = query.date_to.unwrap_or(session.data_to).min(session.data_to);

        if from > to {
            return Err(AuditorError::InvalidDateRange);
        }

        // Build filter for the audit log
        let mut filter = crate::audit::models::AuditLogFilter {
            date_from: Some(from),
            date_to: Some(to),
            event_category: None,
            actor_id: query.redemption_id.clone(),
            actor_type: None,
            target_resource_type: None,
            target_resource_id: query.redemption_id.clone(),
            outcome: None,
            environment: None,
            page: Some(1),
            page_size: Some(query.max_rows.unwrap_or(5_000).min(10_000)),
        };

        // Filter by event type if requested
        let entries = self
            .audit_repo
            .export(&filter, filter.page_size.unwrap_or(5_000))
            .await
            .map_err(|e| AuditorError::Internal(e.to_string()))?;

        // Optionally filter by event_type in memory (audit repo doesn't expose this filter)
        let entries: Vec<_> = entries
            .into_iter()
            .filter(|e| {
                query.event_type.as_ref().map_or(true, |t| &e.event_type == t)
            })
            .collect();

        let payload: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| serde_json::to_value(e).unwrap_or_default())
            .collect();

        let json_bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let checksum = sha256_hex(&json_bytes);
        let filename = format!(
            "evidence_{}_{}.json",
            from.format("%Y%m%d"),
            to.format("%Y%m%d")
        );

        // Log the access
        let _ = self.repo.log_access(
            session.id,
            session.auditor_id,
            "export_evidence",
            Some(serde_json::json!({
                "from": from, "to": to,
                "event_type": query.event_type,
                "redemption_id": query.redemption_id,
                "format": query.format,
            })),
            Some(payload.len() as i64),
            Some(&checksum),
            Some(&filename),
            &session.ip_address,
        ).await;

        Ok((payload, checksum, filename))
    }

    // ── Hash chain verification ───────────────────────────────────────────────

    pub async fn verify_hash_chain(
        &self,
        session: &AuditorSession,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<crate::audit::models::HashChainVerificationResult, AuditorError> {
        let from = from.max(session.data_from);
        let to = to.min(session.data_to);

        let result = self
            .audit_repo
            .verify_hash_chain(from, to)
            .await
            .map_err(|e| AuditorError::Internal(e.to_string()))?;

        let _ = self.repo.log_access(
            session.id,
            session.auditor_id,
            "verify_hash_chain",
            Some(serde_json::json!({ "from": from, "to": to })),
            Some(result.total_checked),
            None,
            None,
            &session.ip_address,
        ).await;

        Ok(result)
    }

    // ── Quarterly packet ──────────────────────────────────────────────────────

    /// Generate (or regenerate) the quarterly audit packet for the given quarter.
    /// `quarter_label` format: "Q1-2026"
    pub async fn generate_quarterly_packet(
        &self,
        quarter_label: &str,
        generated_by: &str,
    ) -> Result<QuarterlyPacket, AuditorError> {
        let (data_from, data_to) = parse_quarter_label(quarter_label)
            .ok_or(AuditorError::InvalidQuarterLabel)?;

        let filter = crate::audit::models::AuditLogFilter {
            date_from: Some(data_from),
            date_to: Some(data_to),
            event_category: None,
            actor_id: None,
            actor_type: None,
            target_resource_type: None,
            target_resource_id: None,
            outcome: None,
            environment: None,
            page: Some(1),
            page_size: Some(10_000),
        };

        let entries = self
            .audit_repo
            .export(&filter, 10_000)
            .await
            .map_err(|e| AuditorError::Internal(e.to_string()))?;

        let row_count = entries.len() as i64;
        let payload = serde_json::json!({
            "quarter": quarter_label,
            "data_from": data_from,
            "data_to": data_to,
            "generated_at": Utc::now(),
            "entries": entries,
        });
        let bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let checksum = sha256_hex(&bytes);

        let packet = self
            .repo
            .upsert_quarterly_packet(quarter_label, data_from, data_to, &checksum, row_count, generated_by)
            .await
            .map_err(AuditorError::Db)?;

        tracing::info!(quarter = quarter_label, rows = row_count, checksum = %checksum, "Quarterly audit packet generated");
        Ok(packet)
    }

    pub async fn list_quarterly_packets(&self) -> Result<Vec<QuarterlyPacket>, AuditorError> {
        self.repo.list_quarterly_packets().await.map_err(AuditorError::Db)
    }

    // ── Admin helpers ─────────────────────────────────────────────────────────

    pub async fn create_auditor(
        &self,
        req: &CreateAuditorRequest,
    ) -> Result<AuditorAccount, AuditorError> {
        let hash = hash_password(&req.password)?;
        self.repo.create_account(req, &hash).await.map_err(AuditorError::Db)
    }

    pub async fn create_access_window(
        &self,
        req: &CreateAccessWindowRequest,
        granted_by: Uuid,
    ) -> Result<AuditorAccessWindow, AuditorError> {
        self.repo.create_access_window(req, granted_by).await.map_err(AuditorError::Db)
    }

    pub async fn add_ip_whitelist(
        &self,
        req: &AddIpWhitelistRequest,
    ) -> Result<(), AuditorError> {
        self.repo.add_ip_whitelist(req).await.map_err(AuditorError::Db)
    }

    pub async fn list_access_log(
        &self,
        auditor_id: Option<Uuid>,
        session_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditorAccessLogEntry>, AuditorError> {
        self.repo
            .list_access_log(auditor_id, session_id, limit, offset)
            .await
            .map_err(AuditorError::Db)
    }
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AuditorError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Account is disabled")]
    AccountDisabled,
    #[error("MFA not configured — contact your administrator")]
    MfaNotConfigured,
    #[error("Invalid TOTP code")]
    InvalidTotp,
    #[error("IP address not whitelisted")]
    IpNotAllowed,
    #[error("No active audit window for this account")]
    NoActiveWindow,
    #[error("Session is invalid or expired")]
    SessionInvalid,
    #[error("Requested date range is outside your permitted window")]
    InvalidDateRange,
    #[error("Invalid quarter label — expected format: Q1-2026")]
    InvalidQuarterLabel,
    #[error("Database error: {0}")]
    Db(#[from] crate::database::error::DatabaseError),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl AuditorError {
    pub fn status_code(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Self::InvalidCredentials | Self::InvalidTotp => StatusCode::UNAUTHORIZED,
            Self::AccountDisabled | Self::IpNotAllowed | Self::NoActiveWindow => StatusCode::FORBIDDEN,
            Self::SessionInvalid => StatusCode::UNAUTHORIZED,
            Self::InvalidDateRange | Self::InvalidQuarterLabel => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hash_password(password: &str) -> Result<String, AuditorError> {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut rand::thread_rng());
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AuditorError::Internal(e.to_string()))
}

fn build_totp(secret_enc: &str) -> Result<TOTP, AuditorError> {
    // In production the secret would be decrypted via the platform key store.
    // Here we treat the stored value as the base32 secret directly.
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret_enc.to_string())
            .to_bytes()
            .map_err(|e| AuditorError::Internal(e.to_string()))?,
    )
    .map_err(|e| AuditorError::Internal(e.to_string()))
}

fn generate_token() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Parse "Q1-2026" → (start, end) UTC timestamps.
fn parse_quarter_label(label: &str) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let parts: Vec<&str> = label.split('-').collect();
    if parts.len() != 2 { return None; }
    let quarter: u32 = parts[0].strip_prefix('Q')?.parse().ok()?;
    let year: i32 = parts[1].parse().ok()?;
    if !(1..=4).contains(&quarter) { return None; }

    let start_month = ((quarter - 1) * 3 + 1) as u32;
    let end_month = start_month + 2;
    let end_day = days_in_month(year, end_month);

    use chrono::NaiveDate;
    let start = NaiveDate::from_ymd_opt(year, start_month, 1)?
        .and_hms_opt(0, 0, 0)?
        .and_utc();
    let end = NaiveDate::from_ymd_opt(year, end_month, end_day)?
        .and_hms_opt(23, 59, 59)?
        .and_utc();
    Some((start, end))
}

fn days_in_month(year: i32, month: u32) -> u32 {
    use chrono::NaiveDate;
    let next = if month == 12 {
        NaiveDate::from_ymd_opt(year + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(year, month + 1, 1)
    };
    next.map(|d| (d - chrono::Duration::days(1)).day()).unwrap_or(30)
}
