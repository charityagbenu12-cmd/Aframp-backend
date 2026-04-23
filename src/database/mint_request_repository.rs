//! Repository for mint request approval workflow
//!
//! Provides CRUD and query operations for:
//! - `mint_requests`   — the request entity with state machine status
//! - `mint_approvals`  — individual approver signatures
//! - `mint_audit_log`  — immutable audit trail

use crate::database::error::DatabaseError;
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

// ============================================================================
// Entities
// ============================================================================

/// A mint request record
#[derive(Debug, Clone, FromRow)]
pub struct MintRequest {
    pub id: Uuid,
    pub submitted_by: String,
    pub destination_wallet: String,
    pub amount_ngn: BigDecimal,
    pub amount_cngn: BigDecimal,
    pub rate_snapshot: BigDecimal,
    pub approval_tier: i16,
    pub required_approvals: i16,
    pub status: String,
    pub reference: Option<String>,
    pub metadata: JsonValue,
    pub expires_at: DateTime<Utc>,
    pub stellar_tx_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A single approver signature on a mint request
#[derive(Debug, Clone, FromRow)]
pub struct MintApproval {
    pub id: Uuid,
    pub mint_request_id: Uuid,
    pub approver_id: String,
    pub approver_role: String,
    pub action: String,
    pub reason_code: Option<String>,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// An immutable audit log entry
#[derive(Debug, Clone, FromRow)]
pub struct MintAuditLog {
    pub id: i64,
    pub mint_request_id: Uuid,
    pub actor_id: String,
    pub actor_role: Option<String>,
    pub event_type: String,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    pub payload: JsonValue,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Repository
// ============================================================================

pub struct MintRequestRepository {
    pool: PgPool,
}

impl MintRequestRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Expose the pool for services that need to run ad-hoc queries.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // -------------------------------------------------------------------------
    // MintRequest CRUD
    // -------------------------------------------------------------------------

    /// Create a new mint request in `pending_approval` state.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        submitted_by: &str,
        destination_wallet: &str,
        amount_ngn: BigDecimal,
        amount_cngn: BigDecimal,
        rate_snapshot: BigDecimal,
        approval_tier: u8,
        required_approvals: u8,
        reference: Option<String>,
        metadata: JsonValue,
    ) -> Result<MintRequest, DatabaseError> {
        sqlx::query_as::<_, MintRequest>(
            r#"
            INSERT INTO mint_requests
                (submitted_by, destination_wallet, amount_ngn, amount_cngn,
                 rate_snapshot, approval_tier, required_approvals, reference, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(submitted_by)
        .bind(destination_wallet)
        .bind(amount_ngn)
        .bind(amount_cngn)
        .bind(rate_snapshot)
        .bind(approval_tier as i16)
        .bind(required_approvals as i16)
        .bind(reference)
        .bind(metadata)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Fetch a mint request by its UUID.
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<MintRequest>, DatabaseError> {
        sqlx::query_as::<_, MintRequest>("SELECT * FROM mint_requests WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)
    }

    /// Update the status (and optionally the stellar_tx_hash) of a mint request.
    pub async fn update_status(
        &self,
        id: Uuid,
        new_status: &str,
        stellar_tx_hash: Option<&str>,
    ) -> Result<MintRequest, DatabaseError> {
        sqlx::query_as::<_, MintRequest>(
            r#"
            UPDATE mint_requests
               SET status = $2,
                   stellar_tx_hash = COALESCE($3, stellar_tx_hash),
                   updated_at = CURRENT_TIMESTAMP
             WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(new_status)
        .bind(stellar_tx_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// List mint requests with optional status filter and pagination.
    pub async fn list(
        &self,
        status_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<MintRequest>, i64), DatabaseError> {
        let (rows, total) = if let Some(status) = status_filter {
            let rows = sqlx::query_as::<_, MintRequest>(
                "SELECT * FROM mint_requests WHERE status = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(status)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;

            let total: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM mint_requests WHERE status = $1")
                    .bind(status)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(DatabaseError::from_sqlx)?;

            (rows, total)
        } else {
            let rows = sqlx::query_as::<_, MintRequest>(
                "SELECT * FROM mint_requests ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(DatabaseError::from_sqlx)?;

            let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mint_requests")
                .fetch_one(&self.pool)
                .await
                .map_err(DatabaseError::from_sqlx)?;

            (rows, total)
        };

        Ok((rows, total))
    }

    // -------------------------------------------------------------------------
    // MintApproval operations
    // -------------------------------------------------------------------------

    /// Persist an approval or rejection signature.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_approval(
        &self,
        mint_request_id: Uuid,
        approver_id: &str,
        approver_role: &str,
        action: &str,
        reason_code: Option<&str>,
        comment: Option<&str>,
    ) -> Result<MintApproval, DatabaseError> {
        sqlx::query_as::<_, MintApproval>(
            r#"
            INSERT INTO mint_approvals
                (mint_request_id, approver_id, approver_role, action, reason_code, comment)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(mint_request_id)
        .bind(approver_id)
        .bind(approver_role)
        .bind(action)
        .bind(reason_code)
        .bind(comment)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// List all approvals for a mint request, ordered by creation time.
    pub async fn list_approvals(
        &self,
        mint_request_id: Uuid,
    ) -> Result<Vec<MintApproval>, DatabaseError> {
        sqlx::query_as::<_, MintApproval>(
            "SELECT * FROM mint_approvals WHERE mint_request_id = $1 ORDER BY created_at ASC",
        )
        .bind(mint_request_id)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Find a specific approver's action on a request (for duplicate check).
    pub async fn find_approval_by_approver(
        &self,
        mint_request_id: Uuid,
        approver_id: &str,
    ) -> Result<Option<MintApproval>, DatabaseError> {
        sqlx::query_as::<_, MintApproval>(
            "SELECT * FROM mint_approvals WHERE mint_request_id = $1 AND approver_id = $2",
        )
        .bind(mint_request_id)
        .bind(approver_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    // -------------------------------------------------------------------------
    // Audit log
    // -------------------------------------------------------------------------

    /// Append an immutable audit log entry.
    #[allow(clippy::too_many_arguments)]
    pub async fn append_audit(
        &self,
        mint_request_id: Uuid,
        actor_id: &str,
        actor_role: Option<&str>,
        event_type: &str,
        from_status: Option<&str>,
        to_status: Option<&str>,
        payload: JsonValue,
    ) -> Result<MintAuditLog, DatabaseError> {
        sqlx::query_as::<_, MintAuditLog>(
            r#"
            INSERT INTO mint_audit_log
                (mint_request_id, actor_id, actor_role, event_type, from_status, to_status, payload)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(mint_request_id)
        .bind(actor_id)
        .bind(actor_role)
        .bind(event_type)
        .bind(from_status)
        .bind(to_status)
        .bind(payload)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }

    /// Fetch the full audit trail for a mint request.
    pub async fn list_audit(
        &self,
        mint_request_id: Uuid,
    ) -> Result<Vec<MintAuditLog>, DatabaseError> {
        sqlx::query_as::<_, MintAuditLog>(
            "SELECT * FROM mint_audit_log WHERE mint_request_id = $1 ORDER BY created_at ASC",
        )
        .bind(mint_request_id)
        .fetch_all(&self.pool)
        .await
        .map_err(DatabaseError::from_sqlx)
    }
}
