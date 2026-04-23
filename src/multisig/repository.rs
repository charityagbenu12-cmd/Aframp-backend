//! Database repository for the Multi-Sig Governance module.
//!
//! All SQL is written as raw `sqlx::query!` / `sqlx::query_as!` macros so
//! compile-time query verification is available when `DATABASE_URL` is set.

use crate::multisig::{
    error::MultiSigError,
    models::{
        GovernanceLogEntry, MultiSigOpType, MultiSigProposal, MultiSigProposalStatus,
        MultiSigSignature, QuorumConfig,
    },
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub struct MultiSigRepository {
    db: PgPool,
}

impl MultiSigRepository {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Quorum configuration
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn get_quorum_config(
        &self,
        op_type: MultiSigOpType,
    ) -> Result<QuorumConfig, MultiSigError> {
        let row = sqlx::query_as!(
            QuorumConfig,
            r#"
            SELECT
                id,
                op_type AS "op_type: MultiSigOpType",
                required_signatures,
                total_signers,
                time_lock_seconds,
                updated_by,
                updated_at
            FROM multisig_quorum_config
            WHERE op_type = $1
            "#,
            op_type as MultiSigOpType,
        )
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| MultiSigError::MissingQuorumConfig(op_type.to_string()))?;

        Ok(row)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Proposals
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn create_proposal(
        &self,
        op_type: MultiSigOpType,
        description: &str,
        unsigned_xdr: &str,
        required_signatures: i16,
        total_signers: i16,
        time_lock_until: Option<DateTime<Utc>>,
        proposed_by: Uuid,
        proposed_by_key: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<MultiSigProposal, MultiSigError> {
        let row = sqlx::query_as!(
            MultiSigProposal,
            r#"
            INSERT INTO multisig_proposals (
                op_type, description, unsigned_xdr,
                required_signatures, total_signers,
                time_lock_until, proposed_by, proposed_by_key, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING
                id,
                op_type AS "op_type: MultiSigOpType",
                description,
                unsigned_xdr,
                signed_xdr,
                stellar_tx_hash,
                required_signatures,
                total_signers,
                time_lock_until,
                status AS "status: MultiSigProposalStatus",
                failure_reason,
                proposed_by,
                proposed_by_key,
                expires_at,
                created_at,
                updated_at,
                submitted_at,
                confirmed_at
            "#,
            op_type as MultiSigOpType,
            description,
            unsigned_xdr,
            required_signatures,
            total_signers,
            time_lock_until,
            proposed_by,
            proposed_by_key,
            expires_at,
        )
        .fetch_one(&self.db)
        .await?;

        Ok(row)
    }

    pub async fn get_proposal(&self, id: Uuid) -> Result<MultiSigProposal, MultiSigError> {
        sqlx::query_as!(
            MultiSigProposal,
            r#"
            SELECT
                id,
                op_type AS "op_type: MultiSigOpType",
                description,
                unsigned_xdr,
                signed_xdr,
                stellar_tx_hash,
                required_signatures,
                total_signers,
                time_lock_until,
                status AS "status: MultiSigProposalStatus",
                failure_reason,
                proposed_by,
                proposed_by_key,
                expires_at,
                created_at,
                updated_at,
                submitted_at,
                confirmed_at
            FROM multisig_proposals
            WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(&self.db)
        .await?
        .ok_or(MultiSigError::ProposalNotFound(id))
    }

    pub async fn list_proposals(
        &self,
        status: Option<MultiSigProposalStatus>,
        op_type: Option<MultiSigOpType>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<MultiSigProposal>, i64), MultiSigError> {
        // Build dynamic query — sqlx doesn't support fully dynamic WHERE clauses
        // with compile-time checking, so we use query_as with runtime binding.
        let rows = sqlx::query_as!(
            MultiSigProposal,
            r#"
            SELECT
                id,
                op_type AS "op_type: MultiSigOpType",
                description,
                unsigned_xdr,
                signed_xdr,
                stellar_tx_hash,
                required_signatures,
                total_signers,
                time_lock_until,
                status AS "status: MultiSigProposalStatus",
                failure_reason,
                proposed_by,
                proposed_by_key,
                expires_at,
                created_at,
                updated_at,
                submitted_at,
                confirmed_at
            FROM multisig_proposals
            WHERE ($1::multisig_proposal_status IS NULL OR status = $1)
              AND ($2::multisig_op_type IS NULL OR op_type = $2)
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
            status as Option<MultiSigProposalStatus>,
            op_type as Option<MultiSigOpType>,
            limit,
            offset,
        )
        .fetch_all(&self.db)
        .await?;

        let total: i64 = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) FROM multisig_proposals
            WHERE ($1::multisig_proposal_status IS NULL OR status = $1)
              AND ($2::multisig_op_type IS NULL OR op_type = $2)
            "#,
            status as Option<MultiSigProposalStatus>,
            op_type as Option<MultiSigOpType>,
        )
        .fetch_one(&self.db)
        .await?
        .unwrap_or(0);

        Ok((rows, total))
    }

    pub async fn update_proposal_status(
        &self,
        id: Uuid,
        status: MultiSigProposalStatus,
        signed_xdr: Option<&str>,
        stellar_tx_hash: Option<&str>,
        failure_reason: Option<&str>,
    ) -> Result<MultiSigProposal, MultiSigError> {
        let now = Utc::now();
        let submitted_at = if status == MultiSigProposalStatus::Submitted {
            Some(now)
        } else {
            None
        };
        let confirmed_at = if status == MultiSigProposalStatus::Confirmed {
            Some(now)
        } else {
            None
        };

        sqlx::query_as!(
            MultiSigProposal,
            r#"
            UPDATE multisig_proposals
            SET
                status           = $2,
                signed_xdr       = COALESCE($3, signed_xdr),
                stellar_tx_hash  = COALESCE($4, stellar_tx_hash),
                failure_reason   = COALESCE($5, failure_reason),
                submitted_at     = COALESCE($6, submitted_at),
                confirmed_at     = COALESCE($7, confirmed_at),
                updated_at       = NOW()
            WHERE id = $1
            RETURNING
                id,
                op_type AS "op_type: MultiSigOpType",
                description,
                unsigned_xdr,
                signed_xdr,
                stellar_tx_hash,
                required_signatures,
                total_signers,
                time_lock_until,
                status AS "status: MultiSigProposalStatus",
                failure_reason,
                proposed_by,
                proposed_by_key,
                expires_at,
                created_at,
                updated_at,
                submitted_at,
                confirmed_at
            "#,
            id,
            status as MultiSigProposalStatus,
            signed_xdr,
            stellar_tx_hash,
            failure_reason,
            submitted_at,
            confirmed_at,
        )
        .fetch_optional(&self.db)
        .await?
        .ok_or(MultiSigError::ProposalNotFound(id))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Signatures
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn add_signature(
        &self,
        proposal_id: Uuid,
        signer_id: Uuid,
        signer_key: &str,
        signer_role: &str,
        signature_xdr: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<MultiSigSignature, MultiSigError> {
        let row = sqlx::query_as!(
            MultiSigSignature,
            r#"
            INSERT INTO multisig_signatures (
                proposal_id, signer_id, signer_key, signer_role,
                signature_xdr, ip_address, user_agent
            )
            VALUES ($1, $2, $3, $4, $5, $6::inet, $7)
            RETURNING
                id,
                proposal_id,
                signer_id,
                signer_key,
                signer_role,
                signature_xdr,
                signed_at,
                ip_address::TEXT AS ip_address,
                user_agent
            "#,
            proposal_id,
            signer_id,
            signer_key,
            signer_role,
            signature_xdr,
            ip_address,
            user_agent,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            // Unique constraint violation → duplicate signature
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("multisig_signatures_proposal_id_signer_id_key") {
                    return MultiSigError::DuplicateSignature(
                        signer_key.to_string(),
                        proposal_id,
                    );
                }
            }
            MultiSigError::Database(e)
        })?;

        Ok(row)
    }

    pub async fn list_signatures(
        &self,
        proposal_id: Uuid,
    ) -> Result<Vec<MultiSigSignature>, MultiSigError> {
        let rows = sqlx::query_as!(
            MultiSigSignature,
            r#"
            SELECT
                id,
                proposal_id,
                signer_id,
                signer_key,
                signer_role,
                signature_xdr,
                signed_at,
                ip_address::TEXT AS ip_address,
                user_agent
            FROM multisig_signatures
            WHERE proposal_id = $1
            ORDER BY signed_at ASC
            "#,
            proposal_id,
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows)
    }

    pub async fn signature_exists(
        &self,
        proposal_id: Uuid,
        signer_id: Uuid,
    ) -> Result<bool, MultiSigError> {
        let count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM multisig_signatures WHERE proposal_id = $1 AND signer_id = $2",
            proposal_id,
            signer_id,
        )
        .fetch_one(&self.db)
        .await?
        .unwrap_or(0);

        Ok(count > 0)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Governance log
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn append_governance_log(
        &self,
        proposal_id: Option<Uuid>,
        event_type: &str,
        actor_key: Option<&str>,
        actor_id: Option<Uuid>,
        payload: &serde_json::Value,
        previous_hash: Option<&str>,
        current_hash: &str,
    ) -> Result<GovernanceLogEntry, MultiSigError> {
        let row = sqlx::query_as!(
            GovernanceLogEntry,
            r#"
            INSERT INTO multisig_governance_log (
                proposal_id, event_type, actor_key, actor_id,
                payload, previous_hash, current_hash
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING
                id,
                proposal_id,
                event_type,
                actor_key,
                actor_id,
                payload,
                previous_hash,
                current_hash,
                created_at
            "#,
            proposal_id,
            event_type,
            actor_key,
            actor_id,
            payload,
            previous_hash,
            current_hash,
        )
        .fetch_one(&self.db)
        .await?;

        Ok(row)
    }

    pub async fn get_last_log_hash(
        &self,
        proposal_id: Option<Uuid>,
    ) -> Result<Option<String>, MultiSigError> {
        let hash = sqlx::query_scalar!(
            r#"
            SELECT current_hash
            FROM multisig_governance_log
            WHERE ($1::uuid IS NULL OR proposal_id = $1)
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            proposal_id,
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(hash)
    }

    pub async fn list_governance_log(
        &self,
        proposal_id: Uuid,
    ) -> Result<Vec<GovernanceLogEntry>, MultiSigError> {
        let rows = sqlx::query_as!(
            GovernanceLogEntry,
            r#"
            SELECT
                id,
                proposal_id,
                event_type,
                actor_key,
                actor_id,
                payload,
                previous_hash,
                current_hash,
                created_at
            FROM multisig_governance_log
            WHERE proposal_id = $1
            ORDER BY created_at ASC
            "#,
            proposal_id,
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Signer lookup (delegates to mint_signers table)
    // ─────────────────────────────────────────────────────────────────────────

    /// Returns (signer_id, role) for an active signer identified by their
    /// Stellar public key.
    pub async fn find_active_signer_by_key(
        &self,
        stellar_public_key: &str,
    ) -> Result<Option<(Uuid, String)>, MultiSigError> {
        let row = sqlx::query!(
            r#"
            SELECT id, role::TEXT AS role
            FROM mint_signers
            WHERE stellar_public_key = $1
              AND status = 'active'
            "#,
            stellar_public_key,
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(row.map(|r| (r.id, r.role)))
    }
}
