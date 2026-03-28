use crate::vault::types::{
    ApprovalSignature, OutboundTransferRequest, TransferRequestStatus, VaultError, VaultResult,
};
use chrono::Utc;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

/// Enforces M-of-N approval before any outbound transfer is executed.
///
/// `required_signatures` — M (minimum approvals needed)
/// `total_signers`       — N (total authorised signers)
pub struct MultiSigGuard {
    pub required_signatures: usize,
    pub total_signers: usize,
    pub db: PgPool,
}

impl MultiSigGuard {
    pub fn new(required_signatures: usize, total_signers: usize, db: PgPool) -> Self {
        Self {
            required_signatures,
            total_signers,
            db,
        }
    }

    /// Create a new outbound transfer request pending approval.
    pub async fn create_request(&self, request: &OutboundTransferRequest) -> VaultResult<Uuid> {
        let payload = serde_json::to_value(request)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;

        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO vault_transfer_requests
                (id, account_id, amount, currency, destination_account,
                 destination_bank_code, narration, status, payload, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending_approval', $8, NOW())
            RETURNING id
            "#,
            request.id,
            request.amount,
            request.currency,
            request.destination_account,
            request.destination_bank_code,
            request.narration,
            payload,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| VaultError::Database(e.to_string()))?;

        info!(request_id = %id, "outbound transfer request created, awaiting signatures");
        Ok(id)
    }

    /// Record a signer's approval. Returns `true` when the M-of-N threshold is met.
    pub async fn add_signature(
        &self,
        request_id: Uuid,
        signer_id: &str,
        role: &str,
    ) -> VaultResult<bool> {
        let row = sqlx::query!(
            "SELECT status, signatures FROM vault_transfer_requests WHERE id = $1",
            request_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| VaultError::Database(e.to_string()))?
        .ok_or(VaultError::TransferNotFound(request_id))?;

        if row.status != "pending_approval" {
            warn!(request_id = %request_id, status = %row.status, "signature rejected: request not pending");
            return Err(VaultError::OutboundBlocked);
        }

        let mut sigs: Vec<ApprovalSignature> = row
            .signatures
            .map(|v| serde_json::from_value(v).unwrap_or_default())
            .unwrap_or_default();

        if sigs.iter().any(|s| s.signer_id == signer_id) {
            return Err(VaultError::DuplicateSignature(signer_id.to_string()));
        }

        sigs.push(ApprovalSignature {
            signer_id: signer_id.to_string(),
            role: role.to_string(),
            signed_at: Utc::now(),
        });

        let threshold_met = sigs.len() >= self.required_signatures;
        let new_status = if threshold_met {
            "approved"
        } else {
            "pending_approval"
        };

        let sigs_json = serde_json::to_value(&sigs)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;

        sqlx::query!(
            "UPDATE vault_transfer_requests SET signatures = $1, status = $2 WHERE id = $3",
            sigs_json,
            new_status,
            request_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| VaultError::Database(e.to_string()))?;

        if threshold_met {
            info!(
                request_id = %request_id,
                signatures = sigs.len(),
                required = self.required_signatures,
                "M-of-N threshold met — transfer approved"
            );
        }

        Ok(threshold_met)
    }

    /// Assert that a request has reached the approval threshold before execution.
    pub async fn assert_approved(&self, request_id: Uuid) -> VaultResult<()> {
        let row = sqlx::query_scalar!(
            "SELECT status FROM vault_transfer_requests WHERE id = $1",
            request_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| VaultError::Database(e.to_string()))?
        .ok_or(VaultError::TransferNotFound(request_id))?;

        if row != "approved" {
            let provided = sqlx::query_scalar!(
                "SELECT jsonb_array_length(signatures) FROM vault_transfer_requests WHERE id = $1",
                request_id
            )
            .fetch_one(&self.db)
            .await
            .map_err(|e| VaultError::Database(e.to_string()))?
            .unwrap_or(0) as usize;

            return Err(VaultError::InsufficientSignatures {
                required: self.required_signatures,
                total: self.total_signers,
                provided,
            });
        }

        Ok(())
    }
}
