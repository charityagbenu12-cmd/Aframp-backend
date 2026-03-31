use crate::chains::stellar::burn_transaction_builder::{
    BatchBurnOperation, BurnOperation, BurnTransactionDraft, CngnBurnTransactionBuilder,
    SignedBurnTransaction,
};
use crate::chains::stellar::client::StellarClient;
use crate::chains::stellar::errors::StellarError;
use crate::chains::stellar::trustline::CngnAssetConfig;
use crate::database::models::redemption::{BurnTransaction, RedemptionRequest};
use crate::database::repositories::redemption_repository::RedemptionRepository;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, instrument, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnServiceConfig {
    pub enable_clawback: bool,
    pub default_timeout_seconds: u64,
    pub max_batch_size: usize,
    pub max_retries: u32,
    pub retry_delay_seconds: u64,
}

impl Default for BurnServiceConfig {
    fn default() -> Self {
        Self {
            enable_clawback: false, // Default to payment-based burns
            default_timeout_seconds: 300, // 5 minutes
            max_batch_size: 100,
            max_retries: 3,
            retry_delay_seconds: 10,
        }
    }
}

#[async_trait]
pub trait BurnService: Send + Sync {
    async fn build_and_submit_burn_transaction(
        &self,
        redemption_request: &RedemptionRequest,
    ) -> Result<String, StellarError>;

    async fn build_and_submit_batch_burn_transaction(
        &self,
        batch_operation: BatchBurnOperation,
    ) -> Result<String, StellarError>;

    async fn confirm_burn_transaction(
        &self,
        transaction_hash: &str,
        redemption_id: &str,
    ) -> Result<bool, StellarError>;

    async fn retry_failed_burn(&self, redemption_id: &str) -> Result<bool, StellarError>;
}

pub struct StellarBurnService {
    client: StellarClient,
    builder: CngnBurnTransactionBuilder,
    repository: Arc<dyn RedemptionRepository>,
    config: BurnServiceConfig,
}

impl StellarBurnService {
    pub fn new(
        client: StellarClient,
        repository: Arc<dyn RedemptionRepository>,
        config: BurnServiceConfig,
    ) -> Self {
        let builder = CngnBurnTransactionBuilder::new(client.clone())
            .with_timeout(std::time::Duration::from_secs(config.default_timeout_seconds));

        Self {
            client,
            builder,
            repository,
            config,
        }
    }

    fn determine_burn_type(&self, _redemption_request: &RedemptionRequest) -> crate::chains::stellar::burn_transaction_builder::BurnType {
        if self.config.enable_clawback {
            crate::chains::stellar::burn_transaction_builder::BurnType::Clawback
        } else {
            crate::chains::stellar::burn_transaction_builder::BurnType::PaymentToIssuer
        }
    }

    async fn update_burn_transaction_status(
        &self,
        redemption_id: &str,
        transaction_hash: &str,
        status: &str,
        error_message: Option<&str>,
    ) -> Result<(), StellarError> {
        // Update database with burn transaction status
        // This would interact with the repository
        info!(
            redemption_id = %redemption_id,
            transaction_hash = %transaction_hash,
            status = %status,
            "Updated burn transaction status"
        );
        Ok(())
    }
}

#[async_trait]
impl BurnService for StellarBurnService {
    #[instrument(skip(self), fields(redemption_id = %redemption_request.redemption_id))]
    async fn build_and_submit_burn_transaction(
        &self,
        redemption_request: &RedemptionRequest,
    ) -> Result<String, StellarError> {
        // Check if burn already exists (idempotency)
        if let Ok(existing) = self.repository.get_burn_transaction(&redemption_request.redemption_id).await {
            if existing.transaction_hash.is_some() {
                info!(
                    redemption_id = %redemption_request.redemption_id,
                    transaction_hash = %existing.transaction_hash.as_ref().unwrap(),
                    "Burn transaction already exists"
                );
                return Ok(existing.transaction_hash.unwrap());
            }
        }

        // Create burn operation
        let burn_operation = BurnOperation {
            source_address: redemption_request.wallet_address.clone(),
            amount_cngn: redemption_request.amount_cngn.to_string(),
            redemption_id: redemption_request.redemption_id.clone(),
            burn_type: self.determine_burn_type(redemption_request),
        };

        // Build transaction
        let draft = self
            .builder
            .build_burn_transaction(burn_operation, None)
            .await?;

        // Store burn transaction draft
        let burn_transaction = BurnTransaction {
            id: uuid::Uuid::new_v4(),
            redemption_id: redemption_request.redemption_id.clone(),
            transaction_hash: draft.transaction_hash.clone(),
            stellar_ledger: None,
            sequence_number: Some(draft.sequence),
            burn_type: format!("{:?}", draft.burn_type),
            source_address: draft.source_address.clone(),
            destination_address: draft.destination_address.clone(),
            amount_cngn: redemption_request.amount_cngn,
            status: "PENDING".to_string(),
            fee_paid_stroops: Some(draft.fee_stroops as i32),
            fee_xlm: Some(draft.fee_stroops as f64 / 10_000_000.0),
            timeout_seconds: draft.timeout_seconds as i32,
            error_code: None,
            error_message: None,
            retry_count: 0,
            max_retries: self.config.max_retries as i32,
            unsigned_envelope_xdr: Some(draft.unsigned_envelope_xdr.clone()),
            signed_envelope_xdr: None,
            memo_text: Some(draft.redemption_id.clone()),
            memo_hash: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            submitted_at: None,
            confirmed_at: None,
        };

        self.repository.create_burn_transaction(&burn_transaction).await
            .map_err(|e| StellarError::transaction_failed(format!("Failed to save burn transaction: {}", e)))?;

        // Sign transaction (in production, this would use secure key management)
        let secret_seed = std::env::var("STELLAR_ISSUER_SECRET_SEED")
            .map_err(|_| StellarError::signing_error("STELLAR_ISSUER_SECRET_SEED not configured"))?;

        let signed_transaction = self.builder.sign_burn_transaction(draft, &secret_seed)?;

        // Update with signed envelope
        self.repository.update_burn_transaction_signed_envelope(
            &redemption_request.redemption_id,
            &signed_transaction.signed_envelope_xdr,
        ).await.map_err(|e| StellarError::transaction_failed(format!("Failed to update signed envelope: {}", e)))?;

        // Submit to Stellar
        match self.builder.submit_burn_transaction(&signed_transaction.signed_envelope_xdr).await {
            Ok(result) => {
                let successful = result.get("successful")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if successful {
                    let tx_hash = result.get("hash")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&signed_transaction.draft.transaction_hash);

                    info!(
                        redemption_id = %redemption_request.redemption_id,
                        transaction_hash = %tx_hash,
                        "Burn transaction submitted successfully"
                    );

                    // Update status to BURNING_IN_PROGRESS
                    self.update_burn_transaction_status(
                        &redemption_request.redemption_id,
                        tx_hash,
                        "BURNING_IN_PROGRESS",
                        None,
                    ).await?;

                    // Update redemption request status
                    self.repository.update_redemption_status(
                        &redemption_request.redemption_id,
                        "BURNING_IN_PROGRESS",
                    ).await.map_err(|e| StellarError::transaction_failed(format!("Failed to update redemption status: {}", e)))?;

                    Ok(tx_hash.to_string())
                } else {
                    let error_message = result.get("error_message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error");

                    error!(
                        redemption_id = %redemption_request.redemption_id,
                        error = %error_message,
                        "Burn transaction submission failed"
                    );

                    // Update status to FAILED
                    self.update_burn_transaction_status(
                        &redemption_request.redemption_id,
                        &signed_transaction.draft.transaction_hash,
                        "FAILED",
                        Some(error_message),
                    ).await?;

                    Err(StellarError::transaction_failed(format!("Burn transaction failed: {}", error_message)))
                }
            }
            Err(e) => {
                error!(
                    redemption_id = %redemption_request.redemption_id,
                    error = %e,
                    "Failed to submit burn transaction"
                );

                // Update status to FAILED
                self.update_burn_transaction_status(
                    &redemption_request.redemption_id,
                    &signed_transaction.draft.transaction_hash,
                    "FAILED",
                    Some(&e.to_string()),
                ).await?;

                Err(e)
            }
        }
    }

    #[instrument(skip(self), fields(batch_id = %batch_operation.batch_id, operations_count = %batch_operation.operations.len()))]
    async fn build_and_submit_batch_burn_transaction(
        &self,
        batch_operation: BatchBurnOperation,
    ) -> Result<String, StellarError> {
        // Build batch transaction
        let draft = self
            .builder
            .build_batch_burn_transaction(batch_operation.clone(), None)
            .await?;

        // Sign transaction
        let secret_seed = std::env::var("STELLAR_ISSUER_SECRET_SEED")
            .map_err(|_| StellarError::signing_error("STELLAR_ISSUER_SECRET_SEED not configured"))?;

        let signed_transaction = self.builder.sign_burn_transaction(
            crate::chains::stellar::burn_transaction_builder::BurnTransactionDraft {
                redemption_id: batch_operation.batch_id.clone(),
                source_address: draft.operations[0].source_address.clone(),
                destination_address: "".to_string(), // Will be set by builder
                amount_cngn: "0".to_string(), // Not used for batch
                burn_type: crate::chains::stellar::burn_transaction_builder::BurnType::PaymentToIssuer,
                sequence: draft.sequence,
                fee_stroops: draft.fee_stroops,
                timeout_seconds: draft.timeout_seconds,
                created_at: draft.created_at.clone(),
                transaction_hash: draft.transaction_hash.clone(),
                unsigned_envelope_xdr: draft.unsigned_envelope_xdr.clone(),
                memo: draft.memo.clone(),
            },
            &secret_seed,
        )?;

        // Submit batch transaction
        match self.builder.submit_burn_transaction(&signed_transaction.signed_envelope_xdr).await {
            Ok(result) => {
                let successful = result.get("successful")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if successful {
                    let tx_hash = result.get("hash")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&draft.transaction_hash);

                    info!(
                        batch_id = %batch_operation.batch_id,
                        transaction_hash = %tx_hash,
                        operations_count = %batch_operation.operations.len(),
                        "Batch burn transaction submitted successfully"
                    );

                    // Update all individual redemption requests
                    for operation in &batch_operation.operations {
                        self.repository.update_redemption_status(
                            &operation.redemption_id,
                            "BURNING_IN_PROGRESS",
                        ).await.map_err(|e| {
                            warn!(
                                redemption_id = %operation.redemption_id,
                                error = %e,
                                "Failed to update redemption status for batch item"
                            );
                            e
                        })?;

                        // Create individual burn transaction records
                        let burn_transaction = BurnTransaction {
                            id: uuid::Uuid::new_v4(),
                            redemption_id: operation.redemption_id.clone(),
                            transaction_hash: Some(tx_hash.to_string()),
                            stellar_ledger: None,
                            sequence_number: Some(draft.sequence),
                            burn_type: format!("{:?}", operation.burn_type),
                            source_address: operation.source_address.clone(),
                            destination_address: "".to_string(), // Will be filled by batch processing
                            amount_cngn: operation.amount_cngn.parse().unwrap_or(0.0),
                            status: "BURNING_IN_PROGRESS".to_string(),
                            fee_paid_stroops: Some(draft.fee_stroops as i32),
                            fee_xlm: Some(draft.fee_stroops as f64 / 10_000_000.0),
                            timeout_seconds: draft.timeout_seconds as i32,
                            error_code: None,
                            error_message: None,
                            retry_count: 0,
                            max_retries: self.config.max_retries as i32,
                            unsigned_envelope_xdr: None,
                            signed_envelope_xdr: Some(signed_transaction.signed_envelope_xdr.clone()),
                            memo_text: Some(operation.redemption_id.clone()),
                            memo_hash: None,
                            metadata: serde_json::json!({"batch_id": batch_operation.batch_id}),
                            created_at: chrono::Utc::now(),
                            updated_at: chrono::Utc::now(),
                            submitted_at: Some(chrono::Utc::now()),
                            confirmed_at: None,
                        };

                        if let Err(e) = self.repository.create_burn_transaction(&burn_transaction).await {
                            error!(
                                redemption_id = %operation.redemption_id,
                                error = %e,
                                "Failed to create burn transaction record for batch item"
                            );
                        }
                    }

                    Ok(tx_hash.to_string())
                } else {
                    let error_message = result.get("error_message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown batch error");

                    error!(
                        batch_id = %batch_operation.batch_id,
                        error = %error_message,
                        "Batch burn transaction submission failed"
                    );

                    Err(StellarError::transaction_failed(format!("Batch burn failed: {}", error_message)))
                }
            }
            Err(e) => {
                error!(
                    batch_id = %batch_operation.batch_id,
                    error = %e,
                    "Failed to submit batch burn transaction"
                );
                Err(e)
            }
        }
    }

    #[instrument(skip(self), fields(transaction_hash = %transaction_hash, redemption_id = %redemption_id))]
    async fn confirm_burn_transaction(
        &self,
        transaction_hash: &str,
        redemption_id: &str,
    ) -> Result<bool, StellarError> {
        // Get transaction from Stellar
        match self.client.get_transaction_by_hash(transaction_hash).await {
            Ok(transaction) => {
                if transaction.successful {
                    info!(
                        transaction_hash = %transaction_hash,
                        redemption_id = %redemption_id,
                        ledger = ?transaction.ledger,
                        "Burn transaction confirmed on-chain"
                    );

                    // Update burn transaction status
                    self.update_burn_transaction_status(
                        redemption_id,
                        transaction_hash,
                        "SUCCESS",
                        None,
                    ).await?;

                    // Update redemption request status
                    self.repository.update_redemption_status(
                        redemption_id,
                        "BURNED_CONFIRMED",
                    ).await.map_err(|e| StellarError::transaction_failed(format!("Failed to update redemption status: {}", e)))?;

                    Ok(true)
                } else {
                    warn!(
                        transaction_hash = %transaction_hash,
                        redemption_id = %redemption_id,
                        "Burn transaction was not successful"
                    );

                    self.update_burn_transaction_status(
                        redemption_id,
                        transaction_hash,
                        "FAILED",
                        Some("Transaction not successful"),
                    ).await?;

                    Ok(false)
                }
            }
            Err(e) => {
                warn!(
                    transaction_hash = %transaction_hash,
                    redemption_id = %redemption_id,
                    error = %e,
                    "Failed to get burn transaction status"
                );
                Err(e)
            }
        }
    }

    #[instrument(skip(self), fields(redemption_id = %redemption_id))]
    async fn retry_failed_burn(&self, redemption_id: &str) -> Result<bool, StellarError> {
        // Get the burn transaction record
        let burn_transaction = self.repository.get_burn_transaction(redemption_id).await
            .map_err(|e| StellarError::transaction_failed(format!("Failed to get burn transaction: {}", e)))?;

        if burn_transaction.retry_count >= burn_transaction.max_retries {
            error!(
                redemption_id = %redemption_id,
                retry_count = %burn_transaction.retry_count,
                max_retries = %burn_transaction.max_retries,
                "Max retries exceeded for burn transaction"
            );
            return Ok(false);
        }

        // Get the redemption request
        let redemption_request = self.repository.get_redemption_request(redemption_id).await
            .map_err(|e| StellarError::transaction_failed(format!("Failed to get redemption request: {}", e)))?;

        // Increment retry count
        self.repository.increment_burn_transaction_retry_count(redemption_id).await
            .map_err(|e| StellarError::transaction_failed(format!("Failed to increment retry count: {}", e)))?;

        // Retry the burn
        match self.build_and_submit_burn_transaction(&redemption_request).await {
            Ok(tx_hash) => {
                info!(
                    redemption_id = %redemption_id,
                    transaction_hash = %tx_hash,
                    retry_count = %burn_transaction.retry_count + 1,
                    "Burn transaction retry successful"
                );
                Ok(true)
            }
            Err(e) => {
                error!(
                    redemption_id = %redemption_id,
                    retry_count = %burn_transaction.retry_count + 1,
                    error = %e,
                    "Burn transaction retry failed"
                );
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burn_service_config_default() {
        let config = BurnServiceConfig::default();
        assert!(!config.enable_clawback);
        assert_eq!(config.default_timeout_seconds, 300);
        assert_eq!(config.max_batch_size, 100);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_seconds, 10);
    }
}
