use crate::chains::stellar::burn_transaction_builder::{BatchBurnOperation, BurnOperation};
use crate::database::models::redemption::{RedemptionBatch, RedemptionRequest};
use crate::database::repositories::redemption_repository::RedemptionRepository;
use crate::services::burn_service::BurnService;
use crate::services::disbursement_service::DisbursementService;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, instrument, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProcessorConfig {
    pub enabled: bool,
    pub batch_size_threshold: usize,
    pub time_window_minutes: u64,
    pub max_batch_size: usize,
    pub processing_interval_seconds: u64,
    pub enable_time_based_batches: bool,
    pub enable_count_based_batches: bool,
    pub enable_manual_batches: bool,
}

impl Default for BatchProcessorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            batch_size_threshold: 10,
            time_window_minutes: 5,
            max_batch_size: 100,
            processing_interval_seconds: 60,
            enable_time_based_batches: true,
            enable_count_based_batches: true,
            enable_manual_batches: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BatchTrigger {
    TimeBased { window_minutes: u64 },
    CountBased { threshold: usize },
    Manual { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProcessingResult {
    pub batch_id: String,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub transaction_hash: Option<String>,
    pub processing_time_seconds: u64,
    pub errors: Vec<String>,
}

#[async_trait]
pub trait BatchProcessor: Send + Sync {
    async fn create_time_based_batch(&self) -> Result<Option<String>, BatchProcessorError>;
    async fn create_count_based_batch(&self) -> Result<Option<String>, BatchProcessorError>;
    async fn create_manual_batch(&self, redemption_ids: Vec<String>, reason: String) -> Result<String, BatchProcessorError>;
    async fn process_batch(&self, batch_id: &str) -> Result<BatchProcessingResult, BatchProcessorError>;
    async fn process_pending_batches(&self) -> Result<Vec<BatchProcessingResult>, BatchProcessorError>;
    async fn start_background_processor(&self) -> Result<(), BatchProcessorError>;
    async fn stop_background_processor(&self) -> Result<(), BatchProcessorError>;
}

pub struct RedemptionBatchProcessor {
    repository: Arc<dyn RedemptionRepository>,
    burn_service: Arc<dyn BurnService>,
    disbursement_service: Arc<dyn DisbursementService>,
    config: BatchProcessorConfig,
    is_running: Arc<tokio::sync::RwLock<bool>>,
}

impl RedemptionBatchProcessor {
    pub fn new(
        repository: Arc<dyn RedemptionRepository>,
        burn_service: Arc<dyn BurnService>,
        disbursement_service: Arc<dyn DisbursementService>,
        config: BatchProcessorConfig,
    ) -> Self {
        Self {
            repository,
            burn_service,
            disbursement_service,
            config,
            is_running: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }

    async fn get_pending_redemption_requests(&self, limit: Option<i64>) -> Result<Vec<RedemptionRequest>, BatchProcessorError> {
        self.repository
            .get_pending_redemption_requests(limit)
            .await
            .map_err(|e| BatchProcessorError::RepositoryError(e.to_string()))
    }

    async fn create_batch_record(
        &self,
        redemption_requests: &[RedemptionRequest],
        batch_type: &str,
        trigger_reason: Option<String>,
    ) -> Result<RedemptionBatch, BatchProcessorError> {
        let batch_id = format!("BATCH_{}", uuid::Uuid::new_v4());
        let total_amount_cngn: f64 = redemption_requests.iter().map(|r| r.amount_cngn).sum();
        let total_amount_ngn: f64 = redemption_requests.iter().map(|r| r.amount_ngn).sum();

        let batch = RedemptionBatch {
            id: uuid::Uuid::new_v4(),
            batch_id: batch_id.clone(),
            total_requests: redemption_requests.len() as i32,
            total_amount_cngn,
            total_amount_ngn,
            batch_type: batch_type.to_string(),
            trigger_reason,
            status: "PENDING".to_string(),
            stellar_transaction_hash: None,
            stellar_ledger: None,
            metadata: serde_json::json!({
                "created_by": "batch_processor",
                "request_ids": redemption_requests.iter().map(|r| &r.redemption_id).collect::<Vec<_>>(),
            }),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            processed_at: None,
            completed_at: None,
        };

        // Save batch to database
        self.repository
            .create_redemption_batch(&batch)
            .await
            .map_err(|e| BatchProcessorError::RepositoryError(e.to_string()))?;

        // Update redemption requests with batch_id
        for request in redemption_requests {
            // This would need to be implemented in the repository
            // self.repository.add_request_to_batch(&batch.id, &request.redemption_id).await?;
        }

        Ok(batch)
    }

    async fn build_batch_burn_operation(
        &self,
        redemption_requests: &[RedemptionRequest],
    ) -> Result<BatchBurnOperation, BatchProcessorError> {
        let operations: Result<Vec<BurnOperation>, BatchProcessorError> = redemption_requests
            .iter()
            .map(|req| {
                // Validate that the request is ready for burning
                if req.status != "TOKENS_LOCKED" && req.status != "BURNING_IN_PROGRESS" {
                    return Err(BatchProcessorError::ValidationError(format!(
                        "Redemption {} is not ready for burning: status = {}",
                        req.redemption_id, req.status
                    )));
                }

                Ok(BurnOperation {
                    source_address: req.wallet_address.clone(),
                    amount_cngn: req.amount_cngn.to_string(),
                    redemption_id: req.redemption_id.clone(),
                    burn_type: crate::chains::stellar::burn_transaction_builder::BurnType::PaymentToIssuer,
                })
            })
            .collect();

        let operations = operations?;

        Ok(BatchBurnOperation {
            operations,
            batch_id: format!("BATCH_{}", uuid::Uuid::new_v4()),
            timeout_seconds: 300, // 5 minutes
        })
    }

    async fn update_redemption_requests_status(
        &self,
        redemption_requests: &[RedemptionRequest],
        status: &str,
    ) -> Result<(), BatchProcessorError> {
        for request in redemption_requests {
            self.repository
                .update_redemption_status(&request.redemption_id, status)
                .await
                .map_err(|e| BatchProcessorError::RepositoryError(e.to_string()))?;
        }
        Ok(())
    }

    async fn process_individual_disbursements(
        &self,
        redemption_requests: &[RedemptionRequest],
    ) -> Result<(usize, usize, Vec<String>), BatchProcessorError> {
        let mut successful = 0;
        let mut failed = 0;
        let mut errors = Vec::new();

        for request in redemption_requests {
            match self.disbursement_service.initiate_disbursement(request).await {
                Ok(_) => {
                    successful += 1;
                    info!(
                        redemption_id = %request.redemption_id,
                        "Individual disbursement initiated"
                    );
                }
                Err(e) => {
                    failed += 1;
                    let error_msg = format!("Failed to initiate disbursement for {}: {}", request.redemption_id, e);
                    error!("{}", error_msg);
                    errors.push(error_msg);
                }
            }
        }

        Ok((successful, failed, errors))
    }
}

#[async_trait]
impl BatchProcessor for RedemptionBatchProcessor {
    #[instrument(skip(self))]
    async fn create_time_based_batch(&self) -> Result<Option<String>, BatchProcessorError> {
        if !self.config.enable_time_based_batches {
            return Ok(None);
        }

        let cutoff_time = chrono::Utc::now() - chrono::Duration::minutes(self.config.time_window_minutes as i64);
        
        // Get requests within the time window
        let pending_requests = self.get_pending_redemption_requests(None).await?;
        let eligible_requests: Vec<_> = pending_requests
            .into_iter()
            .filter(|r| r.created_at <= cutoff_time)
            .take(self.config.max_batch_size)
            .collect();

        if eligible_requests.len() >= self.config.batch_size_threshold {
            let batch = self
                .create_batch_record(
                    &eligible_requests,
                    "TIME_BASED",
                    Some(format!("{} requests within {} minute window", eligible_requests.len(), self.config.time_window_minutes)),
                )
                .await?;

            info!(
                batch_id = %batch.batch_id,
                request_count = %eligible_requests.len(),
                "Created time-based batch"
            );

            Ok(Some(batch.batch_id))
        } else {
            Ok(None)
        }
    }

    #[instrument(skip(self))]
    async fn create_count_based_batch(&self) -> Result<Option<String>, BatchProcessorError> {
        if !self.config.enable_count_based_batches {
            return Ok(None);
        }

        let pending_requests = self
            .get_pending_redemption_requests(Some(self.config.batch_size_threshold as i64))
            .await?;

        if pending_requests.len() >= self.config.batch_size_threshold {
            let batch = self
                .create_batch_record(
                    &pending_requests,
                    "COUNT_BASED",
                    Some(format!("Threshold of {} requests reached", self.config.batch_size_threshold)),
                )
                .await?;

            info!(
                batch_id = %batch.batch_id,
                request_count = %pending_requests.len(),
                "Created count-based batch"
            );

            Ok(Some(batch.batch_id))
        } else {
            Ok(None)
        }
    }

    #[instrument(skip(self), fields(redemption_ids_count = %redemption_ids.len(), reason = %reason))]
    async fn create_manual_batch(&self, redemption_ids: Vec<String>, reason: String) -> Result<String, BatchProcessorError> {
        if !self.config.enable_manual_batches {
            return Err(BatchProcessorError::ConfigurationError("Manual batches are disabled".to_string()));
        }

        if redemption_ids.is_empty() {
            return Err(BatchProcessorError::ValidationError("No redemption IDs provided".to_string()));
        }

        if redemption_ids.len() > self.config.max_batch_size {
            return Err(BatchProcessorError::ValidationError(format!(
                "Batch size {} exceeds maximum {}",
                redemption_ids.len(),
                self.config.max_batch_size
            )));
        }

        // Get the redemption requests
        let mut redemption_requests = Vec::new();
        for redemption_id in &redemption_ids {
            let request = self
                .repository
                .get_redemption_request(redemption_id)
                .await
                .map_err(|e| BatchProcessorError::RepositoryError(e.to_string()))?;
            redemption_requests.push(request);
        }

        let batch = self
            .create_batch_record(&redemption_requests, "MANUAL", Some(reason))
            .await?;

        info!(
            batch_id = %batch.batch_id,
            request_count = %redemption_requests.len(),
            "Created manual batch"
        );

        Ok(batch.batch_id)
    }

    #[instrument(skip(self), fields(batch_id = %batch_id))]
    async fn process_batch(&self, batch_id: &str) -> Result<BatchProcessingResult, BatchProcessorError> {
        let start_time = std::time::Instant::now();
        
        // Get batch details
        let batch = self
            .repository
            .get_redemption_batch(batch_id)
            .await
            .map_err(|e| BatchProcessorError::RepositoryError(e.to_string()))?;

        if batch.status != "PENDING" {
            return Err(BatchProcessorError::ValidationError(format!(
                "Batch {} is not in PENDING status: {}",
                batch_id, batch.status
            )));
        }

        // Update batch status to PROCESSING
        self.repository
            .update_batch_status(batch_id, "PROCESSING")
            .await
            .map_err(|e| BatchProcessorError::RepositoryError(e.to_string()))?;

        // Get redemption requests in this batch
        // This would need to be implemented in the repository
        // let redemption_requests = self.repository.get_requests_in_batch(&batch.id).await?;
        let redemption_requests = self.get_pending_redemption_requests(None).await?; // Simplified

        let mut result = BatchProcessingResult {
            batch_id: batch_id.to_string(),
            total_requests: redemption_requests.len(),
            successful_requests: 0,
            failed_requests: 0,
            transaction_hash: None,
            processing_time_seconds: 0,
            errors: Vec::new(),
        };

        // Step 1: Process burn transactions
        if redemption_requests.len() > 1 {
            // Use batch burn for multiple requests
            let burn_operation = self.build_batch_burn_operation(&redemption_requests).await?;
            
            match self.burn_service.build_and_submit_batch_burn_transaction(burn_operation).await {
                Ok(tx_hash) => {
                    result.transaction_hash = Some(tx_hash.clone());
                    info!(
                        batch_id = %batch_id,
                        transaction_hash = %tx_hash,
                        "Batch burn transaction submitted successfully"
                    );

                    // Update all requests to BURNING_IN_PROGRESS
                    self.update_redemption_requests_status(&redemption_requests, "BURNING_IN_PROGRESS").await?;
                    result.successful_requests = redemption_requests.len();
                }
                Err(e) => {
                    let error_msg = format!("Batch burn failed: {}", e);
                    error!(batch_id = %batch_id, error = %error_msg);
                    result.errors.push(error_msg);
                    result.failed_requests = redemption_requests.len();
                }
            }
        } else if let Some(request) = redemption_requests.first() {
            // Use individual burn for single request
            match self.burn_service.build_and_submit_burn_transaction(request).await {
                Ok(tx_hash) => {
                    result.transaction_hash = Some(tx_hash.clone());
                    info!(
                        batch_id = %batch_id,
                        transaction_hash = %tx_hash,
                        "Individual burn transaction submitted successfully"
                    );
                    result.successful_requests = 1;
                }
                Err(e) => {
                    let error_msg = format!("Individual burn failed: {}", e);
                    error!(batch_id = %batch_id, error = %error_msg);
                    result.errors.push(error_msg);
                    result.failed_requests = 1;
                }
            }
        }

        // Step 2: If burns were successful, initiate disbursements
        if result.successful_requests > 0 {
            let (disbursement_successful, disbursement_failed, disbursement_errors) = 
                self.process_individual_disbursements(&redemption_requests).await?;
            
            result.errors.extend(disbursement_errors);
            // Note: We don't update successful/failed counts here as burns were successful
            // Disbursement failures are handled separately
        }

        // Update batch status
        let final_status = if result.failed_requests == 0 {
            "COMPLETED"
        } else if result.successful_requests > 0 {
            "PARTIAL"
        } else {
            "FAILED"
        };

        self.repository
            .update_batch_status(batch_id, final_status)
            .await
            .map_err(|e| BatchProcessorError::RepositoryError(e.to_string()))?;

        result.processing_time_seconds = start_time.elapsed().as_secs();

        info!(
            batch_id = %batch_id,
            status = %final_status,
            successful = %result.successful_requests,
            failed = %result.failed_requests,
            processing_time_seconds = %result.processing_time_seconds,
            "Batch processing completed"
        );

        Ok(result)
    }

    #[instrument(skip(self))]
    async fn process_pending_batches(&self) -> Result<Vec<BatchProcessingResult>, BatchProcessorError> {
        let pending_batches = self
            .repository
            .get_pending_batches()
            .await
            .map_err(|e| BatchProcessorError::RepositoryError(e.to_string()))?;

        let mut results = Vec::new();

        for batch in pending_batches {
            match self.process_batch(&batch.batch_id).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!(
                        batch_id = %batch.batch_id,
                        error = %e,
                        "Failed to process batch"
                    );
                }
            }
        }

        Ok(results)
    }

    #[instrument(skip(self))]
    async fn start_background_processor(&self) -> Result<(), BatchProcessorError> {
        if !self.config.enabled {
            return Err(BatchProcessorError::ConfigurationError("Batch processor is disabled".to_string()));
        }

        {
            let mut is_running = self.is_running.write().await;
            if *is_running {
                return Err(BatchProcessorError::ConfigurationError("Background processor is already running".to_string()));
            }
            *is_running = true;
        }

        let repository = self.repository.clone();
        let burn_service = self.burn_service.clone();
        let disbursement_service = self.disbursement_service.clone();
        let config = self.config.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.processing_interval_seconds));
            
            loop {
                // Check if we should stop
                {
                    let is_running = is_running.read().await;
                    if !*is_running {
                        info!("Background batch processor stopped");
                        break;
                    }
                }

                interval.tick().await;

                // Create time-based batches
                let processor = RedemptionBatchProcessor {
                    repository: repository.clone(),
                    burn_service: burn_service.clone(),
                    disbursement_service: disbursement_service.clone(),
                    config: config.clone(),
                    is_running: is_running.clone(),
                };

                if let Ok(Some(batch_id)) = processor.create_time_based_batch().await {
                    info!(batch_id = %batch_id, "Auto-created time-based batch");
                }

                // Create count-based batches
                if let Ok(Some(batch_id)) = processor.create_count_based_batch().await {
                    info!(batch_id = %batch_id, "Auto-created count-based batch");
                }

                // Process pending batches
                match processor.process_pending_batches().await {
                    Ok(results) => {
                        if !results.is_empty() {
                            info!(
                                processed_count = %results.len(),
                                "Processed pending batches"
                            );
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to process pending batches");
                    }
                }
            }
        });

        info!("Background batch processor started");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn stop_background_processor(&self) -> Result<(), BatchProcessorError> {
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        info!("Background batch processor stop requested");
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BatchProcessorError {
    #[error("Repository error: {0}")]
    RepositoryError(String),
    
    #[error("Burn service error: {0}")]
    BurnServiceError(String),
    
    #[error("Disbursement service error: {0}")]
    DisbursementServiceError(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Processing error: {0}")]
    ProcessingError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_processor_config_default() {
        let config = BatchProcessorConfig::default();
        assert!(config.enabled);
        assert_eq!(config.batch_size_threshold, 10);
        assert_eq!(config.time_window_minutes, 5);
        assert_eq!(config.max_batch_size, 100);
        assert_eq!(config.processing_interval_seconds, 60);
        assert!(config.enable_time_based_batches);
        assert!(config.enable_count_based_batches);
        assert!(config.enable_manual_batches);
    }
}
