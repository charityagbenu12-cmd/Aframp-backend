use crate::cache::cache::Cache;
use crate::cache::RedisCache;
use crate::chains::stellar::client::StellarClient;
use crate::database::repository::Repository;
use crate::database::transaction_repository::TransactionRepository;
use crate::error::{AppError, AppErrorKind, DomainError, ValidationError};
use crate::payments::factory::PaymentProviderFactory;
use crate::payments::types::{StatusRequest, PaymentState};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// State for the onramp status handler
#[derive(Clone)]
pub struct OnrampStatusService {
    pub transaction_repo: Arc<TransactionRepository>,
    pub cache: Arc<RedisCache>,
    pub stellar_client: Arc<StellarClient>,
    pub payment_factory: Arc<PaymentProviderFactory>,
}

impl OnrampStatusService {
    /// Create a new onramp status service
    pub fn new(
        transaction_repo: Arc<TransactionRepository>,
        cache: Arc<RedisCache>,
        stellar_client: Arc<StellarClient>,
        payment_factory: Arc<PaymentProviderFactory>,
    ) -> Self {
        Self {
            transaction_repo,
            cache,
            stellar_client,
            payment_factory,
        }
    }

    /// Get status for a transaction with ownership verification
    pub async fn get_status(&self, tx_id: &str, requesting_wallet: Option<&str>) -> Result<OnrampStatusResponse, AppError> {
        // Validate transaction ID format
        if let Err(_) = Uuid::parse_str(tx_id) {
            return Err(AppError::new(AppErrorKind::Validation(
                ValidationError::InvalidFormat {
                    field: "tx_id".to_string(),
                    expected: "UUID".to_string(),
                    got: tx_id.to_string(),
                },
            )));
        }

        // Check cache first
        let cache_key = format!("api:onramp:status:{}", tx_id);
        let cached_result: Result<Option<OnrampStatusResponse>, _> = self.cache.get(&cache_key).await;
        
        if let Ok(Some(cached)) = cached_result {
            debug!("Cache hit for onramp status: {}", tx_id);
            
            // Still need to verify ownership for cached responses
            if let Some(wallet) = requesting_wallet {
                if cached.transaction.wallet_address != wallet {
                    return Err(AppError::new(AppErrorKind::Domain(DomainError::Forbidden {
                        message: "Transaction does not belong to the requesting wallet".to_string(),
                    })));
                }
            }
            
            return Ok(cached);
        }

        // Fetch from database
        let transaction = self
            .transaction_repo
            .find_by_id(tx_id)
            .await
            .map_err(|e| {
                error!("Failed to fetch transaction: {}", e);
                AppError::new(AppErrorKind::Domain(DomainError::TransactionNotFound {
                    transaction_id: tx_id.to_string(),
                }))
            })?;

        let tx = match transaction {
            Some(tx) => tx,
            None => {
                return Err(AppError::new(AppErrorKind::Domain(DomainError::TransactionNotFound {
                    transaction_id: tx_id.to_string(),
                })));
            }
        };

        // Verify ownership if wallet is provided
        if let Some(wallet) = requesting_wallet {
            if tx.wallet_address != wallet {
                return Err(AppError::new(AppErrorKind::Domain(DomainError::Forbidden {
                    message: "Transaction does not belong to the requesting wallet".to_string(),
                })));
            }
        }

        // Build response
        let response = self.build_status_response(tx_id, &tx).await?;

        // Cache response with appropriate TTL
        let ttl = get_ttl_for_status(&response.status);
        if let Err(e) = self.cache.set(&cache_key, &response, Some(ttl)).await {
            warn!("Failed to cache onramp status: {}", e);
        }

        Ok(response)
    }

    /// Build status response from transaction
    async fn build_status_response(
        &self,
        tx_id: &str,
        tx: &crate::database::transaction_repository::Transaction,
    ) -> Result<OnrampStatusResponse, AppError> {
        let status = tx.status.clone();
        let stage = map_status_to_stage(&status);
        let message = get_status_message(&status, &tx.payment_provider);

        // Build transaction details
        let transaction_detail = TransactionDetail {
            r#type: "onramp".to_string(),
            amount_ngn: tx.from_amount.clone(),
            amount_cngn: tx.cngn_amount.clone(),
            fees: TransactionFees {
                platform_fee_ngn: extract_platform_fee(&tx.metadata),
                provider_fee_ngn: extract_provider_fee(&tx.metadata),
                total_fee_ngn: extract_total_fee(&tx.metadata),
            },
            provider: tx.payment_provider.clone().unwrap_or_default(),
            wallet_address: tx.wallet_address.clone(),
            chain: "stellar".to_string(),
            created_at: tx.created_at,
            updated_at: tx.updated_at,
            completed_at: if status == "completed" {
                Some(tx.updated_at)
            } else {
                None
            },
        };

        // Check provider status for pending/processing transactions
        let provider_status = if matches!(status.as_str(), "pending" | "processing") {
            self.check_provider_status(&tx.payment_provider, &tx.payment_reference)
                .await
        } else {
            None
        };

        // Check blockchain status for processing/completed transactions
        let blockchain_status = if matches!(status.as_str(), "processing" | "completed") {
            self.check_blockchain_status(&tx.blockchain_tx_hash).await
        } else {
            None
        };

        // Build timeline
        let timeline = build_timeline(&status, tx.created_at, tx.updated_at, &tx.metadata);

        Ok(OnrampStatusResponse {
            tx_id: tx_id.to_string(),
            status,
            stage,
            message,
            failure_reason: tx.error_message.clone(),
            transaction: transaction_detail,
            provider_status,
            blockchain: blockchain_status,
            timeline,
        })
    }

    /// Check payment provider status with timeout handling
    async fn check_provider_status(
        &self,
        provider: &Option<String>,
        reference: &Option<String>,
    ) -> Option<ProviderStatus> {
        let provider_name = provider.as_ref()?;
        let payment_reference = reference.as_ref()?;

        debug!("Checking provider status for {} with reference {}", provider_name, payment_reference);

        // Get provider instance
        let provider_name_enum = match provider_name.parse::<crate::payments::types::ProviderName>() {
            Ok(name) => name,
            Err(e) => {
                warn!("Invalid provider name {}: {}", provider_name, e);
                return Some(ProviderStatus {
                    confirmed: false,
                    reference: payment_reference.clone(),
                    checked_at: Utc::now(),
                    stale: true,
                    error: Some(format!("Invalid provider: {}", provider_name)),
                });
            }
        };

        let provider_instance = match self.payment_factory.get_provider(provider_name_enum) {
            Ok(provider) => provider,
            Err(e) => {
                warn!("Failed to get provider instance for {}: {}", provider_name, e);
                return Some(ProviderStatus {
                    confirmed: false,
                    reference: payment_reference.clone(),
                    checked_at: Utc::now(),
                    stale: true,
                    error: Some(format!("Provider unavailable: {}", e)),
                });
            }
        };

        // Create status request
        let status_request = StatusRequest {
            reference: payment_reference.clone(),
            provider_data: None,
        };

        // Query provider with timeout
        let timeout_duration = Duration::from_secs(10);
        let provider_result = tokio::time::timeout(
            timeout_duration,
            provider_instance.get_payment_status(status_request)
        ).await;

        match provider_result {
            Ok(Ok(status_response)) => {
                let confirmed = matches!(status_response.state, PaymentState::Completed | PaymentState::Confirmed);
                Some(ProviderStatus {
                    confirmed,
                    reference: payment_reference.clone(),
                    checked_at: Utc::now(),
                    stale: false,
                    error: None,
                })
            }
            Ok(Err(e)) => {
                warn!("Provider status check failed for {}: {}", payment_reference, e);
                Some(ProviderStatus {
                    confirmed: false,
                    reference: payment_reference.clone(),
                    checked_at: Utc::now(),
                    stale: true,
                    error: Some(format!("Provider error: {}", e)),
                })
            }
            Err(_) => {
                warn!("Provider status check timed out for {}", payment_reference);
                Some(ProviderStatus {
                    confirmed: false,
                    reference: payment_reference.clone(),
                    checked_at: Utc::now(),
                    stale: true,
                    error: Some("Provider timeout".to_string()),
                })
            }
        }
    }

    /// Check blockchain status with Stellar Horizon
    async fn check_blockchain_status(
        &self,
        tx_hash: &Option<String>,
    ) -> Option<BlockchainStatus> {
        let hash = tx_hash.as_ref()?;

        debug!("Checking blockchain status for transaction {}", hash);

        // Query Stellar Horizon for transaction details
        match self.stellar_client.get_transaction_details(hash).await {
            Ok(tx_details) => {
                let explorer_url = format!("https://stellar.expert/explorer/public/tx/{}", hash);
                Some(BlockchainStatus {
                    stellar_tx_hash: hash.clone(),
                    confirmations: tx_details.ledger.map(|l| l as u32).unwrap_or(0),
                    confirmed: tx_details.successful,
                    explorer_url,
                    checked_at: Utc::now(),
                    stale: false,
                })
            }
            Err(e) => {
                warn!("Failed to check blockchain status for {}: {}", hash, e);
                let explorer_url = format!("https://stellar.expert/explorer/public/tx/{}", hash);
                Some(BlockchainStatus {
                    stellar_tx_hash: hash.clone(),
                    confirmations: 0,
                    confirmed: false,
                    explorer_url,
                    checked_at: Utc::now(),
                    stale: true,
                })
            }
        }
    }
}

/// HTTP handler for GET /api/onramp/status/:tx_id
pub async fn get_onramp_status(
    State(service): State<Arc<OnrampStatusService>>,
    Path(tx_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    info!("GET /api/onramp/status/{}", tx_id);

    // For now, we don't enforce ownership check at the API level
    // In a production system, you'd extract the wallet from JWT claims or API key
    let response = service.get_status(&tx_id, None).await?;

    Ok((StatusCode::OK, Json(response)))
}

/// Response structure for onramp status
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OnrampStatusResponse {
    pub tx_id: String,
    pub status: String,
    pub stage: TransactionStage,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub transaction: TransactionDetail,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_status: Option<ProviderStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockchain: Option<BlockchainStatus>,
    pub timeline: Vec<TimelineEntry>,
}

/// Transaction stage
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStage {
    AwaitingPayment,
    SendingCngn,
    Done,
    Failed,
    Refunded,
}

/// Transaction detail
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionDetail {
    pub r#type: String,
    #[serde(with = "bigdecimal_serde")]
    pub amount_ngn: sqlx::types::BigDecimal,
    #[serde(with = "bigdecimal_serde")]
    pub amount_cngn: sqlx::types::BigDecimal,
    pub fees: TransactionFees,
    pub provider: String,
    pub wallet_address: String,
    pub chain: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Transaction fees
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionFees {
    #[serde(with = "bigdecimal_serde")]
    pub platform_fee_ngn: sqlx::types::BigDecimal,
    #[serde(with = "bigdecimal_serde")]
    pub provider_fee_ngn: sqlx::types::BigDecimal,
    #[serde(with = "bigdecimal_serde")]
    pub total_fee_ngn: sqlx::types::BigDecimal,
}

/// Custom BigDecimal serialization module
mod bigdecimal_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use sqlx::types::BigDecimal;

    pub fn serialize<S>(value: &BigDecimal, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigDecimal, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Provider status
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProviderStatus {
    pub confirmed: bool,
    pub reference: String,
    pub checked_at: DateTime<Utc>,
    pub stale: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Blockchain status
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockchainStatus {
    pub stellar_tx_hash: String,
    pub confirmations: u32,
    pub confirmed: bool,
    pub explorer_url: String,
    pub checked_at: DateTime<Utc>,
    pub stale: bool,
}

/// Timeline entry
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimelineEntry {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub note: String,
}

/// Map status string to transaction stage
fn map_status_to_stage(status: &str) -> TransactionStage {
    match status {
        "pending" => TransactionStage::AwaitingPayment,
        "processing" => TransactionStage::SendingCngn,
        "completed" => TransactionStage::Done,
        "failed" => TransactionStage::Failed,
        "refunded" => TransactionStage::Refunded,
        _ => TransactionStage::AwaitingPayment,
    }
}

/// Get human-readable status message
fn get_status_message(status: &str, provider: &Option<String>) -> String {
    let provider_name = provider.as_deref().unwrap_or("payment provider");
    
    match status {
        "pending" => format!("Waiting for your payment to be confirmed by {}.", provider_name),
        "processing" => "Payment confirmed. Sending cNGN to your wallet.".to_string(),
        "completed" => "cNGN has been sent to your wallet successfully.".to_string(),
        "failed" => "Transaction failed. Please contact support.".to_string(),
        "refunded" => "Refund has been processed.".to_string(),
        _ => "Transaction is being processed.".to_string(),
    }
}

/// Get cache TTL based on status
fn get_ttl_for_status(status: &str) -> Duration {
    match status {
        "pending" => Duration::from_secs(5),
        "processing" => Duration::from_secs(10),
        "completed" | "failed" | "refunded" => Duration::from_secs(300),
        _ => Duration::from_secs(60),
    }
}

/// Build timeline from transaction history
fn build_timeline(
    status: &str,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    _metadata: &serde_json::Value,
) -> Vec<TimelineEntry> {
    let mut timeline = vec![];

    // Always add pending entry
    timeline.push(TimelineEntry {
        status: "pending".to_string(),
        timestamp: created_at,
        note: "Transaction initiated".to_string(),
    });

    // Add processing if applicable
    if status == "processing" || status == "completed" {
        timeline.push(TimelineEntry {
            status: "processing".to_string(),
            timestamp: updated_at,
            note: "Payment confirmed".to_string(),
        });
    }

    // Add completed if applicable
    if status == "completed" {
        timeline.push(TimelineEntry {
            status: "completed".to_string(),
            timestamp: updated_at,
            note: "cNGN sent on Stellar".to_string(),
        });
    }

    // Add failed if applicable
    if status == "failed" {
        timeline.push(TimelineEntry {
            status: "failed".to_string(),
            timestamp: updated_at,
            note: "Transaction failed".to_string(),
        });
    }

    // Add refunded if applicable
    if status == "refunded" {
        timeline.push(TimelineEntry {
            status: "refunded".to_string(),
            timestamp: updated_at,
            note: "Refund processed".to_string(),
        });
    }

    timeline
}

/// Extract platform fee from metadata
fn extract_platform_fee(metadata: &serde_json::Value) -> sqlx::types::BigDecimal {
    metadata
        .get("platform_fee")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| sqlx::types::BigDecimal::from(0))
}

/// Extract provider fee from metadata
fn extract_provider_fee(metadata: &serde_json::Value) -> sqlx::types::BigDecimal {
    metadata
        .get("provider_fee")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| sqlx::types::BigDecimal::from(0))
}

/// Extract total fee from metadata
fn extract_total_fee(metadata: &serde_json::Value) -> sqlx::types::BigDecimal {
    metadata
        .get("total_fee")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| sqlx::types::BigDecimal::from(0))
}
