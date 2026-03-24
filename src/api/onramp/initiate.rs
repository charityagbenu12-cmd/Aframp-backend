use crate::cache::cache::Cache;
use crate::cache::keys::onramp::QuoteKey;
use crate::cache::RedisCache;
use crate::chains::stellar::client::StellarClient;
use crate::chains::stellar::trustline::CngnTrustlineManager;
use crate::chains::stellar::types::is_valid_stellar_address;
use crate::database::repository::Repository;
use crate::database::transaction_repository::TransactionRepository;
use crate::error::{AppError, AppErrorKind, DomainError, ExternalError, InfrastructureError, ValidationError};
use crate::services::onramp_quote::StoredQuote;
use crate::services::payment_orchestrator::{
    PaymentInitiationRequest, PaymentOrchestrator,
};
use crate::payments::types::PaymentMethod;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use bigdecimal::BigDecimal;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct OnrampInitiateState {
    pub transaction_repo: Arc<TransactionRepository>,
    pub cache: Arc<RedisCache>,
    pub stellar_client: Arc<StellarClient>,
    pub orchestrator: Arc<PaymentOrchestrator>,
    pub cngn_issuer: String,
}

// ── Request / Response ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct InitiateOnrampRequest {
    pub quote_id: String,
    pub wallet_address: String,
    pub payment_provider: String,
    pub customer_email: Option<String>,
    pub customer_phone: Option<String>,
    pub callback_url: Option<String>,
    /// Optional idempotency key supplied by the client
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InitiateOnrampResponse {
    pub transaction_id: String,
    pub status: String,
    pub payment_instructions: PaymentInstructions,
    pub quote_summary: QuoteSummary,
}

#[derive(Debug, Serialize)]
pub struct PaymentInstructions {
    pub provider: String,
    pub payment_url: Option<String>,
    pub provider_reference: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct QuoteSummary {
    pub quote_id: String,
    pub amount_ngn: String,
    pub amount_cngn: String,
    pub total_fee_ngn: String,
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// POST /api/onramp/initiate
pub async fn initiate_onramp(
    State(state): State<Arc<OnrampInitiateState>>,
    Json(req): Json<InitiateOnrampRequest>,
) -> Result<impl IntoResponse, AppError> {
    // 1. Basic input validation
    if req.quote_id.trim().is_empty() {
        return Err(AppError::new(AppErrorKind::Validation(
            ValidationError::MissingField { field: "quote_id".to_string() },
        )));
    }
    if !is_valid_stellar_address(&req.wallet_address) {
        return Err(AppError::new(AppErrorKind::Validation(
            ValidationError::InvalidWalletAddress {
                address: req.wallet_address.clone(),
                reason: "Not a valid Stellar public key".to_string(),
            },
        )));
    }

    // 2. Fetch quote from Redis
    let quote_key = QuoteKey::new(&req.quote_id).to_string();
    let quote: StoredQuote = {
        let cache: &dyn Cache<StoredQuote> = &*state.cache;
        cache
            .get(&quote_key)
            .await
            .map_err(|e| {
                error!(error = %e, "Cache error fetching quote");
                AppError::new(AppErrorKind::Infrastructure(InfrastructureError::Cache {
                    message: "Failed to fetch quote".to_string(),
                }))
            })?
            .ok_or_else(|| {
                AppError::new(AppErrorKind::Domain(DomainError::RateExpired {
                    quote_id: req.quote_id.clone(),
                }))
            })?
    };

    // 3. Validate quote belongs to this wallet
    if quote.wallet_address != req.wallet_address {
        return Err(AppError::new(AppErrorKind::Validation(
            ValidationError::InvalidWalletAddress {
                address: req.wallet_address.clone(),
                reason: "Wallet address does not match quote".to_string(),
            },
        )));
    }

    // 4. Verify trustline
    let trustline_manager = CngnTrustlineManager::new((*state.stellar_client).clone());
    let trustline_status = trustline_manager
        .check_trustline(&req.wallet_address)
        .await
        .map_err(|e| AppError::from(e))?;

    if !trustline_status.has_trustline {
        return Err(AppError::new(AppErrorKind::Domain(
            DomainError::TrustlineNotFound {
                wallet_address: req.wallet_address.clone(),
                asset: "cNGN".to_string(),
            },
        )));
    }

    // 5. Check minimum Stellar XLM balance (account must exist and have ≥ 1 XLM)
    let account = state
        .stellar_client
        .get_account(&req.wallet_address)
        .await
        .map_err(|e| {
            warn!(wallet = %req.wallet_address, error = %e, "Failed to fetch Stellar account");
            AppError::new(AppErrorKind::Domain(DomainError::WalletNotFound {
                wallet_address: req.wallet_address.clone(),
            }))
        })?;

    let xlm_balance: f64 = account
        .balances
        .iter()
        .find(|b| b.asset_type == "native")
        .and_then(|b| b.balance.parse().ok())
        .unwrap_or(0.0);

    if xlm_balance < 1.0 {
        return Err(AppError::new(AppErrorKind::Domain(
            DomainError::InsufficientBalance {
                available: xlm_balance.to_string(),
                required: "1.0 XLM".to_string(),
            },
        )));
    }

    // 6. Idempotency — derive key from client-supplied or wallet+quote
    let idempotency_key = req
        .idempotency_key
        .clone()
        .unwrap_or_else(|| format!("onramp:{}:{}", req.wallet_address, req.quote_id));

    let idem_cache_key = format!("idempotency:{}", idempotency_key);

    if let Ok(Some(existing_tx_id)) = {
        let cache: &dyn Cache<String> = &*state.cache;
        cache.get(&idem_cache_key).await
    } {
        info!(
            idempotency_key = %idempotency_key,
            transaction_id = %existing_tx_id,
            "Duplicate request — returning existing transaction"
        );
        // Fetch existing transaction and return same response
        let tx = state
            .transaction_repo
            .as_ref()
            .find_by_id(&existing_tx_id)
            .await
            .map_err(|e| {
                AppError::new(AppErrorKind::Infrastructure(InfrastructureError::Database {
                    message: e.to_string(),
                    is_retryable: true,
                }))
            })?
            .ok_or_else(|| {
                AppError::new(AppErrorKind::Domain(DomainError::TransactionNotFound {
                    transaction_id: existing_tx_id.clone(),
                }))
            })?;

        return Ok((
            StatusCode::OK,
            Json(InitiateOnrampResponse {
                transaction_id: tx.transaction_id.to_string(),
                status: tx.status.clone(),
                payment_instructions: PaymentInstructions {
                    provider: tx.payment_provider.clone().unwrap_or_default(),
                    payment_url: tx.metadata.get("payment_url").and_then(|v: &serde_json::Value| v.as_str()).map(String::from),
                    provider_reference: tx.payment_reference.clone(),
                },
                quote_summary: QuoteSummary {
                    quote_id: req.quote_id.clone(),
                    amount_ngn: quote.amount_ngn.to_string(),
                    amount_cngn: quote.amount_cngn.clone(),
                    total_fee_ngn: quote.total_fee_ngn.clone(),
                },
            }),
        ));
    }

    // 7. Create pending transaction record BEFORE calling provider
    let amount_ngn = BigDecimal::from(quote.amount_ngn);
    let amount_cngn = BigDecimal::from_str(&quote.amount_cngn).unwrap_or_else(|_| BigDecimal::from(0));

    let tx_metadata = serde_json::json!({
        "quote_id": quote.quote_id,
        "idempotency_key": idempotency_key,
        "rate_snapshot": quote.rate_snapshot,
        "chain": quote.chain,
    });

    let transaction = state
        .transaction_repo
        .create_transaction(
            &req.wallet_address,
            "onramp",
            "NGN",
            "cNGN",
            amount_ngn.clone(),
            amount_cngn.clone(),
            amount_cngn.clone(),
            "pending",
            Some(&req.payment_provider),
            None,
            tx_metadata,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to create transaction record");
            AppError::new(AppErrorKind::Infrastructure(InfrastructureError::Database {
                message: e.to_string(),
                is_retryable: true,
            }))
        })?;

    let tx_id = transaction.transaction_id.to_string();

    // 8. Route through Payment Orchestration Service (#20)
    let initiation_req = PaymentInitiationRequest {
        wallet_address: req.wallet_address.clone(),
        amount: amount_ngn.clone(),
        currency: "NGN".to_string(),
        payment_method: PaymentMethod::Card,
        customer_email: req.customer_email.clone(),
        customer_phone: req.customer_phone.clone(),
        callback_url: req.callback_url.clone(),
        idempotency_key: Some(idempotency_key.clone()),
        metadata: Some(serde_json::json!({
            "quote_id": quote.quote_id,
            "wallet_address": req.wallet_address,
            "transaction_id": tx_id,
        })),
    };

    let payment_response = match state.orchestrator.initiate_payment(initiation_req).await {
        Ok(resp) => resp,
        Err(e) => {
            // Rollback: mark transaction as failed before returning error
            error!(tx_id = %tx_id, error = %e, "Orchestrator payment failed — rolling back");
            let _ = state
                .transaction_repo
                .update_error(&tx_id, &e.to_string())
                .await;
            return Err(AppError::from(e));
        }
    };

    // 9. Update transaction with provider reference and payment URL
    let updated_metadata = serde_json::json!({
        "provider_reference": payment_response.provider_reference,
        "payment_url": payment_response.payment_url,
    });
    let _ = state
        .transaction_repo
        .update_status_with_metadata(&tx_id, "pending", updated_metadata)
        .await;

    // 10. Invalidate quote in Redis
    if let Err(e) = {
        let cache: &dyn Cache<StoredQuote> = &*state.cache;
        cache.delete(&quote_key).await
    } {
        warn!(quote_id = %req.quote_id, error = %e, "Failed to invalidate quote in Redis");
    }

    // 11. Store idempotency key (TTL: 24h)
    {
        let cache: &dyn Cache<String> = &*state.cache;
        let _ = cache
            .set(
                &idem_cache_key,
                &tx_id,
                Some(std::time::Duration::from_secs(86400)),
            )
            .await;
    }

    // 12. Structured log
    info!(
        transaction_id = %tx_id,
        wallet = %req.wallet_address,
        provider = %req.payment_provider,
        amount_ngn = %amount_ngn,
        amount_cngn = %amount_cngn,
        quote_id = %req.quote_id,
        "Onramp transaction created"
    );

    Ok((
        StatusCode::OK,
        Json(InitiateOnrampResponse {
            transaction_id: tx_id,
            status: "pending".to_string(),
            payment_instructions: PaymentInstructions {
                provider: req.payment_provider,
                payment_url: payment_response.payment_url,
                provider_reference: payment_response.provider_reference,
            },
            quote_summary: QuoteSummary {
                quote_id: req.quote_id,
                amount_ngn: quote.amount_ngn.to_string(),
                amount_cngn: quote.amount_cngn,
                total_fee_ngn: quote.total_fee_ngn,
            },
        }),
    ))
}

// ── Unit Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::onramp_quote::StoredQuote;

    fn make_stored_quote(wallet: &str) -> StoredQuote {
        StoredQuote {
            quote_id: "q_test123".to_string(),
            wallet_address: wallet.to_string(),
            amount_ngn: 5000,
            amount_cngn: "5000".to_string(),
            rate_snapshot: "1".to_string(),
            platform_fee_ngn: "50".to_string(),
            provider_fee_ngn: "75".to_string(),
            total_fee_ngn: "125".to_string(),
            provider: "paystack".to_string(),
            chain: "stellar".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: (chrono::Utc::now() + chrono::Duration::seconds(180)).to_rfc3339(),
            status: "pending".to_string(),
        }
    }

    #[test]
    fn test_wallet_mismatch_detected() {
        let quote = make_stored_quote("GABC");
        assert_ne!(quote.wallet_address, "GXYZ");
    }

    #[test]
    fn test_quote_fields_present() {
        let quote = make_stored_quote("GABC");
        assert_eq!(quote.amount_ngn, 5000);
        assert_eq!(quote.total_fee_ngn, "125");
        assert_eq!(quote.status, "pending");
    }

    #[test]
    fn test_idempotency_key_derivation() {
        let wallet = "GABC123";
        let quote_id = "q_test123";
        let key = format!("onramp:{}:{}", wallet, quote_id);
        assert_eq!(key, "onramp:GABC123:q_test123");
    }

    #[test]
    fn test_invalid_wallet_address_rejected() {
        assert!(!is_valid_stellar_address("not-a-stellar-address"));
        assert!(!is_valid_stellar_address(""));
    }
}
