//! Kenya corridor service — orchestrates the full NG→KE transfer flow.

use crate::compliance_registry::repository::ComplianceRegistryRepository;
use crate::corridors::kenya::models::*;
use crate::payments::providers::mpesa_kenya::{
    validate_mpesa_recipient, MpesaKenyaConfig, MpesaKenyaProvider,
};
use crate::payments::provider::PaymentProvider;
use crate::payments::types::{Money, WithdrawalMethod, WithdrawalRecipient, WithdrawalRequest};
use crate::services::exchange_rate::ExchangeRateService;
use crate::services::fee_calculation::FeeCalculationService;
use bigdecimal::BigDecimal;
use chrono::Utc;
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum KenyaCorridorError {
    #[error("compliance check failed: {0}")]
    ComplianceDenied(String),

    #[error("recipient validation failed: {0}")]
    RecipientInvalid(String),

    #[error("FX rate unavailable: {0}")]
    FxUnavailable(String),

    #[error("transaction limit exceeded: {0}")]
    LimitExceeded(String),

    #[error("CBK requirement not met: {0}")]
    CbkRequirement(String),

    #[error("disbursement failed: {0}")]
    DisbursementFailed(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("internal error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

pub struct KenyaCorridorService {
    pool: PgPool,
    compliance_repo: Arc<ComplianceRegistryRepository>,
    exchange_rate_svc: Arc<ExchangeRateService>,
    fee_svc: Arc<FeeCalculationService>,
    mpesa_config: MpesaKenyaConfig,
    /// UUID of the NG→KE corridor row in payment_corridors.
    corridor_id: Uuid,
}

impl KenyaCorridorService {
    pub fn new(
        pool: PgPool,
        compliance_repo: Arc<ComplianceRegistryRepository>,
        exchange_rate_svc: Arc<ExchangeRateService>,
        fee_svc: Arc<FeeCalculationService>,
        mpesa_config: MpesaKenyaConfig,
        corridor_id: Uuid,
    ) -> Self {
        Self {
            pool,
            compliance_repo,
            exchange_rate_svc,
            fee_svc,
            mpesa_config,
            corridor_id,
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Build a quote for a cNGN → KES transfer without committing anything.
    pub async fn get_quote(
        &self,
        cngn_amount: Decimal,
    ) -> Result<KenyaTransferQuote, KenyaCorridorError> {
        let (ngn_kes_rate, kes_gross, fee_breakdown) =
            self.calculate_kes_output(cngn_amount).await?;

        let kes_net = kes_gross - fee_breakdown.total_fee_kes;

        Ok(KenyaTransferQuote {
            quote_id: Uuid::new_v4(),
            cngn_amount,
            ngn_equivalent: cngn_amount, // 1 cNGN = 1 NGN
            ngn_kes_rate,
            kes_gross,
            corridor_fee_kes: fee_breakdown.total_fee_kes,
            kes_net,
            fee_breakdown,
            expires_at: Utc::now() + chrono::Duration::seconds(300),
        })
    }

    /// Validate recipient and initiate the transfer.
    pub async fn initiate_transfer(
        &self,
        req: &KenyaTransferRequest,
    ) -> Result<KenyaTransferResponse, KenyaCorridorError> {
        // 1. Compliance gate — corridor must be active and limits respected.
        let cngn_bd = BigDecimal::from_str(&req.cngn_amount.to_string())
            .map_err(|e| KenyaCorridorError::Internal(e.to_string()))?;

        let compliance = self
            .compliance_repo
            .check_compliance(self.corridor_id, req.cngn_amount, "NGN")
            .await
            .map_err(|e| KenyaCorridorError::Database(e.to_string()))?;

        if !compliance.allowed {
            return Err(KenyaCorridorError::ComplianceDenied(
                compliance
                    .denial_reason
                    .unwrap_or_else(|| "Corridor compliance check failed".to_string()),
            ));
        }

        // 2. FX + fee calculation.
        let (ngn_kes_rate, kes_gross, fee_breakdown) =
            self.calculate_kes_output(req.cngn_amount).await?;
        let kes_net = kes_gross - fee_breakdown.total_fee_kes;

        // 3. Enforce M-Pesa / CBK transaction limits.
        self.enforce_limits(kes_net, req)?;

        // 4. Recipient validation.
        let recipient_validated = self.validate_recipient(req).await?;

        // 5. Build quote snapshot.
        let quote = KenyaTransferQuote {
            quote_id: Uuid::new_v4(),
            cngn_amount: req.cngn_amount,
            ngn_equivalent: req.cngn_amount,
            ngn_kes_rate,
            kes_gross,
            corridor_fee_kes: fee_breakdown.total_fee_kes,
            kes_net,
            fee_breakdown,
            expires_at: Utc::now() + chrono::Duration::seconds(300),
        };

        // 6. Persist transfer record.
        let transfer_id = Uuid::new_v4();
        self.persist_transfer(transfer_id, req, &quote).await?;

        // 7. Tag transaction with compliance context.
        let compliance_tag = self
            .compliance_repo
            .tag_transaction(
                transfer_id,
                self.corridor_id,
                compliance.license_id,
                compliance.ruleset_id,
            )
            .await
            .map_err(|e| KenyaCorridorError::Database(e.to_string()))?;

        // 8. Dispatch KES disbursement.
        let disburse_result = self.disburse_kes(transfer_id, req, &quote).await;

        match disburse_result {
            Ok(provider_ref) => {
                self.update_transfer_status(
                    transfer_id,
                    KenyaTransferStatus::DisbursementPending,
                    Some(provider_ref),
                    None,
                )
                .await?;

                info!(
                    transfer_id = %transfer_id,
                    kes_net = %kes_net,
                    "Kenya corridor disbursement queued"
                );

                Ok(KenyaTransferResponse {
                    transfer_id,
                    status: KenyaTransferStatus::DisbursementPending,
                    quote,
                    recipient_validated,
                    compliance_tag_id: Some(compliance_tag.id),
                    created_at: Utc::now(),
                    message: "KES disbursement queued via M-Pesa".to_string(),
                })
            }
            Err(e) => {
                error!(
                    transfer_id = %transfer_id,
                    error = %e,
                    "Kenya corridor disbursement failed — initiating cNGN refund"
                );

                self.update_transfer_status(
                    transfer_id,
                    KenyaTransferStatus::RefundInitiated,
                    None,
                    Some(e.to_string()),
                )
                .await?;

                // Trigger refund (best-effort; worker will retry if this fails).
                let _ = self.initiate_cngn_refund(transfer_id, req).await;

                Err(KenyaCorridorError::DisbursementFailed(e.to_string()))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Fetch live NGN/KES rate and compute gross KES + fee breakdown.
    async fn calculate_kes_output(
        &self,
        cngn_amount: Decimal,
    ) -> Result<(Decimal, Decimal, CorridorFeeBreakdown), KenyaCorridorError> {
        let rate_bd = self
            .exchange_rate_svc
            .get_rate("NGN", "KES")
            .await
            .map_err(|e| KenyaCorridorError::FxUnavailable(e.to_string()))?;

        let rate = Decimal::from_str(&rate_bd.to_string())
            .map_err(|e| KenyaCorridorError::Internal(e.to_string()))?;

        let kes_gross = cngn_amount * rate;

        // Corridor fee: 1.5% platform + ~KES 30 M-Pesa B2C flat fee.
        let platform_fee_bps: u32 = 150;
        let platform_fee_kes = kes_gross * Decimal::new(platform_fee_bps as i64, 4);
        let provider_fee_kes = Decimal::new(30, 0); // KES 30 flat
        let regulatory_levy_kes = Decimal::ZERO; // CBK levy absorbed by platform
        let total_fee_kes = platform_fee_kes + provider_fee_kes + regulatory_levy_kes;

        Ok((
            rate,
            kes_gross,
            CorridorFeeBreakdown {
                platform_fee_bps,
                platform_fee_kes,
                provider_fee_kes,
                regulatory_levy_kes,
                total_fee_kes,
            },
        ))
    }

    /// Enforce M-Pesa single-transaction and CBK National ID requirements.
    fn enforce_limits(
        &self,
        kes_net: Decimal,
        req: &KenyaTransferRequest,
    ) -> Result<(), KenyaCorridorError> {
        // M-Pesa B2C single transaction cap: KES 150,000.
        let mpesa_cap = Decimal::new(150_000, 0);
        if kes_net > mpesa_cap {
            return Err(KenyaCorridorError::LimitExceeded(format!(
                "KES {kes_net} exceeds M-Pesa single-transaction limit of KES 150,000"
            )));
        }

        // CBK: National ID required for transfers ≥ KES 150,000.
        let cbk_id_threshold = Decimal::new(150_000, 0);
        if kes_net >= cbk_id_threshold && req.recipient_national_id.is_none() {
            return Err(KenyaCorridorError::CbkRequirement(
                "Recipient National ID is required for transfers of KES 150,000 or more (CBK regulation)".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate the Kenyan recipient (phone or bank account).
    async fn validate_recipient(
        &self,
        req: &KenyaTransferRequest,
    ) -> Result<bool, KenyaCorridorError> {
        if let Some(phone) = &req.recipient_phone {
            let result = validate_mpesa_recipient(&self.mpesa_config, phone)
                .await
                .map_err(|e| KenyaCorridorError::RecipientInvalid(e.to_string()))?;

            if !result.valid {
                return Err(KenyaCorridorError::RecipientInvalid(
                    result
                        .reason
                        .unwrap_or_else(|| "Phone number validation failed".to_string()),
                ));
            }
            return Ok(true);
        }

        if req.recipient_bank.is_some() {
            // Bank account validation would call Flutterwave's resolve endpoint.
            // Treated as valid for now; full implementation in a follow-up.
            return Ok(true);
        }

        Err(KenyaCorridorError::RecipientInvalid(
            "Either recipient_phone or recipient_bank must be provided".to_string(),
        ))
    }

    /// Dispatch the KES disbursement via M-Pesa B2C.
    async fn disburse_kes(
        &self,
        transfer_id: Uuid,
        req: &KenyaTransferRequest,
        quote: &KenyaTransferQuote,
    ) -> Result<String, KenyaCorridorError> {
        let provider = MpesaKenyaProvider::new(self.mpesa_config.clone())
            .map_err(|e| KenyaCorridorError::Internal(e.to_string()))?;

        let phone = req
            .recipient_phone
            .as_deref()
            .ok_or_else(|| {
                KenyaCorridorError::Internal("No phone number for M-Pesa disbursement".to_string())
            })?;

        let wd_req = WithdrawalRequest {
            amount: Money {
                amount: quote.kes_net.to_string(),
                currency: "KES".to_string(),
            },
            recipient: WithdrawalRecipient {
                account_name: Some(req.recipient_name.clone()),
                account_number: None,
                bank_code: None,
                phone_number: Some(phone.to_string()),
            },
            withdrawal_method: WithdrawalMethod::MobileMoney,
            transaction_reference: transfer_id.to_string(),
            reason: req.purpose.clone(),
            metadata: Some(serde_json::json!({
                "corridor": "NG-KE",
                "sender_wallet": req.sender_wallet,
                "recipient_national_id": req.recipient_national_id,
                "cbk_reference": format!("CBK-{}", transfer_id),
            })),
        };

        let resp = provider
            .process_withdrawal(wd_req)
            .await
            .map_err(|e| KenyaCorridorError::DisbursementFailed(e.to_string()))?;

        Ok(resp.provider_reference.unwrap_or_else(|| transfer_id.to_string()))
    }

    /// Persist the transfer record to the database.
    async fn persist_transfer(
        &self,
        transfer_id: Uuid,
        req: &KenyaTransferRequest,
        quote: &KenyaTransferQuote,
    ) -> Result<(), KenyaCorridorError> {
        let metadata = serde_json::json!({
            "corridor": "NG-KE",
            "idempotency_key": req.idempotency_key,
            "recipient_phone": req.recipient_phone,
            "recipient_bank": req.recipient_bank,
            "recipient_national_id": req.recipient_national_id,
            "purpose": req.purpose,
            "ngn_kes_rate": quote.ngn_kes_rate.to_string(),
            "kes_gross": quote.kes_gross.to_string(),
            "corridor_fee_kes": quote.corridor_fee_kes.to_string(),
            "kes_net": quote.kes_net.to_string(),
            "cbk_reference": format!("CBK-{}", transfer_id),
        });

        sqlx::query!(
            r#"
            INSERT INTO transactions (
                transaction_id, wallet_address, type,
                from_currency, to_currency,
                from_amount, to_amount,
                status, metadata, created_at, updated_at
            ) VALUES (
                $1, $2, 'kenya_corridor',
                'cNGN', 'KES',
                $3, $4,
                'pending_cngn', $5, NOW(), NOW()
            )
            ON CONFLICT (transaction_id) DO NOTHING
            "#,
            transfer_id,
            req.sender_wallet,
            req.cngn_amount as Decimal,
            quote.kes_net as Decimal,
            metadata,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| KenyaCorridorError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update transfer status in the database.
    async fn update_transfer_status(
        &self,
        transfer_id: Uuid,
        status: KenyaTransferStatus,
        provider_reference: Option<String>,
        error_message: Option<String>,
    ) -> Result<(), KenyaCorridorError> {
        sqlx::query!(
            r#"
            UPDATE transactions
            SET status = $2,
                payment_reference = COALESCE($3, payment_reference),
                error_message = COALESCE($4, error_message),
                updated_at = NOW()
            WHERE transaction_id = $1
            "#,
            transfer_id,
            status.as_str(),
            provider_reference,
            error_message,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| KenyaCorridorError::Database(e.to_string()))?;

        Ok(())
    }

    /// Initiate a cNGN refund to the sender's wallet when disbursement fails.
    async fn initiate_cngn_refund(
        &self,
        transfer_id: Uuid,
        req: &KenyaTransferRequest,
    ) -> Result<(), KenyaCorridorError> {
        warn!(
            transfer_id = %transfer_id,
            sender_wallet = %req.sender_wallet,
            cngn_amount = %req.cngn_amount,
            "Initiating cNGN refund for failed Kenya corridor transfer"
        );

        // Mark as refund_initiated; the offramp refund worker picks this up
        // and sends cNGN back via the Stellar payment builder.
        sqlx::query!(
            r#"
            UPDATE transactions
            SET status = 'refund_initiated',
                metadata = metadata || $2::jsonb,
                updated_at = NOW()
            WHERE transaction_id = $1
            "#,
            transfer_id,
            serde_json::json!({ "refund_reason": "kenya_disbursement_failed" }),
        )
        .execute(&self.pool)
        .await
        .map_err(|e| KenyaCorridorError::Database(e.to_string()))?;

        Ok(())
    }
}
