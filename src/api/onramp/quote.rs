use super::models::*;
use crate::cache::cache::Cache;
use crate::cache::keys::onramp::QuoteKey;
use crate::chains::stellar::client::StellarClient;
use crate::chains::stellar::trustline::CngnTrustlineManager;
use crate::chains::stellar::types::is_valid_stellar_address;
use crate::error::{AppError, AppErrorKind, ValidationError};
use crate::services::exchange_rate::{ConversionDirection, ConversionRequest, ExchangeRateService};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use serde_json::json;
use sqlx::types::BigDecimal;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};
use uuid::Uuid;

const QUOTE_TTL_SECONDS: u64 = 300; // 5 minutes per spec
const MIN_AMOUNT_NGN: f64 = 100.0;
const MAX_AMOUNT_NGN: f64 = 5_000_000.0;
const CNGN_ASSET_CODE: &str = "cNGN";

/// Application state for the quote handler
#[derive(Clone)]
pub struct QuoteHandlerState {
    pub cache: Arc<dyn Cache<StoredQuote> + Send + Sync>,
    pub stellar_client: Arc<StellarClient>,
    pub exchange_rate_service: Arc<ExchangeRateService>,
    pub cngn_issuer: String,
}

/// Handle POST /api/onramp/quote
pub async fn create_quote(
    State(state): State<QuoteHandlerState>,
    Json(request): Json<OnrampQuoteRequest>,
) -> Result<impl IntoResponse, AppError> {
    info!(
        wallet = %request.wallet_address,
        amount = %request.amount,
        "Processing onramp quote request"
    );

    // 1. Validate request
    validate_quote_request(&request)?;

    // Parse amount
    let amount_bd = BigDecimal::from_str(&request.amount).map_err(|_| {
        AppError::new(AppErrorKind::Validation(ValidationError::InvalidAmount {
            amount: request.amount.clone(),
            reason: "Invalid amount format".to_string(),
        }))
    })?;

    let amount_f64: f64 = amount_bd.to_string().parse().unwrap_or(0.0);

    // 2. Fetch exchange rate
    let rate_snapshot_at = Utc::now();
    let conversion_request = ConversionRequest {
        from_currency: request.from_currency.clone(),
        to_currency: request.to_currency.clone(),
        amount: amount_bd.clone(),
        direction: ConversionDirection::Buy,
    };

    let conversion_result = state
        .exchange_rate_service
        .calculate_conversion(conversion_request)
        .await
        .map_err(|e| {
            error!("Failed to fetch exchange rate: {}", e);
            AppError::new(AppErrorKind::External(crate::error::ExternalError::Timeout {
                service: "rate_service".to_string(),
                timeout_secs: 30,
            }))
        })?;

    let rate = BigDecimal::from_str(&conversion_result.base_rate)
        .unwrap_or_else(|_| BigDecimal::from(1));
    let rate_f64: f64 = rate.to_string().parse().unwrap_or(1.0);

    // 3. Calculate gross amount
    let gross_amount = &amount_bd * &rate;

    // 4. Calculate fees
    let (platform_fee, provider_fee) = calculate_fees(&state, &amount_bd, &request.payment_method).await?;

    let total_fees = &platform_fee + &provider_fee;
    let net_amount = &amount_bd - &total_fees;

    // Validate net amount is positive
    if net_amount <= BigDecimal::from(0) {
        return Err(AppError::new(AppErrorKind::Validation(ValidationError::InvalidAmount {
            amount: net_amount.to_string(),
            reason: "Net amount after fees must be greater than zero".to_string(),
        })));
    }

    debug!(
        gross = %gross_amount,
        platform_fee = %platform_fee,
        provider_fee = %provider_fee,
        net = %net_amount,
        "Fee calculation complete"
    );

    // 5. Check trustline status
    let trustline_manager = CngnTrustlineManager::new(state.stellar_client.as_ref().clone());
    let trustline_status = trustline_manager
        .check_trustline(&request.wallet_address)
        .await
        .map_err(|e| {
            error!("Failed to check trustline: {}", e);
            AppError::from(e)
        })?;

    // 6. Generate quote ID and store in Redis
    let quote_id = format!("q_{}", Uuid::new_v4().simple());
    let created_at = Utc::now();
    let expires_at = created_at + chrono::Duration::seconds(QUOTE_TTL_SECONDS as i64);

    let stored_quote = StoredQuote {
        quote_id: quote_id.clone(),
        wallet_address: request.wallet_address.clone(),
        from_currency: request.from_currency.clone(),
        to_currency: request.to_currency.clone(),
        from_amount: request.amount.clone(),
        exchange_rate: rate.to_string(),
        gross_amount: gross_amount.to_string(),
        net_amount: net_amount.to_string(),
        fees: FeeBreakdown {
            provider_fee: ProviderFeeDetail {
                amount: provider_fee.to_string(),
                percentage: ((&provider_fee / &amount_bd) * BigDecimal::from(100))
                    .to_string()
                    .parse()
                    .unwrap_or(0.0),
                provider: "flutterwave".to_string(),
            },
            platform_fee: PlatformFeeDetail {
                amount: platform_fee.to_string(),
                percentage: ((&platform_fee / &amount_bd) * BigDecimal::from(100))
                    .to_string()
                    .parse()
                    .unwrap_or(0.0),
            },
            payment_method_fee: PaymentMethodFeeDetail {
                amount: "0.00".to_string(),
                method: request.payment_method.clone(),
            },
            total_fees: total_fees.to_string(),
        },
        trustline_exists: trustline_status.has_trustline,
        payment_method: request.payment_method.clone(),
        created_at: created_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        status: "pending".to_string(),
    };

    let quote_key = QuoteKey::new(&quote_id);
    state
        .cache
        .set(
            &quote_key.to_string(),
            &stored_quote,
            Some(Duration::from_secs(QUOTE_TTL_SECONDS)),
        )
        .await
        .map_err(|e| {
            error!("Failed to store quote in Redis: {}", e);
            AppError::new(AppErrorKind::Infrastructure(crate::error::InfrastructureError::Cache {
                message: "Failed to store quote".to_string(),
            }))
        })?;

    info!(
        quote_id = %quote_id,
        expires_at = %expires_at,
        "Quote created successfully"
    );

    // 7. Build response based on trustline status
    if trustline_status.has_trustline {
        let effective_rate = if amount_bd > BigDecimal::from(0) {
            (&net_amount / &amount_bd)
                .to_string()
                .parse()
                .unwrap_or(1.0)
        } else {
            1.0
        };

        let response = OnrampQuoteResponse {
            quote_id,
            wallet_address: request.wallet_address,
            from_currency: request.from_currency,
            to_currency: request.to_currency,
            from_amount: request.amount.clone(),
            exchange_rate: rate_f64,
            gross_amount: gross_amount.to_string(),
            fees: stored_quote.fees,
            net_amount: net_amount.to_string(),
            breakdown: Breakdown {
                you_pay: format!("{} NGN", request.amount),
                you_receive: format!("{} cNGN", net_amount.to_string()),
                effective_rate,
            },
            trustline_status: TrustlineStatus {
                exists: true,
                ready_to_receive: true,
                action_required: None,
            },
            validity: Validity {
                expires_at: expires_at.to_rfc3339(),
                expires_in_seconds: QUOTE_TTL_SECONDS as i64,
            },
            next_steps: NextSteps {
                endpoint: "/api/onramp/initiate".to_string(),
                method: "POST".to_string(),
                action: "Proceed to payment".to_string(),
            },
            created_at: created_at.to_rfc3339(),
        };

        Ok((StatusCode::OK, Json(json!(response))))
    } else {
        // No trustline - fetch account to get XLM balance
        let account_info = state
            .stellar_client
            .get_account(&request.wallet_address)
            .await
            .ok();

        let xlm_balance = account_info
            .as_ref()
            .and_then(|acc| {
                acc.balances
                    .iter()
                    .find(|b| b.asset_type == "native")
                    .and_then(|b| b.balance.parse::<f64>().ok())
            })
            .unwrap_or(0.0);

        let xlm_needed = (1.5_f64 - xlm_balance).max(0.0);

        let response = OnrampQuoteResponseNoTrustline {
            quote_id,
            wallet_address: request.wallet_address,
            from_currency: request.from_currency,
            to_currency: request.to_currency,
            from_amount: request.amount,
            net_amount: net_amount.to_string(),
            trustline_status: TrustlineStatus {
                exists: false,
                ready_to_receive: false,
                action_required: Some("create_trustline".to_string()),
            },
            trustline_requirements: TrustlineRequirements {
                asset_code: CNGN_ASSET_CODE.to_string(),
                asset_issuer: state.cngn_issuer.clone(),
                min_xlm_required: "1.5".to_string(),
                current_xlm_balance: format!("{:.2}", xlm_balance),
                xlm_needed: format!("{:.2}", xlm_needed),
                instructions: "You need to add cNGN trustline before receiving cNGN. This requires 0.5 XLM base reserve.".to_string(),
                help_url: "/docs/trustline-setup".to_string(),
            },
            next_steps: json!({
                "step_1": format!("Add {:.2} XLM to your wallet", xlm_needed),
                "step_2": "Create cNGN trustline",
                "step_3": "Return to get new quote",
                "action": "Create trustline first"
            }),
            validity: Validity {
                expires_at: expires_at.to_rfc3339(),
                expires_in_seconds: QUOTE_TTL_SECONDS as i64,
            },
            created_at: created_at.to_rfc3339(),
        };

        Ok((StatusCode::OK, Json(json!(response))))
    }
}

/// Validate the quote request
fn validate_quote_request(request: &OnrampQuoteRequest) -> Result<(), AppError> {
    // Validate wallet address
    if !is_valid_stellar_address(&request.wallet_address) {
        return Err(AppError::new(AppErrorKind::Validation(
            ValidationError::InvalidWalletAddress {
                address: request.wallet_address.clone(),
                reason: "Not a valid Stellar public key".to_string(),
            },
        )));
    }

    // Validate currencies
    if request.from_currency != "NGN" {
        return Err(AppError::new(AppErrorKind::Validation(
            ValidationError::InvalidCurrency {
                currency: request.from_currency.clone(),
                reason: "Only NGN is supported as source currency".to_string(),
            },
        )));
    }

    if request.to_currency != "cNGN" {
        return Err(AppError::new(AppErrorKind::Validation(
            ValidationError::InvalidCurrency {
                currency: request.to_currency.clone(),
                reason: "Only cNGN is supported as target currency".to_string(),
            },
        )));
    }

    // Validate amount
    let amount_f64: f64 = request.amount.parse().map_err(|_| {
        AppError::new(AppErrorKind::Validation(ValidationError::InvalidAmount {
            amount: request.amount.clone(),
            reason: "Invalid amount format".to_string(),
        }))
    })?;

    if amount_f64 < MIN_AMOUNT_NGN {
        return Err(AppError::new(AppErrorKind::Validation(
            ValidationError::OutOfRange {
                field: "amount".to_string(),
                min: Some(MIN_AMOUNT_NGN.to_string()),
                max: Some(MAX_AMOUNT_NGN.to_string()),
            },
        )));
    }

    if amount_f64 > MAX_AMOUNT_NGN {
        return Err(AppError::new(AppErrorKind::Validation(
            ValidationError::OutOfRange {
                field: "amount".to_string(),
                min: Some(MIN_AMOUNT_NGN.to_string()),
                max: Some(MAX_AMOUNT_NGN.to_string()),
            },
        )));
    }

    Ok(())
}

/// Calculate fees for onramp transaction
async fn calculate_fees(
    state: &QuoteHandlerState,
    amount: &BigDecimal,
    payment_method: &Option<String>,
) -> Result<(BigDecimal, BigDecimal), AppError> {
    let method = payment_method.as_deref().unwrap_or("card");

    // Platform fee: 0.1% with minimum ₦10
    let platform_fee_pct = BigDecimal::from_str("0.001").unwrap();
    let platform_fee = (amount * &platform_fee_pct).max(BigDecimal::from(10));

    // Provider fee (Flutterwave): 1.4% or ₦50 (whichever higher), capped at ₦2,000
    let provider_fee_pct = BigDecimal::from_str("0.014").unwrap();
    let provider_fee_calc = amount * &provider_fee_pct;
    let provider_fee_min = BigDecimal::from(50);
    let provider_fee_max = BigDecimal::from(2000);

    let provider_fee = provider_fee_calc
        .max(provider_fee_min)
        .min(provider_fee_max);

    debug!(
        amount = %amount,
        platform_fee = %platform_fee,
        provider_fee = %provider_fee,
        method = %method,
        "Calculated fees"
    );

    Ok((platform_fee, provider_fee))
}
