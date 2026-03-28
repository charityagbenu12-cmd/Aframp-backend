use std::str::FromStr;

use rust_decimal::Decimal;
use serde_json::Value;

use crate::database::wallet_repository::WalletRepository;

use super::errors::IntegrityError;
use super::field_validation::ValidationContext;
use super::{IntegrityEndpoint, RequestIntegrityState};

pub async fn validate_consistency(
    endpoint: IntegrityEndpoint,
    payload: &Value,
    state: &RequestIntegrityState,
    ctx: &ValidationContext,
) -> Result<(), IntegrityError> {
    match endpoint {
        IntegrityEndpoint::OnrampInitiate => validate_onramp_consistency(payload, ctx),
        IntegrityEndpoint::OfframpInitiate => validate_offramp_consistency(payload, ctx),
        IntegrityEndpoint::BatchCngnTransfer => validate_batch_cngn_consistency(payload, state, ctx).await,
        IntegrityEndpoint::BatchFiatPayout => Ok(()),
    }
}

fn validate_onramp_consistency(payload: &Value, ctx: &ValidationContext) -> Result<(), IntegrityError> {
    let Some(quote) = &ctx.stored_quote else {
        return Ok(());
    };

    let wallet_address = payload.get("wallet_address").and_then(Value::as_str).unwrap_or_default();
    if quote.wallet_address != wallet_address {
        return Err(IntegrityError::consistency(
            "QUOTE_WALLET_MISMATCH",
            "wallet_address is inconsistent with the referenced quote",
            Some("wallet_address".to_string()),
        ));
    }

    let provider = payload.get("payment_provider").and_then(Value::as_str).unwrap_or_default();
    if !quote.provider.eq_ignore_ascii_case(provider) {
        return Err(IntegrityError::consistency(
            "QUOTE_PROVIDER_MISMATCH",
            "payment_provider is inconsistent with the referenced quote",
            Some("payment_provider".to_string()),
        ));
    }

    Ok(())
}

fn validate_offramp_consistency(payload: &Value, ctx: &ValidationContext) -> Result<(), IntegrityError> {
    let Some(quote) = &ctx.stored_quote else {
        return Ok(());
    };
    let wallet_address = payload.get("wallet_address").and_then(Value::as_str).unwrap_or_default();
    if quote.wallet_address != wallet_address {
        return Err(IntegrityError::consistency(
            "QUOTE_WALLET_MISMATCH",
            "wallet_address is inconsistent with the referenced quote",
            Some("wallet_address".to_string()),
        ));
    }
    Ok(())
}

async fn validate_batch_cngn_consistency(
    payload: &Value,
    state: &RequestIntegrityState,
    ctx: &ValidationContext,
) -> Result<(), IntegrityError> {
    let Some(db) = &state.db else {
        return Ok(());
    };
    let Some(batch_total) = ctx.batch_total else {
        return Ok(());
    };
    let Some(source_wallet) = payload.get("source_wallet").and_then(Value::as_str) else {
        return Ok(());
    };

    let tolerance = std::env::var("REQUEST_INTEGRITY_BATCH_BALANCE_TOLERANCE")
        .ok()
        .and_then(|value| Decimal::from_str(&value).ok())
        .unwrap_or_else(|| Decimal::new(1, 2));

    let repo = WalletRepository::new(db.as_ref().clone());
    let wallet = repo
        .find_by_account(source_wallet)
        .await
        .map_err(|_| IntegrityError::consistency(
            "SOURCE_WALLET_LOOKUP_FAILED",
            "source_wallet balance could not be validated",
            Some("source_wallet".to_string()),
        ))?
        .ok_or_else(|| IntegrityError::consistency(
            "SOURCE_WALLET_NOT_FOUND",
            "source_wallet does not exist in the wallet catalogue",
            Some("source_wallet".to_string()),
        ))?;

    let balance = Decimal::from_str(&wallet.balance).map_err(|_| {
        IntegrityError::consistency(
            "SOURCE_WALLET_BALANCE_INVALID",
            "source_wallet balance is not parseable",
            Some("source_wallet".to_string()),
        )
    })?;

    if batch_total > balance + tolerance {
        return Err(IntegrityError::consistency(
            "BATCH_TOTAL_EXCEEDS_BALANCE",
            format!(
                "Batch total {batch_total} exceeds the cached balance {balance} with tolerance {tolerance}"
            ),
            Some("transfers".to_string()),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::onramp_quote::StoredQuote;

    #[test]
    fn quote_provider_mismatch_is_rejected() {
        let payload = serde_json::json!({
            "wallet_address": "GBZXN7PIRZGNMHGAI5T7R2PO4N7WFMQ7P3WG2XSEW3VOV6Q2NYV6G3SH",
            "payment_provider": "paystack"
        });
        let ctx = ValidationContext {
            stored_quote: Some(StoredQuote {
                quote_id: "q_1234567890abcdef1234567890abcdef".to_string(),
                wallet_address: "GBZXN7PIRZGNMHGAI5T7R2PO4N7WFMQ7P3WG2XSEW3VOV6Q2NYV6G3SH".to_string(),
                amount_ngn: 1000,
                amount_cngn: "1000".to_string(),
                rate_snapshot: "1.0".to_string(),
                platform_fee_ngn: "10".to_string(),
                provider_fee_ngn: "10".to_string(),
                total_fee_ngn: "20".to_string(),
                provider: "flutterwave".to_string(),
                chain: "stellar".to_string(),
                created_at: chrono::Utc::now().to_rfc3339(),
                expires_at: (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
                status: "pending".to_string(),
            }),
            ..Default::default()
        };

        let err = validate_onramp_consistency(&payload, &ctx).unwrap_err();
        assert_eq!(err.code, "QUOTE_PROVIDER_MISMATCH");
    }
}

