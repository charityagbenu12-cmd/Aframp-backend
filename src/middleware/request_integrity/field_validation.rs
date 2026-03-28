use std::collections::HashSet;
use std::str::FromStr;

use rust_decimal::Decimal;
use serde_json::Value;
use tracing::warn;
use uuid::Uuid;

use crate::cache::cache::Cache;
use crate::chains::stellar::types::is_valid_stellar_address;
use crate::database::provider_config_repository::ProviderConfigRepository;
use crate::services::onramp_quote::StoredQuote;

use super::errors::IntegrityError;
use super::{IntegrityEndpoint, RequestIntegrityState};

#[derive(Debug, Clone, Default)]
pub struct ValidationContext {
    pub stored_quote: Option<StoredQuote>,
    pub amount_snapshot: Option<Decimal>,
    pub batch_total: Option<Decimal>,
}

pub async fn validate_fields(
    endpoint: IntegrityEndpoint,
    payload: &Value,
    state: &RequestIntegrityState,
    ctx: &mut ValidationContext,
) -> Result<(), IntegrityError> {
    match endpoint {
        IntegrityEndpoint::OnrampInitiate => validate_onramp_initiate(payload, state, ctx).await,
        IntegrityEndpoint::OfframpInitiate => validate_offramp_initiate(payload, state, ctx).await,
        IntegrityEndpoint::BatchCngnTransfer => validate_batch_cngn(payload, ctx),
        IntegrityEndpoint::BatchFiatPayout => validate_batch_fiat(payload, ctx),
    }
}

async fn validate_onramp_initiate(
    payload: &Value,
    state: &RequestIntegrityState,
    ctx: &mut ValidationContext,
) -> Result<(), IntegrityError> {
    let quote_id = required_string(payload, "quote_id")?;
    let wallet_address = required_string(payload, "wallet_address")?;
    let payment_provider = required_string(payload, "payment_provider")?;

    validate_quote_id_format(quote_id)?;
    validate_stellar_wallet("wallet_address", wallet_address)?;
    validate_provider_id(payment_provider, state).await?;

    let quote = load_quote(quote_id, state).await?;
    validate_quote_is_active(quote_id, &quote)?;
    ctx.amount_snapshot = Some(Decimal::from(quote.amount_ngn));
    ctx.stored_quote = Some(quote);
    Ok(())
}

async fn validate_offramp_initiate(
    payload: &Value,
    state: &RequestIntegrityState,
    ctx: &mut ValidationContext,
) -> Result<(), IntegrityError> {
    let quote_id = required_string(payload, "quote_id")?;
    let wallet_address = required_string(payload, "wallet_address")?;

    validate_quote_id_format(quote_id)?;
    validate_stellar_wallet("wallet_address", wallet_address)?;

    let bank_details = payload
        .get("bank_details")
        .and_then(Value::as_object)
        .ok_or_else(|| IntegrityError::field("INVALID_BANK_DETAILS", "bank_details must be an object", Some("bank_details".to_string())))?;

    let bank_code = bank_details
        .get("bank_code")
        .and_then(Value::as_str)
        .ok_or_else(|| IntegrityError::field("INVALID_BANK_CODE", "bank_code must be a string", Some("bank_details.bank_code".to_string())))?;
    let account_number = bank_details
        .get("account_number")
        .and_then(Value::as_str)
        .ok_or_else(|| IntegrityError::field("INVALID_ACCOUNT_NUMBER", "account_number must be a string", Some("bank_details.account_number".to_string())))?;
    let account_name = bank_details
        .get("account_name")
        .and_then(Value::as_str)
        .ok_or_else(|| IntegrityError::field("INVALID_ACCOUNT_NAME", "account_name must be a string", Some("bank_details.account_name".to_string())))?;

    if bank_code.len() != 3 || !bank_code.chars().all(|c| c.is_ascii_digit()) {
        return Err(IntegrityError::field(
            "INVALID_BANK_CODE",
            "bank_code must be a 3-digit string",
            Some("bank_details.bank_code".to_string()),
        ));
    }
    if account_number.len() != 10 || !account_number.chars().all(|c| c.is_ascii_digit()) {
        return Err(IntegrityError::field(
            "INVALID_ACCOUNT_NUMBER",
            "account_number must be exactly 10 digits",
            Some("bank_details.account_number".to_string()),
        ));
    }
    if account_name.trim().is_empty() {
        return Err(IntegrityError::field(
            "INVALID_ACCOUNT_NAME",
            "account_name must not be empty",
            Some("bank_details.account_name".to_string()),
        ));
    }

    let quote = load_quote(quote_id, state).await?;
    validate_quote_is_active(quote_id, &quote)?;
    ctx.amount_snapshot = Decimal::from_str(&quote.amount_cngn).ok();
    ctx.stored_quote = Some(quote);
    Ok(())
}

fn validate_batch_cngn(payload: &Value, ctx: &mut ValidationContext) -> Result<(), IntegrityError> {
    let source_wallet = required_string(payload, "source_wallet")?;
    validate_stellar_wallet("source_wallet", source_wallet)?;

    let transfers = payload
        .get("transfers")
        .and_then(Value::as_array)
        .ok_or_else(|| IntegrityError::field("INVALID_TRANSFERS", "transfers must be an array", Some("transfers".to_string())))?;
    if transfers.is_empty() {
        return Err(IntegrityError::field(
            "EMPTY_BATCH",
            "Batch must contain at least one transfer",
            Some("transfers".to_string()),
        ));
    }

    let mut total = Decimal::ZERO;
    for (index, item) in transfers.iter().enumerate() {
        let item_obj = item.as_object().ok_or_else(|| {
            IntegrityError::field(
                "INVALID_TRANSFER_ITEM",
                "Each transfer must be an object",
                Some(format!("transfers[{index}]")),
            )
        })?;
        let destination_wallet = item_obj
            .get("destination_wallet")
            .and_then(Value::as_str)
            .ok_or_else(|| IntegrityError::field("INVALID_DESTINATION_WALLET", "destination_wallet must be a string", Some(format!("transfers[{index}].destination_wallet"))))?;
        validate_stellar_wallet(&format!("transfers[{index}].destination_wallet"), destination_wallet)?;
        let amount = item_obj
            .get("amount_cngn")
            .and_then(Value::as_str)
            .ok_or_else(|| IntegrityError::field("INVALID_AMOUNT", "amount_cngn must be a string", Some(format!("transfers[{index}].amount_cngn"))))?;
        let parsed = validate_amount(amount, CurrencyKind::Cngn, Some(format!("transfers[{index}].amount_cngn")))?;
        total += parsed;
    }

    ctx.batch_total = Some(total);
    Ok(())
}

fn validate_batch_fiat(payload: &Value, ctx: &mut ValidationContext) -> Result<(), IntegrityError> {
    let payouts = payload
        .get("payouts")
        .and_then(Value::as_array)
        .ok_or_else(|| IntegrityError::field("INVALID_PAYOUTS", "payouts must be an array", Some("payouts".to_string())))?;
    if payouts.is_empty() {
        return Err(IntegrityError::field(
            "EMPTY_BATCH",
            "Batch must contain at least one payout",
            Some("payouts".to_string()),
        ));
    }

    let mut total = Decimal::ZERO;
    for (index, item) in payouts.iter().enumerate() {
        let item_obj = item.as_object().ok_or_else(|| {
            IntegrityError::field(
                "INVALID_PAYOUT_ITEM",
                "Each payout must be an object",
                Some(format!("payouts[{index}]")),
            )
        })?;
        let bank_code = item_obj
            .get("bank_code")
            .and_then(Value::as_str)
            .ok_or_else(|| IntegrityError::field("INVALID_BANK_CODE", "bank_code must be a string", Some(format!("payouts[{index}].bank_code"))))?;
        if bank_code.len() != 3 || !bank_code.chars().all(|c| c.is_ascii_digit()) {
            return Err(IntegrityError::field(
                "INVALID_BANK_CODE",
                "bank_code must be a 3-digit string",
                Some(format!("payouts[{index}].bank_code")),
            ));
        }
        let account_number = item_obj
            .get("bank_account_number")
            .and_then(Value::as_str)
            .ok_or_else(|| IntegrityError::field("INVALID_BANK_ACCOUNT", "bank_account_number must be a string", Some(format!("payouts[{index}].bank_account_number"))))?;
        if account_number.len() != 10 || !account_number.chars().all(|c| c.is_ascii_digit()) {
            return Err(IntegrityError::field(
                "INVALID_BANK_ACCOUNT",
                "bank_account_number must be exactly 10 digits",
                Some(format!("payouts[{index}].bank_account_number")),
            ));
        }
        let amount = item_obj
            .get("amount_ngn")
            .and_then(Value::as_str)
            .ok_or_else(|| IntegrityError::field("INVALID_AMOUNT", "amount_ngn must be a string", Some(format!("payouts[{index}].amount_ngn"))))?;
        total += validate_amount(amount, CurrencyKind::Ngn, Some(format!("payouts[{index}].amount_ngn")))?;
    }

    ctx.batch_total = Some(total);
    Ok(())
}

async fn validate_provider_id(provider: &str, state: &RequestIntegrityState) -> Result<(), IntegrityError> {
    let static_allowed: HashSet<&str> = ["flutterwave", "paystack", "mpesa", "mock"].into_iter().collect();
    if static_allowed.contains(provider) {
        return Ok(());
    }

    let Some(db) = &state.db else {
        return Err(IntegrityError::field(
            "UNKNOWN_PROVIDER_IDENTIFIER",
            format!("Provider '{provider}' is not active"),
            Some("payment_provider".to_string()),
        ));
    };

    let repo = ProviderConfigRepository::new(db.as_ref().clone());
    match repo.find_by_provider(provider).await {
        Ok(Some(config)) if config.is_enabled => Ok(()),
        Ok(_) => Err(IntegrityError::field(
            "UNKNOWN_PROVIDER_IDENTIFIER",
            format!("Provider '{provider}' is not active"),
            Some("payment_provider".to_string()),
        )),
        Err(error) => {
            warn!(error = %error, provider = %provider, "Failed to validate provider configuration");
            Err(IntegrityError::field(
                "UNKNOWN_PROVIDER_IDENTIFIER",
                format!("Provider '{provider}' could not be validated"),
                Some("payment_provider".to_string()),
            ))
        }
    }
}

async fn load_quote(quote_id: &str, state: &RequestIntegrityState) -> Result<StoredQuote, IntegrityError> {
    let cache = state.cache.as_ref().ok_or_else(|| {
        IntegrityError::field(
            "QUOTE_LOOKUP_UNAVAILABLE",
            "Quote validation cache is unavailable",
            Some("quote_id".to_string()),
        )
    })?;

    let cache_key = crate::cache::keys::onramp::QuoteKey::new(quote_id).to_string();
    let quote: Option<StoredQuote> = cache
        .get(&cache_key)
        .await
        .map_err(|_| IntegrityError::field("INVALID_QUOTE_ID", "quote_id could not be resolved", Some("quote_id".to_string())))?;

    quote.ok_or_else(|| {
        IntegrityError::field(
            "INVALID_QUOTE_ID",
            "quote_id does not exist",
            Some("quote_id".to_string()),
        )
    })
}

fn validate_quote_id_format(quote_id: &str) -> Result<(), IntegrityError> {
    let valid_uuid = Uuid::parse_str(quote_id).is_ok();
    let valid_prefixed_uuid = quote_id
        .strip_prefix("q_")
        .is_some_and(|raw| raw.len() == 32 && raw.chars().all(|c| c.is_ascii_hexdigit()));

    if valid_uuid || valid_prefixed_uuid {
        Ok(())
    } else {
        Err(IntegrityError::field(
            "INVALID_QUOTE_ID",
            "quote_id must be a UUID or q_<uuid> token",
            Some("quote_id".to_string()),
        ))
    }
}

fn validate_quote_is_active(quote_id: &str, quote: &StoredQuote) -> Result<(), IntegrityError> {
    if quote.status != "pending" {
        return Err(IntegrityError::field(
            "INVALID_QUOTE_ID",
            "quote_id has already been consumed",
            Some("quote_id".to_string()),
        ));
    }

    let expires_at = chrono::DateTime::parse_from_rfc3339(&quote.expires_at).map_err(|_| {
        IntegrityError::field(
            "INVALID_QUOTE_ID",
            "quote_id contains an invalid expiry timestamp",
            Some("quote_id".to_string()),
        )
    })?;
    if expires_at.with_timezone(&chrono::Utc) <= chrono::Utc::now() {
        return Err(IntegrityError::field(
            "EXPIRED_QUOTE_ID",
            format!("quote_id '{quote_id}' has expired"),
            Some("quote_id".to_string()),
        ));
    }
    Ok(())
}

fn validate_stellar_wallet(field: &str, wallet: &str) -> Result<(), IntegrityError> {
    if !is_valid_stellar_address(wallet) {
        return Err(IntegrityError::field(
            "INVALID_WALLET_ADDRESS",
            "Wallet address is not a valid Stellar public key",
            Some(field.to_string()),
        ));
    }

    let blacklist: HashSet<String> = std::env::var("INTEGRITY_BLACKLISTED_WALLETS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if blacklist.contains(wallet) {
        return Err(IntegrityError::field(
            "BLACKLISTED_WALLET_ADDRESS",
            "Wallet address is blocked",
            Some(field.to_string()),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum CurrencyKind {
    Ngn,
    Cngn,
}

fn validate_amount(
    amount: &str,
    currency: CurrencyKind,
    field: Option<String>,
) -> Result<Decimal, IntegrityError> {
    let parsed = Decimal::from_str(amount).map_err(|_| {
        IntegrityError::field(
            "INVALID_AMOUNT",
            "Amount must be a valid decimal string",
            field.clone(),
        )
    })?;
    if parsed <= Decimal::ZERO {
        return Err(IntegrityError::field(
            "INVALID_AMOUNT",
            "Amount must be greater than zero",
            field,
        ));
    }

    let (max_amount, scale_limit) = match currency {
        CurrencyKind::Ngn => (Decimal::from(50_000_000u64), 2u32),
        CurrencyKind::Cngn => (Decimal::from(50_000_000u64), 7u32),
    };

    if parsed > max_amount {
        return Err(IntegrityError::field(
            "AMOUNT_TOO_LARGE",
            format!("Amount exceeds the configured maximum of {max_amount}"),
            field,
        ));
    }
    if parsed.scale() > scale_limit {
        return Err(IntegrityError::field(
            "INVALID_AMOUNT_PRECISION",
            format!("Amount exceeds the allowed decimal precision of {scale_limit}"),
            field,
        ));
    }

    Ok(parsed)
}

fn required_string<'a>(payload: &'a Value, field: &str) -> Result<&'a str, IntegrityError> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| IntegrityError::field("INVALID_FIELD", format!("{field} must be a string"), Some(field.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_precision_is_enforced() {
        let err = validate_amount("12.123", CurrencyKind::Ngn, Some("amount".to_string())).unwrap_err();
        assert_eq!(err.code, "INVALID_AMOUNT_PRECISION");
    }

    #[test]
    fn quote_format_accepts_prefixed_uuid() {
        assert!(validate_quote_id_format("q_1234567890abcdef1234567890abcdef").is_ok());
    }
}
