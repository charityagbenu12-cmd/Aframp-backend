use serde_json::Value;

use super::errors::IntegrityError;
use super::IntegrityEndpoint;

const MAX_SMALL_BODY_BYTES: usize = 8 * 1024;
const MAX_BATCH_BODY_BYTES: usize = 64 * 1024;
const MAX_STANDARD_STRING: usize = 255;
const MAX_URL_STRING: usize = 1024;
const MAX_MEMO_STRING: usize = 128;

pub fn endpoint_max_body_size(endpoint: IntegrityEndpoint) -> usize {
    match endpoint {
        IntegrityEndpoint::OnrampInitiate | IntegrityEndpoint::OfframpInitiate => MAX_SMALL_BODY_BYTES,
        IntegrityEndpoint::BatchCngnTransfer | IntegrityEndpoint::BatchFiatPayout => MAX_BATCH_BODY_BYTES,
    }
}

pub fn validate_structure(
    endpoint: IntegrityEndpoint,
    payload: &Value,
    body_len: usize,
) -> Result<(), IntegrityError> {
    if body_len > endpoint_max_body_size(endpoint) {
        return Err(IntegrityError::payload_too_large(
            endpoint,
            endpoint_max_body_size(endpoint),
            format!("Observed body size {body_len} bytes"),
        ));
    }

    match endpoint {
        IntegrityEndpoint::OnrampInitiate => validate_onramp_initiate(payload),
        IntegrityEndpoint::OfframpInitiate => validate_offramp_initiate(payload),
        IntegrityEndpoint::BatchCngnTransfer => validate_batch_cngn(payload),
        IntegrityEndpoint::BatchFiatPayout => validate_batch_fiat(payload),
    }
}

fn validate_onramp_initiate(payload: &Value) -> Result<(), IntegrityError> {
    let obj = expect_object(payload, "request")?;
    reject_unknown_fields(
        obj,
        &[
            "quote_id",
            "wallet_address",
            "payment_provider",
            "customer_email",
            "customer_phone",
            "callback_url",
            "idempotency_key",
        ],
    )?;

    required_string(obj, "quote_id", MAX_STANDARD_STRING)?;
    required_string(obj, "wallet_address", 56)?;
    required_string(obj, "payment_provider", 64)?;
    optional_string(obj, "customer_email", MAX_STANDARD_STRING)?;
    optional_string(obj, "customer_phone", 32)?;
    optional_string(obj, "callback_url", MAX_URL_STRING)?;
    optional_string(obj, "idempotency_key", MAX_STANDARD_STRING)?;
    Ok(())
}

fn validate_offramp_initiate(payload: &Value) -> Result<(), IntegrityError> {
    let obj = expect_object(payload, "request")?;
    reject_unknown_fields(obj, &["quote_id", "wallet_address", "bank_details"])?;
    required_string(obj, "quote_id", MAX_STANDARD_STRING)?;
    required_string(obj, "wallet_address", 56)?;
    let bank_details = obj
        .get("bank_details")
        .ok_or_else(|| IntegrityError::structural("MISSING_REQUIRED_FIELD", "Field 'bank_details' is required", Some("bank_details".to_string())))?;
    let bank_obj = expect_object(bank_details, "bank_details")?;
    reject_unknown_fields(bank_obj, &["bank_code", "account_number", "account_name"])?;
    required_string(bank_obj, "bank_code", 8)?;
    required_string(bank_obj, "account_number", 32)?;
    required_string(bank_obj, "account_name", 200)?;
    Ok(())
}

fn validate_batch_cngn(payload: &Value) -> Result<(), IntegrityError> {
    let obj = expect_object(payload, "request")?;
    reject_unknown_fields(obj, &["source_wallet", "transfers"])?;
    required_string(obj, "source_wallet", 56)?;
    let transfers = obj
        .get("transfers")
        .ok_or_else(|| IntegrityError::structural("MISSING_REQUIRED_FIELD", "Field 'transfers' is required", Some("transfers".to_string())))?;
    let items = expect_array(transfers, "transfers")?;
    for (index, item) in items.iter().enumerate() {
        let item_obj = expect_object(item, &format!("transfers[{index}]"))?;
        reject_unknown_fields(item_obj, &["destination_wallet", "amount_cngn", "memo"])?;
        required_string(item_obj, "destination_wallet", 56)?;
        required_string(item_obj, "amount_cngn", 64)?;
        optional_string(item_obj, "memo", MAX_MEMO_STRING)?;
    }
    Ok(())
}

fn validate_batch_fiat(payload: &Value) -> Result<(), IntegrityError> {
    let obj = expect_object(payload, "request")?;
    reject_unknown_fields(obj, &["payouts"])?;
    let payouts = obj
        .get("payouts")
        .ok_or_else(|| IntegrityError::structural("MISSING_REQUIRED_FIELD", "Field 'payouts' is required", Some("payouts".to_string())))?;
    let items = expect_array(payouts, "payouts")?;
    for (index, item) in items.iter().enumerate() {
        let item_obj = expect_object(item, &format!("payouts[{index}]"))?;
        reject_unknown_fields(item_obj, &["bank_account_number", "bank_code", "amount_ngn", "reference"])?;
        required_string(item_obj, "bank_account_number", 32)?;
        required_string(item_obj, "bank_code", 8)?;
        required_string(item_obj, "amount_ngn", 64)?;
        optional_string(item_obj, "reference", MAX_STANDARD_STRING)?;
    }
    Ok(())
}

fn reject_unknown_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), IntegrityError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(IntegrityError::structural(
                "UNEXPECTED_FIELD",
                format!("Field '{key}' is not allowed"),
                Some(key.clone()),
            ));
        }
    }
    Ok(())
}

fn required_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
    max_len: usize,
) -> Result<(), IntegrityError> {
    let value = object.get(field).ok_or_else(|| {
        IntegrityError::structural(
            "MISSING_REQUIRED_FIELD",
            format!("Field '{field}' is required"),
            Some(field.to_string()),
        )
    })?;
    match value {
        Value::String(text) => {
            if text.len() > max_len {
                Err(IntegrityError::structural(
                    "FIELD_TOO_LONG",
                    format!("Field '{field}' exceeds the maximum length of {max_len}"),
                    Some(field.to_string()),
                ))
            } else {
                Ok(())
            }
        }
        _ => Err(IntegrityError::structural(
            "INVALID_FIELD_TYPE",
            format!("Field '{field}' must be a string"),
            Some(field.to_string()),
        )),
    }
}

fn optional_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
    max_len: usize,
) -> Result<(), IntegrityError> {
    if let Some(value) = object.get(field) {
        match value {
            Value::Null => Ok(()),
            Value::String(text) => {
                if text.len() > max_len {
                    Err(IntegrityError::structural(
                        "FIELD_TOO_LONG",
                        format!("Field '{field}' exceeds the maximum length of {max_len}"),
                        Some(field.to_string()),
                    ))
                } else {
                    Ok(())
                }
            }
            _ => Err(IntegrityError::structural(
                "INVALID_FIELD_TYPE",
                format!("Field '{field}' must be a string"),
                Some(field.to_string()),
            )),
        }
    } else {
        Ok(())
    }
}

fn expect_object<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a serde_json::Map<String, Value>, IntegrityError> {
    value.as_object().ok_or_else(|| {
        IntegrityError::structural(
            "INVALID_FIELD_TYPE",
            format!("Field '{field}' must be an object"),
            Some(field.to_string()),
        )
    })
}

fn expect_array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, IntegrityError> {
    value.as_array().ok_or_else(|| {
        IntegrityError::structural(
            "INVALID_FIELD_TYPE",
            format!("Field '{field}' must be an array"),
            Some(field.to_string()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_unknown_field() {
        let payload = json!({
            "quote_id": "q_123",
            "wallet_address": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "payment_provider": "paystack",
            "extra": "boom"
        });

        let error = validate_structure(IntegrityEndpoint::OnrampInitiate, &payload, 32).unwrap_err();
        assert_eq!(error.code, "UNEXPECTED_FIELD");
    }

    #[test]
    fn rejects_missing_required_field() {
        let payload = json!({
            "wallet_address": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "payment_provider": "paystack"
        });

        let error = validate_structure(IntegrityEndpoint::OnrampInitiate, &payload, 32).unwrap_err();
        assert_eq!(error.code, "MISSING_REQUIRED_FIELD");
        assert_eq!(error.field.as_deref(), Some("quote_id"));
    }
}

