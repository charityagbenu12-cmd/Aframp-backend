use std::str::FromStr;

use redis::AsyncCommands;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use super::field_validation::ValidationContext;
use super::{parse_profile, IntegrityEndpoint, RequestIntegrityState};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConsumerProfile {
    pub request_count: u64,
    pub max_amount: String,
    pub last_currency: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAssessment {
    pub flagged: bool,
    pub field: Option<String>,
    pub flagged_value: Option<String>,
    pub deviation_magnitude: Option<String>,
    pub profile_summary: Option<String>,
}

pub async fn evaluate_anomaly(
    endpoint: IntegrityEndpoint,
    payload: &Value,
    consumer_id: &str,
    state: &RequestIntegrityState,
    ctx: &ValidationContext,
) -> Option<AnomalyAssessment> {
    let amount = extract_amount(endpoint, payload, ctx)?;
    let currency = extract_currency(endpoint);

    let Some(cache) = &state.cache else {
        return Some(AnomalyAssessment {
            flagged: false,
            field: None,
            flagged_value: None,
            deviation_magnitude: None,
            profile_summary: None,
        });
    };

    let profile_key = format!("request_integrity:profile:{consumer_id}:{}", endpoint.as_str());
    let mut conn = cache.get_connection().await.ok()?;
    let raw_profile: Option<String> = conn.get(&profile_key).await.ok();
    let mut profile = parse_profile(raw_profile).unwrap_or_default();

    let historical_max = Decimal::from_str(&profile.max_amount).unwrap_or(Decimal::ZERO);
    let flagged = profile.request_count >= 3 && historical_max > Decimal::ZERO && amount > historical_max * Decimal::from(10u32);

    if flagged {
        crate::metrics::security::request_anomaly_flags_total()
            .with_label_values(&[consumer_id, endpoint.as_str(), "amount"])
            .inc();
        warn!(
            consumer_id = %consumer_id,
            endpoint = endpoint.as_str(),
            field = "amount",
            flagged_value = %amount,
            historical_max = %historical_max,
            deviation = %(amount / historical_max),
            "Request anomaly flagged"
        );
    }

    if amount > historical_max {
        profile.max_amount = amount.to_string();
    } else if profile.max_amount.is_empty() {
        profile.max_amount = amount.to_string();
    }
    profile.request_count += 1;
    profile.last_currency = Some(currency.to_string());

    if let Ok(serialized) = serde_json::to_string(&profile) {
        let _: Result<(), _> = conn.set_ex(&profile_key, serialized, 60 * 60 * 24 * 30).await;
    }

    Some(AnomalyAssessment {
        flagged,
        field: flagged.then_some("amount".to_string()),
        flagged_value: flagged.then_some(amount.to_string()),
        deviation_magnitude: flagged.then(|| {
            if historical_max > Decimal::ZERO {
                (amount / historical_max).round_dp(2).to_string()
            } else {
                "n/a".to_string()
            }
        }),
        profile_summary: Some(format!(
            "request_count={}, historical_max_amount={}, last_currency={}",
            profile.request_count,
            if historical_max > Decimal::ZERO { historical_max.to_string() } else { "0".to_string() },
            currency
        )),
    })
}

fn extract_amount(
    endpoint: IntegrityEndpoint,
    _payload: &Value,
    ctx: &ValidationContext,
) -> Option<Decimal> {
    match endpoint {
        IntegrityEndpoint::OnrampInitiate | IntegrityEndpoint::OfframpInitiate => ctx.amount_snapshot,
        IntegrityEndpoint::BatchCngnTransfer | IntegrityEndpoint::BatchFiatPayout => ctx.batch_total,
    }
}

fn extract_currency(endpoint: IntegrityEndpoint) -> &'static str {
    match endpoint {
        IntegrityEndpoint::OnrampInitiate | IntegrityEndpoint::BatchFiatPayout => "NGN",
        IntegrityEndpoint::OfframpInitiate | IntegrityEndpoint::BatchCngnTransfer => "cNGN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::request_integrity::field_validation::ValidationContext;

    #[test]
    fn amount_extraction_uses_context() {
        let ctx = ValidationContext {
            batch_total: Some(Decimal::from(42u32)),
            ..Default::default()
        };

        assert_eq!(
            extract_amount(IntegrityEndpoint::BatchCngnTransfer, &Value::Null, &ctx),
            Some(Decimal::from(42u32))
        );
    }
}

