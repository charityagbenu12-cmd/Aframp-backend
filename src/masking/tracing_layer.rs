//! OpenTelemetry span attribute masking layer.
//! Masks sensitive span attributes before export using the same field registry.

use crate::masking::engine::{is_sensitive_field, strategy_for_field};

/// Mask sensitive attributes in a span attribute map (key-value pairs).
/// Returns the sanitised map.
pub fn mask_span_attributes(
    attrs: Vec<(String, String)>,
) -> Vec<(String, String)> {
    attrs
        .into_iter()
        .map(|(k, v)| {
            if is_sensitive_field(&k) {
                let strategy = strategy_for_field(&k);
                let masked = strategy.apply(&v);
                tracing::warn!(
                    attribute = %k,
                    "Sensitive span attribute masked before export"
                );
                crate::masking::metrics::record_masking_event(&k, "trace");
                (k, masked)
            } else {
                (k, v)
            }
        })
        .collect()
}

/// Mask a Prometheus metric label value if the label name is sensitive.
/// Returns the safe label value.
pub fn safe_metric_label(label_name: &str, label_value: &str) -> String {
    if is_sensitive_field(label_name) {
        crate::masking::metrics::record_masking_event(label_name, "metric_label");
        "[REDACTED]".to_string()
    } else {
        label_value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_span_attributes_sensitive() {
        let attrs = vec![
            ("user_id".to_string(), "usr_123".to_string()),
            ("token".to_string(), "eyJhbGci...".to_string()),
            ("amount".to_string(), "5000".to_string()),
        ];
        let masked = mask_span_attributes(attrs);
        let token_val = masked.iter().find(|(k, _)| k == "token").unwrap();
        assert_eq!(token_val.1, "[REDACTED]");
        let amount_val = masked.iter().find(|(k, _)| k == "amount").unwrap();
        assert_eq!(amount_val.1, "5000");
    }

    #[test]
    fn test_safe_metric_label_non_sensitive() {
        assert_eq!(safe_metric_label("route", "/api/v1/wallet"), "/api/v1/wallet");
    }

    #[test]
    fn test_safe_metric_label_sensitive() {
        assert_eq!(safe_metric_label("email", "user@example.com"), "[REDACTED]");
    }
}
