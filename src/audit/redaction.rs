/// Sensitive field catalogue — keys whose values must never appear in audit logs.
/// Any JSON key matching one of these names will have its value replaced with
/// the REDACTED placeholder before the entry is written.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "password_hash",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "private_key",
    "mfa_secret",
    "totp_secret",
    "fido2_credential",
    "card_number",
    "cvv",
    "pin",
    "ssn",
    "document_image",
    "selfie",
    "authorization",
    "x-api-key",
    "x-signature",
];

const REDACTED: &str = "[REDACTED]";

/// Recursively redact sensitive fields from a JSON value in-place.
pub fn redact(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if SENSITIVE_KEYS.iter().any(|s| k.to_lowercase().contains(s)) {
                    *v = serde_json::Value::String(REDACTED.to_string());
                } else {
                    redact(v);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact(v);
            }
        }
        _ => {}
    }
}

/// Compute SHA-256 of raw bytes and return hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Compute the hash chain entry hash.
/// hash = SHA-256( previous_hash || entry_content )
pub fn compute_entry_hash(previous_hash: &str, entry_content: &str) -> String {
    sha256_hex(format!("{}{}", previous_hash, entry_content).as_bytes())
}

/// Build the canonical string representation of a pending entry for hashing.
pub fn entry_content(entry: &crate::audit::models::PendingAuditEntry, id: uuid::Uuid, created_at: &chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        id,
        entry.event_type,
        entry.event_category.as_str(),
        entry.actor_id.as_deref().unwrap_or(""),
        entry.actor_ip.as_deref().unwrap_or(""),
        entry.session_id.as_deref().unwrap_or(""),
        entry.target_resource_type.as_deref().unwrap_or(""),
        entry.target_resource_id.as_deref().unwrap_or(""),
        entry.request_method,
        entry.request_path,
        entry.request_body_hash.as_deref().unwrap_or(""),
        entry.response_status,
        entry.response_latency_ms,
        entry.outcome as i32,
        entry.failure_reason.as_deref().unwrap_or(""),
        entry.environment,
        created_at.timestamp_millis(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_redact_sensitive_fields() {
        let mut v = json!({
            "email": "user@example.com",
            "password": "s3cr3t",
            "nested": { "token": "abc123", "name": "Alice" }
        });
        redact(&mut v);
        assert_eq!(v["password"], REDACTED);
        assert_eq!(v["nested"]["token"], REDACTED);
        assert_eq!(v["email"], "user@example.com");
        assert_eq!(v["nested"]["name"], "Alice");
    }

    #[test]
    fn test_sha256_hex_deterministic() {
        let h1 = sha256_hex(b"hello");
        let h2 = sha256_hex(b"hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_hash_chain_links() {
        let h0 = "0".repeat(64);
        let h1 = compute_entry_hash(&h0, "entry1");
        let h2 = compute_entry_hash(&h1, "entry2");
        assert_ne!(h1, h2);
        // Recomputing h2 from h1 must be deterministic
        assert_eq!(h2, compute_entry_hash(&h1, "entry2"));
    }
}
