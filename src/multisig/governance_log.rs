//! Tamper-evident governance log helper.
//!
//! Every governance event is appended with a SHA-256 hash that chains to the
//! previous entry, making retroactive tampering detectable.

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Compute the SHA-256 hash for a governance log entry.
///
/// The hash input is:
///   `previous_hash || proposal_id || event_type || actor_key || payload_json`
///
/// Using `||` to denote concatenation with a null-byte separator.
pub fn compute_entry_hash(
    previous_hash: Option<&str>,
    proposal_id: Option<Uuid>,
    event_type: &str,
    actor_key: Option<&str>,
    payload: &serde_json::Value,
) -> String {
    let mut hasher = Sha256::new();

    // Chain to previous entry
    hasher.update(previous_hash.unwrap_or("GENESIS").as_bytes());
    hasher.update(b"\x00");

    // Proposal context
    hasher.update(
        proposal_id
            .map(|id| id.to_string())
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update(b"\x00");

    // Event classification
    hasher.update(event_type.as_bytes());
    hasher.update(b"\x00");

    // Actor identity
    hasher.update(actor_key.unwrap_or("system").as_bytes());
    hasher.update(b"\x00");

    // Payload (deterministic JSON serialisation)
    hasher.update(payload.to_string().as_bytes());

    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_hash_is_deterministic() {
        let id = Uuid::new_v4();
        let payload = json!({"amount": "1000000"});
        let h1 = compute_entry_hash(None, Some(id), "proposal_created", Some("GABC"), &payload);
        let h2 = compute_entry_hash(None, Some(id), "proposal_created", Some("GABC"), &payload);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_changes_with_different_inputs() {
        let id = Uuid::new_v4();
        let payload = json!({"amount": "1000000"});
        let h1 = compute_entry_hash(None, Some(id), "proposal_created", Some("GABC"), &payload);
        let h2 = compute_entry_hash(
            Some(&h1),
            Some(id),
            "signature_added",
            Some("GDEF"),
            &payload,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_genesis_entry_has_no_previous() {
        let payload = json!({});
        let h = compute_entry_hash(None, None, "system_init", None, &payload);
        assert_eq!(h.len(), 64); // 32 bytes → 64 hex chars
    }
}
