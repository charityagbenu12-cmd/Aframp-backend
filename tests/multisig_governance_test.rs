//! Integration tests for the Multi-Sig Governance Framework.
//!
//! These tests exercise the pure-logic layers (XDR builders, governance log
//! hash chain, tier/threshold helpers) without requiring a live database or
//! Stellar Horizon connection.

#[cfg(feature = "database")]
mod tests {
    use Bitmesh_backend::multisig::{
        governance_log::compute_entry_hash,
        models::{MultiSigOpType, MultiSigProposalStatus},
        xdr_builder::{build_burn_xdr, build_mint_xdr, build_set_options_xdr, SetOptionsParams},
    };
    use serde_json::json;
    use uuid::Uuid;

    // ─────────────────────────────────────────────────────────────────────────
    // Known valid Stellar testnet addresses for unit tests
    // ─────────────────────────────────────────────────────────────────────────
    const ISSUER: &str = "GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX";
    const DEST: &str = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

    // ─────────────────────────────────────────────────────────────────────────
    // XDR builder tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_mint_xdr_is_valid_base64() {
        let xdr = build_mint_xdr(ISSUER, DEST, 10_000_000_000, 12345)
            .expect("mint XDR build should succeed");
        // base64 must be non-empty and decodable
        assert!(!xdr.is_empty());
        let decoded = base64::decode(&xdr);
        assert!(decoded.is_ok(), "mint XDR must be valid base64");
    }

    #[test]
    fn test_burn_xdr_is_valid_base64() {
        let xdr = build_burn_xdr(DEST, ISSUER, 5_000_000_000, 99)
            .expect("burn XDR build should succeed");
        assert!(!xdr.is_empty());
        let decoded = base64::decode(&xdr);
        assert!(decoded.is_ok(), "burn XDR must be valid base64");
    }

    #[test]
    fn test_set_options_add_signer_xdr() {
        let params = SetOptionsParams {
            master_weight: None,
            low_threshold: None,
            med_threshold: Some(3),
            high_threshold: Some(3),
            signer: Some((DEST.to_string(), 1)),
        };
        let xdr = build_set_options_xdr(ISSUER, 0, params)
            .expect("set_options XDR build should succeed");
        assert!(!xdr.is_empty());
    }

    #[test]
    fn test_set_options_remove_signer_xdr() {
        // weight = 0 removes the signer
        let params = SetOptionsParams {
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            signer: Some((DEST.to_string(), 0)),
        };
        let xdr = build_set_options_xdr(ISSUER, 5, params)
            .expect("remove signer XDR build should succeed");
        assert!(!xdr.is_empty());
    }

    #[test]
    fn test_set_options_change_thresholds_xdr() {
        let params = SetOptionsParams {
            master_weight: Some(0),
            low_threshold: Some(1),
            med_threshold: Some(3),
            high_threshold: Some(4),
            signer: None,
        };
        let xdr = build_set_options_xdr(ISSUER, 100, params)
            .expect("change threshold XDR build should succeed");
        assert!(!xdr.is_empty());
    }

    #[test]
    fn test_invalid_address_returns_error() {
        let result = build_mint_xdr("NOT_A_VALID_ADDRESS", DEST, 1_000_000, 0);
        assert!(result.is_err(), "invalid address must return an error");
    }

    #[test]
    fn test_mint_and_burn_produce_different_xdr() {
        let mint = build_mint_xdr(ISSUER, DEST, 1_000_000, 0).unwrap();
        let burn = build_burn_xdr(DEST, ISSUER, 1_000_000, 0).unwrap();
        assert_ne!(mint, burn, "mint and burn XDR must differ");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Governance log hash chain tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_governance_log_hash_is_deterministic() {
        let id = Uuid::new_v4();
        let payload = json!({"amount_stroops": "10000000000"});
        let h1 = compute_entry_hash(None, Some(id), "proposal_created", Some(ISSUER), &payload);
        let h2 = compute_entry_hash(None, Some(id), "proposal_created", Some(ISSUER), &payload);
        assert_eq!(h1, h2, "same inputs must produce same hash");
    }

    #[test]
    fn test_governance_log_hash_chain_links() {
        let id = Uuid::new_v4();
        let payload = json!({});

        let h1 = compute_entry_hash(None, Some(id), "proposal_created", Some(ISSUER), &payload);
        let h2 = compute_entry_hash(Some(&h1), Some(id), "signature_added", Some(DEST), &payload);
        let h3 = compute_entry_hash(Some(&h2), Some(id), "threshold_met", None, &payload);

        // Each hash must be unique
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);

        // Each hash must be 64 hex chars (SHA-256)
        assert_eq!(h1.len(), 64);
        assert_eq!(h2.len(), 64);
        assert_eq!(h3.len(), 64);
    }

    #[test]
    fn test_governance_log_hash_changes_with_different_actor() {
        let id = Uuid::new_v4();
        let payload = json!({});
        let h1 = compute_entry_hash(None, Some(id), "signature_added", Some(ISSUER), &payload);
        let h2 = compute_entry_hash(None, Some(id), "signature_added", Some(DEST), &payload);
        assert_ne!(h1, h2, "different actors must produce different hashes");
    }

    #[test]
    fn test_governance_log_genesis_entry() {
        let payload = json!({"init": true});
        let h = compute_entry_hash(None, None, "system_init", None, &payload);
        assert_eq!(h.len(), 64);
        // Must be valid hex
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Model / enum tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_op_type_requires_time_lock() {
        assert!(MultiSigOpType::AddSigner.requires_time_lock());
        assert!(MultiSigOpType::RemoveSigner.requires_time_lock());
        assert!(MultiSigOpType::ChangeThreshold.requires_time_lock());
        assert!(!MultiSigOpType::Mint.requires_time_lock());
        assert!(!MultiSigOpType::Burn.requires_time_lock());
        assert!(!MultiSigOpType::SetOptions.requires_time_lock());
    }

    #[test]
    fn test_proposal_status_terminal_states() {
        assert!(MultiSigProposalStatus::Confirmed.is_terminal());
        assert!(MultiSigProposalStatus::Rejected.is_terminal());
        assert!(MultiSigProposalStatus::Expired.is_terminal());
        assert!(!MultiSigProposalStatus::Pending.is_terminal());
        assert!(!MultiSigProposalStatus::TimeLocked.is_terminal());
        assert!(!MultiSigProposalStatus::Ready.is_terminal());
        assert!(!MultiSigProposalStatus::Submitted.is_terminal());
    }

    #[test]
    fn test_op_type_as_str() {
        assert_eq!(MultiSigOpType::Mint.as_str(), "mint");
        assert_eq!(MultiSigOpType::Burn.as_str(), "burn");
        assert_eq!(MultiSigOpType::SetOptions.as_str(), "set_options");
        assert_eq!(MultiSigOpType::AddSigner.as_str(), "add_signer");
        assert_eq!(MultiSigOpType::RemoveSigner.as_str(), "remove_signer");
        assert_eq!(MultiSigOpType::ChangeThreshold.as_str(), "change_threshold");
    }
}
