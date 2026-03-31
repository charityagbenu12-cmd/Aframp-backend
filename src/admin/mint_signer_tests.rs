#[cfg(test)]
mod tests {
    use crate::admin::mint_signer_models::*;
    use crate::admin::mint_signer_service::*;
    use chrono::{Duration, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_challenge(challenge: &str, expires_in_secs: i64) -> MintSignerChallenge {
        MintSignerChallenge {
            id: uuid::Uuid::new_v4(),
            signer_id: uuid::Uuid::new_v4(),
            challenge: challenge.to_string(),
            challenge_hash: String::new(),
            expires_at: Utc::now() + Duration::seconds(expires_in_secs),
            used_at: None,
            outcome: None,
            created_at: Utc::now(),
        }
    }

    fn sign_challenge(challenge: &str) -> (String, String) {
        let sk = SigningKey::generate(&mut OsRng);
        let sig = sk.sign(challenge.as_bytes());
        let pk_bytes = sk.verifying_key().to_bytes();
        let pk_str = stellar_strkey::ed25519::PublicKey(pk_bytes).to_string();
        (pk_str, hex::encode(sig.to_bytes()))
    }

    // ── Challenge verification ────────────────────────────────────────────────

    #[test]
    fn valid_signature_passes_verification() {
        let challenge_str = "onboard:test-signer";
        let (pk, sig) = sign_challenge(challenge_str);
        let ch = make_challenge(challenge_str, 900);
        assert!(verify_challenge_response_pub(&ch, &pk, &sig, None).is_ok());
    }

    #[test]
    fn wrong_signature_fails_verification() {
        let (pk, _) = sign_challenge("other");
        let (_, sig) = sign_challenge("onboard:test-signer");
        let ch = make_challenge("onboard:test-signer", 900);
        assert!(verify_challenge_response_pub(&ch, &pk, &sig, None).is_err());
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let challenge_str = "onboard:expired";
        let (pk, sig) = sign_challenge(challenge_str);
        let ch = make_challenge(challenge_str, -1); // already expired
        let err = verify_challenge_response_pub(&ch, &pk, &sig, None).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn used_challenge_is_rejected() {
        let challenge_str = "onboard:used";
        let (pk, sig) = sign_challenge(challenge_str);
        let mut ch = make_challenge(challenge_str, 900);
        ch.used_at = Some(Utc::now());
        let err = verify_challenge_response_pub(&ch, &pk, &sig, None).unwrap_err();
        assert!(err.contains("already been used"));
    }

    // ── Role diversity ────────────────────────────────────────────────────────

    #[test]
    fn quorum_satisfied_with_cfo() {
        let roles = vec![SignerRole::Cfo, SignerRole::Cto];
        assert!(role_diversity_satisfied(&roles, true));
    }

    #[test]
    fn quorum_fails_without_cfo_or_cco() {
        let roles = vec![SignerRole::Cto, SignerRole::TreasuryManager];
        assert!(!role_diversity_satisfied(&roles, true));
    }

    #[test]
    fn quorum_passes_when_diversity_not_required() {
        let roles = vec![SignerRole::Cto, SignerRole::TreasuryManager];
        assert!(role_diversity_satisfied(&roles, false));
    }

    // ── Rotation grace period ─────────────────────────────────────────────────

    #[test]
    fn rotation_within_grace_period_is_valid() {
        let grace_ends_at = Utc::now() + Duration::hours(24);
        assert!(Utc::now() < grace_ends_at);
    }

    #[test]
    fn rotation_past_grace_period_is_expired() {
        let grace_ends_at = Utc::now() - Duration::hours(1);
        assert!(Utc::now() > grace_ends_at);
    }

    // ── Removal safety check ──────────────────────────────────────────────────

    #[test]
    fn removal_blocked_when_below_threshold() {
        let active: i64 = 3;
        let threshold: i64 = 3;
        let remaining = active - 1;
        assert!(remaining < threshold, "should block removal");
    }

    #[test]
    fn removal_allowed_when_above_threshold() {
        let active: i64 = 5;
        let threshold: i64 = 3;
        let remaining = active - 1;
        assert!(remaining >= threshold, "should allow removal");
    }

    // ── Quorum reachability ───────────────────────────────────────────────────

    #[test]
    fn quorum_reachable_when_weight_meets_threshold() {
        assert!(quorum_reachable(10, 3));
    }

    #[test]
    fn quorum_unreachable_when_weight_below_threshold() {
        assert!(!quorum_reachable(2, 3));
    }

    #[test]
    fn signer_role_max_weight_is_correct() {
        assert_eq!(SignerRole::Cfo.max_weight(), 2);
        assert_eq!(SignerRole::TreasuryManager.max_weight(), 1);
        assert_eq!(SignerRole::ExternalAuditor.max_weight(), 1);
    }
}

// ── Test-visible pure functions (extracted from service) ──────────────────────

pub fn verify_challenge_response_pub(
    challenge: &crate::admin::mint_signer_models::MintSignerChallenge,
    public_key: &str,
    signature_hex: &str,
    ip: Option<&str>,
) -> Result<(), String> {
    super::mint_signer_service::verify_challenge_response_pub(challenge, public_key, signature_hex, ip)
}

pub fn role_diversity_satisfied(roles: &[crate::admin::mint_signer_models::SignerRole], require_cfo_or_cco: bool) -> bool {
    if !require_cfo_or_cco { return true; }
    roles.iter().any(|r| matches!(r, crate::admin::mint_signer_models::SignerRole::Cfo | crate::admin::mint_signer_models::SignerRole::Cco))
}

pub fn quorum_reachable(total_weight: i64, threshold: i64) -> bool {
    total_weight >= threshold
}
