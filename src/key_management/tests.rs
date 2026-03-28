//! Unit tests for the key management framework.

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use crate::key_management::{
        catalogue::{KeyStatus, KeyType},
        escrow::{reconstruct, split, EscrowError},
        rotation::{days_until_rotation, is_in_grace_period, DEFAULT_GRACE_PERIOD_DAYS, JWT_GRACE_PERIOD_DAYS},
    };

    // -----------------------------------------------------------------------
    // Rotation schedule calculation
    // -----------------------------------------------------------------------

    #[test]
    fn test_rotation_days_per_key_type() {
        assert_eq!(KeyType::JwtSigning.rotation_days(), 90);
        assert_eq!(KeyType::PayloadEncryption.rotation_days(), 180);
        assert_eq!(KeyType::DbFieldEncryption.rotation_days(), 365);
        assert_eq!(KeyType::HmacDerivation.rotation_days(), 90);
        assert_eq!(KeyType::BackupEncryption.rotation_days(), 365);
    }

    #[test]
    fn test_days_until_rotation_future() {
        let next = Utc::now() + Duration::days(30);
        let days = days_until_rotation(Some(next)).unwrap();
        assert!(days >= 29 && days <= 30);
    }

    #[test]
    fn test_days_until_rotation_overdue() {
        let past = Utc::now() - Duration::days(5);
        let days = days_until_rotation(Some(past)).unwrap();
        assert!(days < 0);
    }

    #[test]
    fn test_days_until_rotation_none() {
        assert!(days_until_rotation(None).is_none());
    }

    // -----------------------------------------------------------------------
    // Grace period enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_in_grace_period_active() {
        let grace_end = Utc::now() + Duration::days(3);
        assert!(is_in_grace_period("transitional", Some(grace_end)));
    }

    #[test]
    fn test_is_in_grace_period_expired() {
        let grace_end = Utc::now() - Duration::hours(1);
        assert!(!is_in_grace_period("transitional", Some(grace_end)));
    }

    #[test]
    fn test_is_in_grace_period_wrong_status() {
        let grace_end = Utc::now() + Duration::days(3);
        assert!(!is_in_grace_period("active", Some(grace_end)));
        assert!(!is_in_grace_period("retired", Some(grace_end)));
    }

    #[test]
    fn test_jwt_grace_period_shorter_than_default() {
        assert!(JWT_GRACE_PERIOD_DAYS < DEFAULT_GRACE_PERIOD_DAYS);
    }

    // -----------------------------------------------------------------------
    // Key status transitions
    // -----------------------------------------------------------------------

    #[test]
    fn test_key_status_as_str() {
        assert_eq!(KeyStatus::Active.as_str(), "active");
        assert_eq!(KeyStatus::Transitional.as_str(), "transitional");
        assert_eq!(KeyStatus::Retired.as_str(), "retired");
        assert_eq!(KeyStatus::Destroyed.as_str(), "destroyed");
        assert_eq!(KeyStatus::Pending.as_str(), "pending");
    }

    // -----------------------------------------------------------------------
    // Shamir's Secret Sharing
    // -----------------------------------------------------------------------

    #[test]
    fn test_shamir_split_and_reconstruct_3_of_5() {
        let secret = b"aes-256-key-material-32-bytes!!";
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Any 3 shares reconstruct correctly
        let r = reconstruct(&shares[..3], 3).unwrap();
        assert_eq!(r.as_slice(), secret);
    }

    #[test]
    fn test_shamir_reconstruct_different_subsets() {
        let secret = b"consistent-secret-value-here!!!";
        let shares = split(secret, 3, 5).unwrap();

        let r1 = reconstruct(&[shares[0].clone(), shares[2].clone(), shares[4].clone()], 3).unwrap();
        let r2 = reconstruct(&[shares[1].clone(), shares[3].clone(), shares[4].clone()], 3).unwrap();
        assert_eq!(r1.as_slice(), secret);
        assert_eq!(r2.as_slice(), secret);
    }

    #[test]
    fn test_shamir_insufficient_shares_fails() {
        let secret = b"secret";
        let shares = split(secret, 3, 5).unwrap();
        let result = reconstruct(&shares[..2], 3);
        assert!(matches!(result, Err(EscrowError::InsufficientShares { needed: 3, got: 2 })));
    }

    #[test]
    fn test_shamir_invalid_threshold_fails() {
        assert!(matches!(
            split(b"secret", 6, 5),
            Err(EscrowError::InvalidThreshold { threshold: 6, total: 5 })
        ));
    }

    #[test]
    fn test_shamir_2_of_2() {
        let secret = b"minimal-threshold";
        let shares = split(secret, 2, 2).unwrap();
        let r = reconstruct(&shares, 2).unwrap();
        assert_eq!(r.as_slice(), secret);
    }

    #[test]
    fn test_shamir_1_of_1() {
        let secret = b"trivial";
        let shares = split(secret, 1, 1).unwrap();
        let r = reconstruct(&shares, 1).unwrap();
        assert_eq!(r.as_slice(), secret);
    }

    #[test]
    fn test_shamir_empty_secret_fails() {
        assert!(matches!(split(b"", 2, 3), Err(EscrowError::EmptySecret)));
    }

    // -----------------------------------------------------------------------
    // Re-encryption batch logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_size_does_not_exceed_remaining() {
        use crate::key_management::reencryption::BATCH_SIZE;
        let total = 100i64;
        let processed = 90i64;
        let remaining = total - processed;
        let batch = remaining.min(BATCH_SIZE);
        assert_eq!(batch, 10); // only 10 left, not full batch
    }

    #[test]
    fn test_full_batch_when_many_remaining() {
        use crate::key_management::reencryption::BATCH_SIZE;
        let total = 10_000i64;
        let processed = 0i64;
        let remaining = total - processed;
        let batch = remaining.min(BATCH_SIZE);
        assert_eq!(batch, BATCH_SIZE);
    }
}
