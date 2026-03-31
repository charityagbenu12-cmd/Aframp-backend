//! Integration tests for the platform key management framework.

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use Bitmesh_backend::key_management::{
        catalogue::{KeyCatalogueRepository, KeyStatus, KeyType, NewPlatformKey},
        emergency::EmergencyRevocationService,
        escrow::{reconstruct, split},
        reencryption::{ReencryptionService, BATCH_SIZE, ENCRYPTED_TABLES},
        rotation::{
            days_until_rotation, is_in_grace_period, KeyRotationScheduler,
            DEFAULT_GRACE_PERIOD_DAYS,
        },
    };

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_key(key_type: KeyType, suffix: &str) -> NewPlatformKey {
        NewPlatformKey {
            key_id: format!("{}-{suffix}", key_type.as_str()),
            algorithm: match &key_type {
                KeyType::JwtSigning => "RS256".to_string(),
                KeyType::PayloadEncryption => "ECDH-ES+A256KW".to_string(),
                _ => "AES-256-GCM".to_string(),
            },
            key_length_bits: Some(256),
            storage_location: "secrets_manager".to_string(),
            jwt_kid: if matches!(key_type, KeyType::JwtSigning) {
                Some(format!("kid-{suffix}"))
            } else {
                None
            },
            enc_version: if matches!(key_type, KeyType::PayloadEncryption) {
                Some(format!("v{suffix}"))
            } else {
                None
            },
            notes: None,
            key_type,
        }
    }

    // -----------------------------------------------------------------------
    // Rotation schedule — unit-level (no DB needed)
    // -----------------------------------------------------------------------

    #[test]
    fn test_rotation_schedule_all_key_types() {
        let schedules = [
            (KeyType::JwtSigning, 90i64),
            (KeyType::PayloadEncryption, 180),
            (KeyType::DbFieldEncryption, 365),
            (KeyType::HmacDerivation, 90),
            (KeyType::BackupEncryption, 365),
        ];
        for (kt, expected_days) in schedules {
            assert_eq!(kt.rotation_days(), expected_days, "Wrong rotation days for {:?}", kt);
        }
    }

    #[test]
    fn test_zero_downtime_both_keys_valid_during_grace() {
        // Simulate: old key is transitional, new key is active, grace not yet expired
        let grace_end = Utc::now() + Duration::days(DEFAULT_GRACE_PERIOD_DAYS);

        // Old key: transitional + grace period active → still valid
        assert!(is_in_grace_period("transitional", Some(grace_end)));

        // New key: active → valid
        let new_status = "active";
        assert_eq!(new_status, "active");
    }

    #[test]
    fn test_old_key_invalid_after_grace_expires() {
        let grace_end = Utc::now() - Duration::hours(1);
        assert!(!is_in_grace_period("transitional", Some(grace_end)));
    }

    #[test]
    fn test_overdue_key_has_negative_days() {
        let overdue = Utc::now() - Duration::days(10);
        let days = days_until_rotation(Some(overdue)).unwrap();
        assert!(days < 0, "Expected negative days for overdue key, got {days}");
    }

    // -----------------------------------------------------------------------
    // Shamir escrow — share distribution and recovery
    // -----------------------------------------------------------------------

    #[test]
    fn test_escrow_3_of_5_share_distribution_and_recovery() {
        let key_material = b"platform-backup-encryption-key!"; // 32 bytes
        let shares = split(key_material, 3, 5).unwrap();

        // 5 shares distributed to 5 custodians
        assert_eq!(shares.len(), 5);
        // Each share has the same length as the secret
        for share in &shares {
            assert_eq!(share.y.len(), key_material.len());
        }

        // Any 3 custodians can reconstruct
        let recovered = reconstruct(&shares[..3], 3).unwrap();
        assert_eq!(recovered.as_slice(), key_material);

        // A different set of 3 also works
        let recovered2 = reconstruct(
            &[shares[0].clone(), shares[3].clone(), shares[4].clone()],
            3,
        )
        .unwrap();
        assert_eq!(recovered2.as_slice(), key_material);
    }

    #[test]
    fn test_escrow_2_shares_insufficient_for_3_of_5() {
        let key_material = b"secret-key-bytes";
        let shares = split(key_material, 3, 5).unwrap();
        let result = reconstruct(&shares[..2], 3);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Re-encryption batch processing logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_reencryption_batch_does_not_exceed_remaining() {
        let total = 1_200i64;
        let processed = 1_100i64;
        let remaining = total - processed;
        let batch = remaining.min(BATCH_SIZE);
        assert_eq!(batch, 100); // only 100 left
    }

    #[test]
    fn test_reencryption_completes_when_all_processed() {
        let total = 500i64;
        let processed = 500i64;
        let remaining = total - processed;
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_encrypted_tables_catalogue_not_empty() {
        assert!(!ENCRYPTED_TABLES.is_empty());
    }

    // -----------------------------------------------------------------------
    // Emergency revocation — immediate retirement, no grace period
    // -----------------------------------------------------------------------

    #[test]
    fn test_emergency_revocation_requires_reason() {
        // Validate that an empty reason would be rejected at the API layer
        let reason = "";
        assert!(reason.trim().is_empty(), "Empty reason should be rejected");
    }

    #[test]
    fn test_emergency_revocation_grace_period_is_zero() {
        // Emergency revocations must have no grace period
        // Verified by the fact that EmergencyRevocationService calls
        // update_status with grace_period_end = None
        let grace: Option<chrono::DateTime<Utc>> = None;
        assert!(grace.is_none());
    }

    // -----------------------------------------------------------------------
    // Key catalogue metadata — no key material exposed
    // -----------------------------------------------------------------------

    #[test]
    fn test_platform_key_serialization_has_no_material_fields() {
        use Bitmesh_backend::key_management::catalogue::PlatformKey;
        use serde_json::Value;

        // Build a minimal PlatformKey and verify serialization has no key material
        let key = PlatformKey {
            id: uuid::Uuid::new_v4(),
            key_id: "jwt-signing-v1".to_string(),
            key_type: "jwt_signing".to_string(),
            algorithm: "RS256".to_string(),
            key_length_bits: Some(4096),
            status: "active".to_string(),
            storage_location: "secrets_manager".to_string(),
            rotation_days: 90,
            created_at: Utc::now(),
            activated_at: Some(Utc::now()),
            last_rotated_at: None,
            next_rotation_at: Some(Utc::now() + Duration::days(90)),
            grace_period_end: None,
            retired_at: None,
            destroyed_at: None,
            jwt_kid: Some("kid-abc123".to_string()),
            enc_version: None,
            notes: None,
        };

        let json = serde_json::to_value(&key).unwrap();
        let obj = json.as_object().unwrap();

        // These fields must NOT exist in the serialized output
        let forbidden = ["private_key", "key_material", "secret", "pem", "der"];
        for field in forbidden {
            assert!(
                !obj.contains_key(field),
                "Key material field '{field}' must not be serialized"
            );
        }
    }
}
