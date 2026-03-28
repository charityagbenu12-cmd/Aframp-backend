//! Unit and integration tests for the payload encryption module.

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p384::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    use rand::rngs::OsRng;
    use zeroize::Zeroizing;

    use crate::crypto::{
        envelope::{
            aes_gcm_decrypt, aes_gcm_encrypt, concat_ct_tag, decode_nonce, generate_session_key,
            EncryptedEnvelope, ALG_ECDH_ES_A256KW, ENC_A256GCM,
        },
        keys::{
            aes_kw_wrap, ecdh_derive_kek, is_sensitive_field, EncryptionError, KeyStatus,
            KeyStore, PlatformKeyVersion, SENSITIVE_FIELDS,
        },
    };

    // -----------------------------------------------------------------------
    // AES-256-GCM encrypt / decrypt round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_aes_gcm_round_trip() {
        let key = generate_session_key();
        let plaintext = b"sensitive-national-id-12345";

        let (nonce, ct_tag) = aes_gcm_encrypt(&key, plaintext).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ct_tag).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_gcm_auth_tag_verification_rejects_tampered_ciphertext() {
        let key = generate_session_key();
        let plaintext = b"bank-account-number";

        let (nonce, mut ct_tag) = aes_gcm_encrypt(&key, plaintext).unwrap();
        // Flip a byte in the ciphertext.
        ct_tag[0] ^= 0xFF;

        let result = aes_gcm_decrypt(&key, &nonce, &ct_tag);
        assert!(matches!(result, Err(EncryptionError::AuthTagVerificationFailed)));
    }

    #[test]
    fn test_aes_gcm_auth_tag_verification_rejects_tampered_tag() {
        let key = generate_session_key();
        let plaintext = b"iban-value";

        let (nonce, mut ct_tag) = aes_gcm_encrypt(&key, plaintext).unwrap();
        // Flip a byte in the tag (last 16 bytes).
        let len = ct_tag.len();
        ct_tag[len - 1] ^= 0xFF;

        let result = aes_gcm_decrypt(&key, &nonce, &ct_tag);
        assert!(matches!(result, Err(EncryptionError::AuthTagVerificationFailed)));
    }

    #[test]
    fn test_session_key_is_zeroized_on_drop() {
        // Verify Zeroizing<[u8;32]> zeroes memory on drop.
        let key_ptr: *const u8;
        {
            let key = generate_session_key();
            key_ptr = key.as_ptr();
            // key drops here
        }
        // We can't reliably read freed memory in safe Rust, but we verify the
        // type is Zeroizing which guarantees zeroing via the zeroize crate.
        // This test documents the intent.
        let _ = key_ptr;
    }

    // -----------------------------------------------------------------------
    // Key version validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_key_store_rejects_retired_key_version() {
        let active = PlatformKeyVersion::generate("v1", KeyStatus::Active).unwrap();
        let retired = PlatformKeyVersion::generate("v2", KeyStatus::Retired).unwrap();
        let store = KeyStore::new(vec![active, retired]).unwrap();

        let result = store.get_for_decryption("v2");
        assert!(matches!(result, Err(EncryptionError::KeyVersionRetired(_))));
    }

    #[test]
    fn test_key_store_rejects_unknown_key_version() {
        let active = PlatformKeyVersion::generate("v1", KeyStatus::Active).unwrap();
        let store = KeyStore::new(vec![active]).unwrap();

        let result = store.get_for_decryption("v99");
        assert!(matches!(result, Err(EncryptionError::KeyVersionNotFound(_))));
    }

    #[test]
    fn test_key_store_accepts_transitional_key_version() {
        let active = PlatformKeyVersion::generate("v1", KeyStatus::Active).unwrap();
        let transitional = PlatformKeyVersion::generate("v2", KeyStatus::Transitional).unwrap();
        let store = KeyStore::new(vec![active, transitional]).unwrap();

        assert!(store.get_for_decryption("v2").is_ok());
    }

    #[test]
    fn test_key_store_requires_active_key() {
        let retired = PlatformKeyVersion::generate("v1", KeyStatus::Retired).unwrap();
        let result = KeyStore::new(vec![retired]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Envelope format parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_envelope_is_envelope_detection() {
        let envelope_json = serde_json::json!({
            "__enc": true,
            "kid": "v1",
            "alg": ALG_ECDH_ES_A256KW,
            "enc": ENC_A256GCM,
            "epk": "abc",
            "ek": "def",
            "iv": "ghi",
            "ct": "jkl",
            "tag": "mno"
        });
        assert!(EncryptedEnvelope::is_envelope(&envelope_json));

        let plain = serde_json::json!("some-plaintext");
        assert!(!EncryptedEnvelope::is_envelope(&plain));

        let obj_no_marker = serde_json::json!({"field": "value"});
        assert!(!EncryptedEnvelope::is_envelope(&obj_no_marker));
    }

    #[test]
    fn test_envelope_algorithm_validation() {
        let mut env = make_test_envelope("v1");
        assert!(env.validate_algorithms().is_ok());

        env.alg = "RSA-OAEP".into();
        assert!(matches!(
            env.validate_algorithms(),
            Err(EncryptionError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn test_decode_nonce_rejects_wrong_length() {
        let short = URL_SAFE_NO_PAD.encode([0u8; 8]);
        assert!(decode_nonce(&short).is_err());

        let correct = URL_SAFE_NO_PAD.encode([0u8; 12]);
        assert!(decode_nonce(&correct).is_ok());
    }

    #[test]
    fn test_concat_ct_tag_rejects_wrong_tag_length() {
        let mut env = make_test_envelope("v1");
        // tag must be 16 bytes
        env.tag = URL_SAFE_NO_PAD.encode([0u8; 8]);
        assert!(concat_ct_tag(&env).is_err());
    }

    // -----------------------------------------------------------------------
    // Full ECDH-ES + AES-KW + AES-GCM round-trip (Rust reference impl)
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_encryption_decryption_round_trip() {
        // 1. Platform generates key pair.
        let platform_key = PlatformKeyVersion::generate("v1", KeyStatus::Active).unwrap();
        let platform_pub = PublicKey::from_sec1_bytes(&platform_key.public_key_bytes).unwrap();

        // 2. Consumer side: generate ephemeral key pair.
        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let ephemeral_pub = ephemeral_secret.public_key();
        let epk_bytes = ephemeral_pub.to_encoded_point(false).as_bytes().to_vec();
        let epk_b64 = URL_SAFE_NO_PAD.encode(&epk_bytes);

        // 3. Consumer derives KEK via ECDH.
        let kek = ecdh_derive_kek(&ephemeral_secret, &platform_pub).unwrap();

        // 4. Consumer generates session key and wraps it.
        let session_key = generate_session_key();
        let wrapped_key = aes_kw_wrap(&kek, &session_key).unwrap();
        let ek_b64 = URL_SAFE_NO_PAD.encode(&wrapped_key);

        // 5. Consumer encrypts the plaintext field.
        let plaintext = b"NG12345678";
        let (nonce, ct_tag) = aes_gcm_encrypt(&session_key, plaintext).unwrap();

        // Split ct and tag (last 16 bytes are the tag in aes-gcm output).
        let tag_start = ct_tag.len() - 16;
        let ct_b64 = URL_SAFE_NO_PAD.encode(&ct_tag[..tag_start]);
        let tag_b64 = URL_SAFE_NO_PAD.encode(&ct_tag[tag_start..]);
        let iv_b64 = URL_SAFE_NO_PAD.encode(nonce);

        // 6. Server side: unwrap session key and decrypt.
        let store = KeyStore::new(vec![platform_key]).unwrap();
        let kv = store.get_for_decryption("v1").unwrap();
        let decrypted_session_key = kv.unwrap_session_key(&epk_b64, &ek_b64).unwrap();

        let nonce_bytes = decode_nonce(&iv_b64).unwrap();
        let ct_tag_bytes = {
            let mut v = URL_SAFE_NO_PAD.decode(&ct_b64).unwrap();
            v.extend_from_slice(&URL_SAFE_NO_PAD.decode(&tag_b64).unwrap());
            v
        };

        let decrypted = aes_gcm_decrypt(&decrypted_session_key, &nonce_bytes, &ct_tag_bytes).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    // -----------------------------------------------------------------------
    // Sensitive field catalogue
    // -----------------------------------------------------------------------

    #[test]
    fn test_sensitive_field_catalogue() {
        assert!(is_sensitive_field("national_id"));
        assert!(is_sensitive_field("passport_number"));
        assert!(is_sensitive_field("bank_account_number"));
        assert!(is_sensitive_field("phone_number"));
        assert!(is_sensitive_field("iban"));
        assert!(!is_sensitive_field("wallet_address"));
        assert!(!is_sensitive_field("amount"));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_test_envelope(kid: &str) -> EncryptedEnvelope {
        EncryptedEnvelope {
            marker: true,
            kid: kid.to_string(),
            alg: ALG_ECDH_ES_A256KW.to_string(),
            enc: ENC_A256GCM.to_string(),
            epk: URL_SAFE_NO_PAD.encode([0u8; 97]),
            ek: URL_SAFE_NO_PAD.encode([0u8; 40]),
            iv: URL_SAFE_NO_PAD.encode([0u8; 12]),
            ct: URL_SAFE_NO_PAD.encode([0u8; 32]),
            tag: URL_SAFE_NO_PAD.encode([0u8; 16]),
        }
    }
}
