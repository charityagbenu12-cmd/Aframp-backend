//! Integration tests for the Stellar issuer account infrastructure.
//!
//! These tests run against Stellar testnet. They require the following env vars:
//!   STELLAR_NETWORK=testnet
//!   STELLAR_HORIZON_URL=https://horizon-testnet.stellar.org  (optional override)
//!
//! Tests that require funded accounts are skipped when the accounts are not funded.

use Bitmesh_backend::chains::stellar::{
    client::StellarClient,
    config::{StellarConfig, StellarNetwork},
    issuer::{
        fee_monitor::is_below_alert_threshold,
        setup::{build_issuer_setup_transaction, build_trustline_transaction, generate_keypair},
        stellar_toml::{generate_stellar_toml, validate_stellar_toml},
        types::{IssuerConfig, MultiSigConfig, SignerEntry, StellarEnvironment, VerificationReport},
        verification::assert_issuer_configured,
    },
};

fn testnet_client() -> StellarClient {
    let config = StellarConfig {
        network: StellarNetwork::Testnet,
        ..Default::default()
    };
    StellarClient::new(config).expect("testnet client")
}

// ---------------------------------------------------------------------------
// Keypair generation
// ---------------------------------------------------------------------------

#[test]
fn test_generate_keypair_valid_stellar_address() {
    let kp = generate_keypair().expect("keypair generation");
    assert!(kp.public_key.starts_with('G'));
    assert_eq!(kp.public_key.len(), 56);
    assert!(kp.secret_key_strkey.starts_with('S'));
    assert_eq!(kp.secret_key_bytes.len(), 32);
}

#[test]
fn test_generate_keypair_entropy_unique() {
    let kp1 = generate_keypair().unwrap();
    let kp2 = generate_keypair().unwrap();
    assert_ne!(kp1.public_key, kp2.public_key);
    assert_ne!(kp1.secret_key_bytes, kp2.secret_key_bytes);
}

// ---------------------------------------------------------------------------
// Multi-signature threshold calculation
// ---------------------------------------------------------------------------

#[test]
fn test_threshold_3_of_5_satisfied() {
    use Bitmesh_backend::chains::stellar::issuer::types::threshold_satisfied;
    // 5 signers with weight 1 each, threshold 3
    assert!(threshold_satisfied(&[1, 1, 1, 1, 1], 3));
    assert!(threshold_satisfied(&[1, 1, 1], 3));
    assert!(!threshold_satisfied(&[1, 1], 3));
}

#[test]
fn test_threshold_weighted_signers() {
    use Bitmesh_backend::chains::stellar::issuer::types::threshold_satisfied;
    // 2 signers with weight 2 each satisfy threshold 3
    assert!(threshold_satisfied(&[2, 2], 3));
    assert!(!threshold_satisfied(&[1, 1], 3));
}

// ---------------------------------------------------------------------------
// Account flag verification
// ---------------------------------------------------------------------------

#[test]
fn test_required_flags_all_set() {
    use Bitmesh_backend::chains::stellar::issuer::types::RequiredFlags;
    let flags = RequiredFlags {
        auth_required: true,
        auth_revocable: true,
        auth_clawback_enabled: true,
    };
    assert!(flags.all_set());
}

#[test]
fn test_required_flags_partial_fails() {
    use Bitmesh_backend::chains::stellar::issuer::types::RequiredFlags;
    let flags = RequiredFlags {
        auth_required: true,
        auth_revocable: false,
        auth_clawback_enabled: true,
    };
    assert!(!flags.all_set());
}

// ---------------------------------------------------------------------------
// stellar.toml generation and validation
// ---------------------------------------------------------------------------

#[test]
fn test_stellar_toml_generation_and_validation() {
    let kp = generate_keypair().unwrap();
    let config = IssuerConfig {
        environment: StellarEnvironment::Testnet,
        issuer_account_id: kp.public_key.clone(),
        home_domain: "example.com".to_string(),
        asset_code: "cNGN".to_string(),
        decimal_precision: 7,
        min_issuance_amount: "1".parse().unwrap(),
        max_issuance_amount: "1000000".parse().unwrap(),
        multisig: MultiSigConfig {
            master_weight: 0,
            low_threshold: 3,
            med_threshold: 3,
            high_threshold: 3,
            required_signers: 3,
            signers: vec![],
        },
    };

    let toml = generate_stellar_toml(
        &config,
        "Aframp",
        "https://example.com",
        "https://example.com/reserves",
        "https://example.com/attestation",
    );

    assert!(validate_stellar_toml(&toml, &kp.public_key).is_ok());
    assert!(toml.contains("Test SDF Network"));
    assert!(toml.contains("cNGN"));
    assert!(toml.contains(&kp.public_key));
}

#[test]
fn test_stellar_toml_validation_rejects_missing_issuer() {
    let toml = "VERSION = \"2.0.0\"\nNETWORK_PASSPHRASE = \"test\"\n[[CURRENCIES]]\nis_asset_anchored = true";
    let result = validate_stellar_toml(toml, "GXXX_MISSING");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Fee account balance threshold evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_fee_balance_below_threshold() {
    assert!(is_below_alert_threshold(30.0, 50.0));
    assert!(!is_below_alert_threshold(60.0, 50.0));
    assert!(!is_below_alert_threshold(50.0, 50.0));
}

// ---------------------------------------------------------------------------
// Unsigned transaction building
// ---------------------------------------------------------------------------

#[test]
fn test_build_issuer_setup_transaction_produces_valid_xdr() {
    let issuer_kp = generate_keypair().unwrap();
    let signer1 = generate_keypair().unwrap();
    let signer2 = generate_keypair().unwrap();
    let signer3 = generate_keypair().unwrap();

    let multisig = MultiSigConfig {
        master_weight: 0,
        low_threshold: 3,
        med_threshold: 3,
        high_threshold: 3,
        required_signers: 3,
        signers: vec![
            SignerEntry {
                public_key: signer1.public_key,
                weight: 1,
                identity: "ops-key-1".to_string(),
                secrets_ref: "secrets/issuer/signer-1".to_string(),
            },
            SignerEntry {
                public_key: signer2.public_key,
                weight: 1,
                identity: "ops-key-2".to_string(),
                secrets_ref: "secrets/issuer/signer-2".to_string(),
            },
            SignerEntry {
                public_key: signer3.public_key,
                weight: 1,
                identity: "ops-key-3".to_string(),
                secrets_ref: "secrets/issuer/signer-3".to_string(),
            },
        ],
    };

    let result = build_issuer_setup_transaction(
        &issuer_kp.public_key,
        100,
        "example.com",
        &multisig,
    );

    assert!(result.is_ok());
    let unsigned = result.unwrap();
    assert!(!unsigned.unsigned_xdr.is_empty());
    assert_eq!(unsigned.account_id, issuer_kp.public_key);
}

#[test]
fn test_build_trustline_transaction_produces_valid_xdr() {
    let dist_kp = generate_keypair().unwrap();
    let issuer_kp = generate_keypair().unwrap();

    let result = build_trustline_transaction(
        &dist_kp.public_key,
        100,
        "cNGN",
        &issuer_kp.public_key,
        None,
    );

    assert!(result.is_ok());
    assert!(!result.unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Verification report startup guard
// ---------------------------------------------------------------------------

#[test]
fn test_assert_issuer_configured_blocks_on_failure() {
    let mut report = VerificationReport::new(None);
    report.check_flags_ok = true;
    report.check_master_weight_zero = false; // master key not zeroed
    report.check_thresholds_ok = true;
    report.check_signers_ok = true;
    report.check_stellar_toml_ok = true;
    report.compute_overall();

    let result = assert_issuer_configured(&report);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("master_weight_zero=false"));
}

#[test]
fn test_assert_issuer_configured_passes_when_all_ok() {
    let mut report = VerificationReport::new(None);
    report.check_flags_ok = true;
    report.check_master_weight_zero = true;
    report.check_thresholds_ok = true;
    report.check_signers_ok = true;
    report.check_stellar_toml_ok = true;
    report.compute_overall();

    assert!(assert_issuer_configured(&report).is_ok());
}

// ---------------------------------------------------------------------------
// Testnet integration: account creation and trustline (requires funded accounts)
// ---------------------------------------------------------------------------

/// This test is skipped unless STELLAR_INTEGRATION_TEST=1 is set.
/// It verifies that a freshly generated account can be fetched from testnet
/// after being funded via Friendbot.
#[tokio::test]
async fn test_testnet_account_creation_and_trustline() {
    if std::env::var("STELLAR_INTEGRATION_TEST").unwrap_or_default() != "1" {
        return; // skip unless explicitly enabled
    }

    let client = testnet_client();
    let issuer_kp = generate_keypair().unwrap();
    let dist_kp = generate_keypair().unwrap();

    // Fund via Friendbot
    let friendbot_url = format!(
        "https://friendbot.stellar.org?addr={}",
        issuer_kp.public_key
    );
    let _ = reqwest::get(&friendbot_url).await;

    let friendbot_url2 = format!(
        "https://friendbot.stellar.org?addr={}",
        dist_kp.public_key
    );
    let _ = reqwest::get(&friendbot_url2).await;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Verify issuer account exists
    let issuer_account = client.get_account(&issuer_kp.public_key).await;
    assert!(issuer_account.is_ok(), "Issuer account should exist after funding");

    // Build trustline transaction
    let sequence = client
        .get_account(&dist_kp.public_key)
        .await
        .unwrap()
        .sequence;

    let xdr = build_trustline_transaction(
        &dist_kp.public_key,
        sequence,
        "cNGN",
        &issuer_kp.public_key,
        None,
    );
    assert!(xdr.is_ok(), "Trustline XDR should build successfully");
}
