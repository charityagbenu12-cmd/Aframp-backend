use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Issuer account configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerConfig {
    pub environment: StellarEnvironment,
    pub issuer_account_id: String,
    pub home_domain: String,
    pub asset_code: String,
    pub decimal_precision: u8,
    pub min_issuance_amount: rust_decimal::Decimal,
    pub max_issuance_amount: rust_decimal::Decimal,
    pub multisig: MultiSigConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StellarEnvironment {
    Testnet,
    Mainnet,
}

impl StellarEnvironment {
    pub fn as_str(&self) -> &'static str {
        match self {
            StellarEnvironment::Testnet => "testnet",
            StellarEnvironment::Mainnet => "mainnet",
        }
    }
}

impl std::fmt::Display for StellarEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSigConfig {
    /// Master key weight — must be 0 after setup.
    pub master_weight: u8,
    pub low_threshold: u8,
    pub med_threshold: u8,
    pub high_threshold: u8,
    /// Minimum number of signers required (e.g. 3 for 3-of-5).
    pub required_signers: u8,
    pub signers: Vec<SignerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerEntry {
    pub public_key: String,
    pub weight: u8,
    /// Human-readable identity label (e.g. "ops-key-1").
    pub identity: String,
    /// Secrets manager reference for the private key.
    pub secrets_ref: String,
}

// ---------------------------------------------------------------------------
// Distribution account
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionAccount {
    pub account_id: String,
    /// Secrets manager reference for the private key.
    pub secrets_ref: String,
    pub trustline_authorized: bool,
}

// ---------------------------------------------------------------------------
// Fee account
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeAccount {
    pub account_id: String,
    pub secrets_ref: String,
    /// Alert when XLM balance falls below this (in XLM).
    pub alert_threshold_xlm: f64,
    /// Minimum balance to maintain (in XLM).
    pub min_balance_xlm: f64,
}

// ---------------------------------------------------------------------------
// Verification report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub issuer_id: Option<Uuid>,
    pub check_flags_ok: bool,
    pub check_master_weight_zero: bool,
    pub check_thresholds_ok: bool,
    pub check_signers_ok: bool,
    pub check_stellar_toml_ok: bool,
    pub overall_pass: bool,
    pub details: serde_json::Value,
    pub verified_at: chrono::DateTime<chrono::Utc>,
}

impl VerificationReport {
    pub fn new(issuer_id: Option<Uuid>) -> Self {
        Self {
            issuer_id,
            check_flags_ok: false,
            check_master_weight_zero: false,
            check_thresholds_ok: false,
            check_signers_ok: false,
            check_stellar_toml_ok: false,
            overall_pass: false,
            details: serde_json::json!({}),
            verified_at: chrono::Utc::now(),
        }
    }

    pub fn compute_overall(&mut self) {
        self.overall_pass = self.check_flags_ok
            && self.check_master_weight_zero
            && self.check_thresholds_ok
            && self.check_signers_ok
            && self.check_stellar_toml_ok;
    }
}

// ---------------------------------------------------------------------------
// Account flags
// ---------------------------------------------------------------------------

/// Required issuer account flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredFlags {
    pub auth_required: bool,
    pub auth_revocable: bool,
    pub auth_clawback_enabled: bool,
}

impl RequiredFlags {
    pub fn all_set(&self) -> bool {
        self.auth_required && self.auth_revocable && self.auth_clawback_enabled
    }
}

// ---------------------------------------------------------------------------
// Threshold calculation helpers
// ---------------------------------------------------------------------------

/// Calculate whether a given set of signer weights satisfies the threshold.
pub fn threshold_satisfied(signer_weights: &[u8], threshold: u8) -> bool {
    let total: u16 = signer_weights.iter().map(|&w| w as u16).sum();
    total >= threshold as u16
}

/// Calculate the minimum weight sum needed to meet the required signer count
/// when all signers have equal weight.
pub fn min_weight_for_quorum(signer_count: u8, required: u8, weight_per_signer: u8) -> u8 {
    required.saturating_mul(weight_per_signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_satisfied_exact() {
        // 3-of-5 with weight 1 each: need 3 signers
        assert!(threshold_satisfied(&[1, 1, 1], 3));
        assert!(!threshold_satisfied(&[1, 1], 3));
    }

    #[test]
    fn test_threshold_satisfied_weighted() {
        // Two signers with weight 2 each satisfy threshold 3
        assert!(threshold_satisfied(&[2, 2], 3));
        assert!(!threshold_satisfied(&[1, 1], 3));
    }

    #[test]
    fn test_min_weight_for_quorum() {
        assert_eq!(min_weight_for_quorum(5, 3, 1), 3);
        assert_eq!(min_weight_for_quorum(5, 3, 2), 6);
    }

    #[test]
    fn test_required_flags_all_set() {
        let flags = RequiredFlags {
            auth_required: true,
            auth_revocable: true,
            auth_clawback_enabled: true,
        };
        assert!(flags.all_set());

        let partial = RequiredFlags {
            auth_required: true,
            auth_revocable: false,
            auth_clawback_enabled: true,
        };
        assert!(!partial.all_set());
    }

    #[test]
    fn test_verification_report_overall() {
        let mut report = VerificationReport::new(None);
        report.check_flags_ok = true;
        report.check_master_weight_zero = true;
        report.check_thresholds_ok = true;
        report.check_signers_ok = true;
        report.check_stellar_toml_ok = true;
        report.compute_overall();
        assert!(report.overall_pass);

        report.check_flags_ok = false;
        report.compute_overall();
        assert!(!report.overall_pass);
    }
}
