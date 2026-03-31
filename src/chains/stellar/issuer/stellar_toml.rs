//! stellar.toml generation and validation.
//!
//! The TOML file is served at `https://<home_domain>/.well-known/stellar.toml`
//! and must conform to SEP-0001.

use crate::chains::stellar::issuer::types::{IssuerConfig, StellarEnvironment};
use serde::Serialize;

/// Minimal SEP-0001 stellar.toml content for the cNGN issuer.
#[derive(Debug, Serialize)]
pub struct StellarToml {
    pub version: String,
    pub network_passphrase: String,
    pub accounts: Vec<String>,
    pub documentation: TomlDocumentation,
    pub currencies: Vec<TomlCurrency>,
}

#[derive(Debug, Serialize)]
pub struct TomlDocumentation {
    pub org_name: String,
    pub org_url: String,
    pub org_description: String,
}

#[derive(Debug, Serialize)]
pub struct TomlCurrency {
    pub code: String,
    pub issuer: String,
    pub display_decimals: u8,
    pub name: String,
    pub desc: String,
    pub conditions: String,
    pub reserve_url: String,
    pub attestation_url: String,
    pub is_asset_anchored: bool,
    pub anchor_asset_type: String,
    pub anchor_asset: String,
    pub redemption_instructions: String,
}

/// Generate the stellar.toml content for the given issuer configuration.
pub fn generate_stellar_toml(
    config: &IssuerConfig,
    org_name: &str,
    org_url: &str,
    reserve_url: &str,
    attestation_url: &str,
) -> String {
    let network_passphrase = match config.environment {
        StellarEnvironment::Testnet => "Test SDF Network ; September 2015",
        StellarEnvironment::Mainnet => "Public Global Stellar Network ; September 2015",
    };

    // Build TOML manually to match SEP-0001 format exactly
    format!(
        r#"VERSION = "2.0.0"

NETWORK_PASSPHRASE = "{network_passphrase}"

ACCOUNTS = [
  "{issuer}"
]

[DOCUMENTATION]
ORG_NAME = "{org_name}"
ORG_URL = "{org_url}"
ORG_DESCRIPTION = "cNGN — Nigerian Naira stablecoin on Stellar"

[[CURRENCIES]]
code = "{asset_code}"
issuer = "{issuer}"
display_decimals = {decimals}
name = "cNGN Nigerian Naira"
desc = "cNGN is a Nigerian Naira-backed stablecoin issued on the Stellar network."
conditions = "cNGN is fully collateralized by Nigerian Naira reserves. Redemption requires KYC verification."
reserve_url = "{reserve_url}"
attestation_url = "{attestation_url}"
is_asset_anchored = true
anchor_asset_type = "fiat"
anchor_asset = "NGN"
redemption_instructions = "Redeem cNGN via the platform at {org_url}"
"#,
        network_passphrase = network_passphrase,
        issuer = config.issuer_account_id,
        org_name = org_name,
        org_url = org_url,
        asset_code = config.asset_code,
        decimals = config.decimal_precision,
        reserve_url = reserve_url,
        attestation_url = attestation_url,
    )
}

/// Validate that a stellar.toml string contains the required fields.
pub fn validate_stellar_toml(toml_content: &str, issuer_account_id: &str) -> Result<(), String> {
    if !toml_content.contains("VERSION") {
        return Err("Missing VERSION field".into());
    }
    if !toml_content.contains("NETWORK_PASSPHRASE") {
        return Err("Missing NETWORK_PASSPHRASE field".into());
    }
    if !toml_content.contains(issuer_account_id) {
        return Err(format!(
            "Issuer account {} not found in stellar.toml",
            issuer_account_id
        ));
    }
    if !toml_content.contains("[[CURRENCIES]]") {
        return Err("Missing [[CURRENCIES]] section".into());
    }
    if !toml_content.contains("is_asset_anchored") {
        return Err("Missing is_asset_anchored field".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::stellar::issuer::types::{MultiSigConfig, StellarEnvironment};

    fn test_config() -> IssuerConfig {
        IssuerConfig {
            environment: StellarEnvironment::Testnet,
            issuer_account_id: "GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX"
                .to_string(),
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
        }
    }

    #[test]
    fn test_generate_stellar_toml_contains_required_fields() {
        let config = test_config();
        let toml = generate_stellar_toml(
            &config,
            "Aframp",
            "https://example.com",
            "https://example.com/reserves",
            "https://example.com/attestation",
        );

        assert!(toml.contains("VERSION"));
        assert!(toml.contains("NETWORK_PASSPHRASE"));
        assert!(toml.contains("Test SDF Network"));
        assert!(toml.contains("GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX"));
        assert!(toml.contains("cNGN"));
        assert!(toml.contains("[[CURRENCIES]]"));
        assert!(toml.contains("is_asset_anchored = true"));
    }

    #[test]
    fn test_validate_stellar_toml_valid() {
        let config = test_config();
        let toml = generate_stellar_toml(
            &config,
            "Aframp",
            "https://example.com",
            "https://example.com/reserves",
            "https://example.com/attestation",
        );
        let result = validate_stellar_toml(
            &toml,
            "GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_stellar_toml_missing_issuer() {
        let toml = "VERSION = \"2.0.0\"\nNETWORK_PASSPHRASE = \"test\"\n[[CURRENCIES]]\nis_asset_anchored = true";
        let result = validate_stellar_toml(toml, "GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_validate_stellar_toml_missing_version() {
        let toml = "NETWORK_PASSPHRASE = \"test\"";
        let result = validate_stellar_toml(toml, "GXXX");
        assert!(result.is_err());
    }

    #[test]
    fn test_mainnet_uses_correct_passphrase() {
        let mut config = test_config();
        config.environment = StellarEnvironment::Mainnet;
        let toml = generate_stellar_toml(
            &config,
            "Aframp",
            "https://example.com",
            "https://example.com/reserves",
            "https://example.com/attestation",
        );
        assert!(toml.contains("Public Global Stellar Network"));
    }
}
