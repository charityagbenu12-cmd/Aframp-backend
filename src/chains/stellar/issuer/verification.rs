//! Issuer account configuration verification.
//!
//! Checks that the on-chain state of the issuer account matches the required
//! security configuration. Any failed check blocks application startup.

use crate::chains::stellar::{
    client::StellarClient,
    errors::StellarResult,
    issuer::types::{IssuerConfig, RequiredFlags, VerificationReport},
};
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Verify the issuer account on-chain state against the expected configuration.
/// Returns a `VerificationReport` — callers must check `overall_pass` and block
/// startup if it is `false`.
pub async fn verify_issuer_account(
    client: &StellarClient,
    config: &IssuerConfig,
    issuer_db_id: Option<Uuid>,
) -> StellarResult<VerificationReport> {
    let mut report = VerificationReport::new(issuer_db_id);

    let account = match client.get_account(&config.issuer_account_id).await {
        Ok(a) => a,
        Err(e) => {
            error!(
                issuer = %config.issuer_account_id,
                error = %e,
                "Failed to fetch issuer account from Horizon"
            );
            report.details = json!({ "error": e.to_string() });
            return Ok(report);
        }
    };

    // --- Check 1: Account flags ---
    let flags = RequiredFlags {
        auth_required: account.flags.auth_required,
        auth_revocable: account.flags.auth_revocable,
        auth_clawback_enabled: account.flags.auth_clawback_enabled,
    };
    report.check_flags_ok = flags.all_set();
    if !report.check_flags_ok {
        warn!(
            auth_required = account.flags.auth_required,
            auth_revocable = account.flags.auth_revocable,
            auth_clawback = account.flags.auth_clawback_enabled,
            "Issuer account flags not fully set"
        );
    }

    // --- Check 2: Master key weight is 0 ---
    let master_weight = account
        .signers
        .iter()
        .find(|s| s.key == config.issuer_account_id)
        .map(|s| s.weight)
        .unwrap_or(1); // default is 1 if not explicitly set

    report.check_master_weight_zero = master_weight == 0;
    if !report.check_master_weight_zero {
        error!(
            master_weight = master_weight,
            "CRITICAL: Issuer account master key weight is non-zero"
        );
    }

    // --- Check 3: Thresholds match configuration ---
    let t = &account.thresholds;
    let expected = &config.multisig;
    report.check_thresholds_ok = t.low_threshold == expected.low_threshold
        && t.med_threshold == expected.med_threshold
        && t.high_threshold == expected.high_threshold;

    if !report.check_thresholds_ok {
        warn!(
            on_chain_low = t.low_threshold,
            on_chain_med = t.med_threshold,
            on_chain_high = t.high_threshold,
            expected_low = expected.low_threshold,
            expected_med = expected.med_threshold,
            expected_high = expected.high_threshold,
            "Issuer account thresholds mismatch"
        );
    }

    // --- Check 4: All authorized signers present with correct weights ---
    let on_chain_signers: std::collections::HashMap<&str, u8> = account
        .signers
        .iter()
        .map(|s| (s.key.as_str(), s.weight))
        .collect();

    let mut signers_ok = true;
    for expected_signer in &config.multisig.signers {
        match on_chain_signers.get(expected_signer.public_key.as_str()) {
            Some(&w) if w == expected_signer.weight => {}
            Some(&w) => {
                warn!(
                    signer = %expected_signer.public_key,
                    expected_weight = expected_signer.weight,
                    actual_weight = w,
                    "Signer weight mismatch"
                );
                signers_ok = false;
            }
            None => {
                warn!(
                    signer = %expected_signer.public_key,
                    "Expected signer not found on issuer account"
                );
                signers_ok = false;
            }
        }
    }
    report.check_signers_ok = signers_ok;

    // --- Check 5: stellar.toml accessible ---
    report.check_stellar_toml_ok =
        verify_stellar_toml(&config.home_domain, &config.issuer_account_id).await;

    // --- Emit observability metrics ---
    emit_verification_metrics(&report, &config.issuer_account_id);

    report.details = json!({
        "flags": {
            "auth_required": account.flags.auth_required,
            "auth_revocable": account.flags.auth_revocable,
            "auth_clawback_enabled": account.flags.auth_clawback_enabled,
        },
        "master_weight": master_weight,
        "thresholds": {
            "low": t.low_threshold,
            "med": t.med_threshold,
            "high": t.high_threshold,
        },
        "signer_count": account.signers.len(),
    });

    report.compute_overall();

    if report.overall_pass {
        info!(
            issuer = %config.issuer_account_id,
            environment = %config.environment,
            "Issuer account verification passed"
        );
    } else {
        error!(
            issuer = %config.issuer_account_id,
            flags_ok = report.check_flags_ok,
            master_weight_zero = report.check_master_weight_zero,
            thresholds_ok = report.check_thresholds_ok,
            signers_ok = report.check_signers_ok,
            toml_ok = report.check_stellar_toml_ok,
            "Issuer account verification FAILED — blocking startup"
        );
    }

    Ok(report)
}

/// Verify the stellar.toml is accessible at the home domain.
async fn verify_stellar_toml(home_domain: &str, issuer_account_id: &str) -> bool {
    let url = format!("https://{}/.well-known/stellar.toml", home_domain);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.text().await {
                Ok(body) => {
                    // Verify the issuer account ID appears in the TOML
                    let valid = body.contains(issuer_account_id);
                    if !valid {
                        warn!(url = %url, "stellar.toml does not reference issuer account");
                    }
                    valid
                }
                Err(e) => {
                    warn!(url = %url, error = %e, "Failed to read stellar.toml body");
                    false
                }
            }
        }
        Ok(resp) => {
            warn!(url = %url, status = %resp.status(), "stellar.toml returned non-200");
            false
        }
        Err(e) => {
            warn!(url = %url, error = %e, "stellar.toml not accessible");
            false
        }
    }
}

fn emit_verification_metrics(report: &VerificationReport, issuer_id: &str) {
    use crate::metrics::issuer as m;

    let flags_val = if report.check_flags_ok { 1.0 } else { 0.0 };
    let master_val = if report.check_master_weight_zero {
        0.0
    } else {
        1.0 // non-zero is the alert condition
    };

    m::issuer_flags_ok().with_label_values(&[issuer_id]).set(flags_val);
    m::issuer_master_weight().with_label_values(&[issuer_id]).set(master_val);

    if !report.check_flags_ok {
        error!(
            issuer = %issuer_id,
            "ALERT: Issuer account flag disabled — possible unauthorized modification"
        );
    }
    if !report.check_master_weight_zero {
        error!(
            issuer = %issuer_id,
            "ALERT: Issuer account master key weight is non-zero — critical configuration regression"
        );
    }
}

/// Persist the verification report to the database.
pub async fn persist_verification_report(
    pool: &PgPool,
    report: &VerificationReport,
) -> Result<(), sqlx::Error> {
    let issuer_id = report.issuer_id.ok_or_else(|| {
        sqlx::Error::Protocol("issuer_id required to persist report".into())
    })?;

    sqlx::query!(
        r#"
        INSERT INTO issuer_verification_reports
            (issuer_id, check_flags_ok, check_master_weight_zero, check_thresholds_ok,
             check_signers_ok, check_stellar_toml_ok, overall_pass, details, verified_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
        issuer_id,
        report.check_flags_ok,
        report.check_master_weight_zero,
        report.check_thresholds_ok,
        report.check_signers_ok,
        report.check_stellar_toml_ok,
        report.overall_pass,
        report.details,
        report.verified_at,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Block application startup if the verification report has any failed check.
/// Call this during application initialization after running `verify_issuer_account`.
pub fn assert_issuer_configured(report: &VerificationReport) -> Result<(), String> {
    if report.overall_pass {
        Ok(())
    } else {
        Err(format!(
            "Issuer account verification failed: flags_ok={}, master_weight_zero={}, \
             thresholds_ok={}, signers_ok={}, toml_ok={}",
            report.check_flags_ok,
            report.check_master_weight_zero,
            report.check_thresholds_ok,
            report.check_signers_ok,
            report.check_stellar_toml_ok,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::stellar::issuer::types::{MultiSigConfig, StellarEnvironment};

    #[test]
    fn test_assert_issuer_configured_pass() {
        let mut report = VerificationReport::new(None);
        report.check_flags_ok = true;
        report.check_master_weight_zero = true;
        report.check_thresholds_ok = true;
        report.check_signers_ok = true;
        report.check_stellar_toml_ok = true;
        report.compute_overall();
        assert!(assert_issuer_configured(&report).is_ok());
    }

    #[test]
    fn test_assert_issuer_configured_fail() {
        let mut report = VerificationReport::new(None);
        report.check_flags_ok = false;
        report.compute_overall();
        let result = assert_issuer_configured(&report);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("flags_ok=false"));
    }
}
