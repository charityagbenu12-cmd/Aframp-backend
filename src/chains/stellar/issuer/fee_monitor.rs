//! Fee account balance monitor.
//!
//! Polls the fee account XLM balance and emits alerts when it falls below
//! the configured threshold.

use crate::chains::stellar::{
    client::StellarClient,
    errors::StellarResult,
    issuer::types::FeeAccount,
};
use crate::metrics::issuer as m;
use tracing::{error, info, warn};

/// Check the fee account balance and emit metrics + alerts.
/// Returns the current XLM balance as a float.
pub async fn check_fee_account_balance(
    client: &StellarClient,
    fee_account: &FeeAccount,
) -> StellarResult<f64> {
    let account = client.get_account(&fee_account.account_id).await?;

    let xlm_balance: f64 = account
        .balances
        .iter()
        .find(|b| b.asset_type == "native")
        .and_then(|b| b.balance.parse().ok())
        .unwrap_or(0.0);

    m::fee_account_balance_xlm()
        .with_label_values(&[&fee_account.account_id])
        .set(xlm_balance);

    if xlm_balance < fee_account.min_balance_xlm {
        error!(
            account = %fee_account.account_id,
            balance = xlm_balance,
            threshold = fee_account.min_balance_xlm,
            "ALERT: Fee account balance critically low — operations team must replenish immediately"
        );
    } else if xlm_balance < fee_account.alert_threshold_xlm {
        warn!(
            account = %fee_account.account_id,
            balance = xlm_balance,
            threshold = fee_account.alert_threshold_xlm,
            "Fee account balance below alert threshold — schedule replenishment"
        );
    } else {
        info!(
            account = %fee_account.account_id,
            balance = xlm_balance,
            "Fee account balance OK"
        );
    }

    Ok(xlm_balance)
}

/// Evaluate whether a fee account balance is below the alert threshold.
/// Pure function — used in unit tests and alerting logic.
pub fn is_below_alert_threshold(balance_xlm: f64, threshold_xlm: f64) -> bool {
    balance_xlm < threshold_xlm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_below_threshold() {
        assert!(is_below_alert_threshold(40.0, 50.0));
        assert!(!is_below_alert_threshold(60.0, 50.0));
        assert!(!is_below_alert_threshold(50.0, 50.0));
    }

    #[test]
    fn test_exactly_at_threshold_not_below() {
        assert!(!is_below_alert_threshold(50.0, 50.0));
    }

    #[test]
    fn test_zero_balance_always_below() {
        assert!(is_below_alert_threshold(0.0, 1.0));
    }
}
