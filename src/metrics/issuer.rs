//! Prometheus metrics for the Stellar issuer account infrastructure.

use prometheus::{register_gauge_vec_with_registry, GaugeVec, Registry};
use std::sync::OnceLock;

static ISSUER_ACCOUNT_XLM_BALANCE: OnceLock<GaugeVec> = OnceLock::new();
static DISTRIBUTION_ACCOUNT_XLM_BALANCE: OnceLock<GaugeVec> = OnceLock::new();
static FEE_ACCOUNT_XLM_BALANCE: OnceLock<GaugeVec> = OnceLock::new();
static CNGN_TOTAL_CIRCULATION: OnceLock<GaugeVec> = OnceLock::new();
static ISSUER_FLAGS_OK: OnceLock<GaugeVec> = OnceLock::new();
static ISSUER_MASTER_WEIGHT: OnceLock<GaugeVec> = OnceLock::new();

pub fn issuer_account_xlm_balance() -> &'static GaugeVec {
    ISSUER_ACCOUNT_XLM_BALANCE
        .get()
        .expect("issuer metrics not initialised")
}

pub fn distribution_account_xlm_balance() -> &'static GaugeVec {
    DISTRIBUTION_ACCOUNT_XLM_BALANCE
        .get()
        .expect("issuer metrics not initialised")
}

pub fn fee_account_balance_xlm() -> &'static GaugeVec {
    FEE_ACCOUNT_XLM_BALANCE
        .get()
        .expect("issuer metrics not initialised")
}

pub fn cngn_total_circulation() -> &'static GaugeVec {
    CNGN_TOTAL_CIRCULATION
        .get()
        .expect("issuer metrics not initialised")
}

/// 1.0 = flags correctly set, 0.0 = one or more flags missing (alert condition).
pub fn issuer_flags_ok() -> &'static GaugeVec {
    ISSUER_FLAGS_OK
        .get()
        .expect("issuer metrics not initialised")
}

/// 0.0 = master weight is zero (correct), >0 = master weight non-zero (alert condition).
pub fn issuer_master_weight() -> &'static GaugeVec {
    ISSUER_MASTER_WEIGHT
        .get()
        .expect("issuer metrics not initialised")
}

/// Register all issuer metrics with the global registry.
/// Called from `metrics::register_all`.
pub fn register(r: &Registry) {
    ISSUER_ACCOUNT_XLM_BALANCE
        .set(
            register_gauge_vec_with_registry!(
                "aframp_issuer_account_xlm_balance",
                "XLM balance of the cNGN issuer account",
                &["account_id"],
                r
            )
            .unwrap(),
        )
        .ok();

    DISTRIBUTION_ACCOUNT_XLM_BALANCE
        .set(
            register_gauge_vec_with_registry!(
                "aframp_distribution_account_xlm_balance",
                "XLM balance of the cNGN distribution account",
                &["account_id"],
                r
            )
            .unwrap(),
        )
        .ok();

    FEE_ACCOUNT_XLM_BALANCE
        .set(
            register_gauge_vec_with_registry!(
                "aframp_fee_account_xlm_balance",
                "XLM balance of the Stellar fee account",
                &["account_id"],
                r
            )
            .unwrap(),
        )
        .ok();

    CNGN_TOTAL_CIRCULATION
        .set(
            register_gauge_vec_with_registry!(
                "aframp_cngn_total_circulation",
                "Total cNGN in circulation (sum of all authorized trustline balances)",
                &["environment"],
                r
            )
            .unwrap(),
        )
        .ok();

    ISSUER_FLAGS_OK
        .set(
            register_gauge_vec_with_registry!(
                "aframp_issuer_flags_ok",
                "1 if all required issuer account flags are set, 0 if any flag is missing",
                &["account_id"],
                r
            )
            .unwrap(),
        )
        .ok();

    ISSUER_MASTER_WEIGHT
        .set(
            register_gauge_vec_with_registry!(
                "aframp_issuer_master_weight",
                "Master key weight of the issuer account (must be 0)",
                &["account_id"],
                r
            )
            .unwrap(),
        )
        .ok();
}
