use prometheus::{register_gauge_vec_with_registry, GaugeVec};
use std::sync::OnceLock;

static ACTIVE_SIGNERS: OnceLock<GaugeVec> = OnceLock::new();
static SUSPENDED_SIGNERS: OnceLock<GaugeVec> = OnceLock::new();
static INACTIVE_SIGNERS: OnceLock<GaugeVec> = OnceLock::new();
static DAYS_UNTIL_KEY_EXPIRY: OnceLock<GaugeVec> = OnceLock::new();

pub fn register(r: &prometheus::Registry) {
    ACTIVE_SIGNERS.set(register_gauge_vec_with_registry!(
        "aframp_mint_signers_active", "Active mint signer count", &[], r).unwrap()).ok();
    SUSPENDED_SIGNERS.set(register_gauge_vec_with_registry!(
        "aframp_mint_signers_suspended", "Suspended mint signer count", &[], r).unwrap()).ok();
    INACTIVE_SIGNERS.set(register_gauge_vec_with_registry!(
        "aframp_mint_signers_inactive", "Signers exceeding inactivity threshold", &[], r).unwrap()).ok();
    DAYS_UNTIL_KEY_EXPIRY.set(register_gauge_vec_with_registry!(
        "aframp_mint_signer_earliest_key_expiry_days", "Days until earliest signer key expiry", &[], r).unwrap()).ok();
}

pub fn inactive_signers_gauge() -> &'static prometheus::Gauge {
    // convenience — returns the no-label gauge
    static G: OnceLock<prometheus::Gauge> = OnceLock::new();
    G.get_or_init(|| prometheus::Gauge::new(
        "aframp_mint_signers_inactive_total", "Inactive signers").unwrap())
}

pub async fn update_counts(svc: &super::mint_signer_service::MintSignerService) {
    if let Some(g) = ACTIVE_SIGNERS.get() {
        g.with_label_values(&[]).set(svc.count_active().await as f64);
    }
    if let Some(g) = SUSPENDED_SIGNERS.get() {
        g.with_label_values(&[]).set(svc.count_suspended().await as f64);
    }
    if let Some(g) = DAYS_UNTIL_KEY_EXPIRY.get() {
        if let Some(days) = svc.days_until_earliest_expiry().await {
            g.with_label_values(&[]).set(days as f64);
        }
    }
}
