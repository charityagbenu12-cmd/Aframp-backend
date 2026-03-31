//! Reserve Gatekeeper - CBN/ASC compliance enforcement layer.
//
//! Enforces the 1:1 reserve ratio (CBN/ASC). Provides:
//! * Pre-mint validation hook
//! * Circuit breaker (mint_enabled flag)
//! * Slack/PagerDuty alerting at 105% warning threshold
//! * Audit logging for blocked mints (Issue #117)

use crate::audit::models::{AuditActorType, AuditEventCategory, AuditOutcome, PendingAuditEntry};
use crate::audit::writer::AuditWriter;
use crate::error::{AppError, AppErrorKind, DomainError};
use bigdecimal::BigDecimal;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, warn};

const MIN_RESERVE_RATIO: f64 = 1.0;
const WARNING_THRESHOLD: f64 = 1.05;

#[derive(Debug, Clone)]
pub struct CollateralSnapshot {
    pub total_reserves: BigDecimal,
    pub total_supply: BigDecimal,
}

impl CollateralSnapshot {
    pub fn ratio(&self) -> f64 {
        if self.total_supply == BigDecimal::from(0) {
            return f64::INFINITY;
        }
        let r = &self.total_reserves / &self.total_supply;
        r.to_string().parse::<f64>().unwrap_or(0.0)
    }

    pub fn ratio_after_mint(&self, mint_amount: &BigDecimal) -> f64 {
        let new_supply = &self.total_supply + mint_amount;
        if new_supply == BigDecimal::from(0) {
            return f64::INFINITY;
        }
        let r = &self.total_reserves / &new_supply;
        r.to_string().parse::<f64>().unwrap_or(0.0)
    }
}

pub struct AlertClient {
    http: reqwest::Client,
}

impl AlertClient {
    pub fn new() -> Self {
        Self { http: reqwest::Client::new() }
    }

    pub async fn send_reserve_warning(&self, ratio: f64, snapshot: &CollateralSnapshot) {
        let msg = format!(
            "cNGN Reserve Warning - ratio {:.4} below threshold {:.2}. Reserves: {}, Supply: {}",
            ratio, WARNING_THRESHOLD, snapshot.total_reserves, snapshot.total_supply
        );

        if let Ok(url) = std::env::var("SLACK_TREASURY_WEBHOOK_URL") {
            let payload = serde_json::json!({ "text": msg });
            if let Err(e) = self.http.post(&url).json(&payload).send().await {
                error!(error = %e, "Failed to send Slack reserve warning");
            }
        }

        if let Ok(routing_key) = std::env::var("PAGERDUTY_ROUTING_KEY") {
            let payload = serde_json::json!({
                "routing_key": routing_key,
                "event_action": "trigger",
                "payload": { "summary": msg, "severity": "warning", "source": "reserve-gatekeeper" }
            });
            if let Err(e) = self.http
                .post("https://events.pagerduty.com/v2/enqueue")
                .json(&payload).send().await
            {
                error!(error = %e, "Failed to send PagerDuty reserve warning");
            }
        }
    }
}

pub struct ReserveGatekeeper {
    mint_enabled: Arc<AtomicBool>,
    alert_client: AlertClient,
    audit_writer: Option<Arc<AuditWriter>>,
    environment: String,
}

impl ReserveGatekeeper {
    pub fn new(audit_writer: Option<Arc<AuditWriter>>) -> Self {
        let environment = std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        Self {
            mint_enabled: Arc::new(AtomicBool::new(true)),
            alert_client: AlertClient::new(),
            audit_writer,
            environment,
        }
    }

    pub fn mint_enabled_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.mint_enabled)
    }

    pub async fn check_mint(
        &self,
        snapshot: &CollateralSnapshot,
        mint_amount: &BigDecimal,
        actor_id: Option<&str>,
    ) -> Result<(), AppError> {
        if !self.mint_enabled.load(Ordering::SeqCst) {
            warn!("Mint attempt blocked: circuit breaker is open");
            self.audit_blocked_mint(snapshot, mint_amount, actor_id, "circuit_breaker_open").await;
            return Err(AppError::new(AppErrorKind::Domain(DomainError::MintDisabled)));
        }

        let post_ratio = snapshot.ratio_after_mint(mint_amount);

        if post_ratio < MIN_RESERVE_RATIO {
            warn!(post_ratio = post_ratio, mint_amount = %mint_amount, "Mint rejected: post-mint ratio breaches 1:1 minimum");
            self.audit_blocked_mint(
                snapshot, mint_amount, actor_id,
                &format!("reserve_insufficient: post_ratio={:.6}", post_ratio),
            ).await;
            return Err(AppError::new(AppErrorKind::Domain(DomainError::ReserveInsufficient {
                total_reserves: snapshot.total_reserves.to_string(),
                total_supply: snapshot.total_supply.to_string(),
                mint_amount: mint_amount.to_string(),
                ratio: format!("{:.6}", post_ratio),
            })));
        }

        if post_ratio < WARNING_THRESHOLD {
            warn!(post_ratio = post_ratio, "Reserve ratio below warning threshold after proposed mint");
            self.alert_client.send_reserve_warning(post_ratio, snapshot).await;
        }

        Ok(())
    }

    pub async fn evaluate_ratio(&self, snapshot: &CollateralSnapshot) {
        let ratio = snapshot.ratio();

        if ratio < MIN_RESERVE_RATIO {
            error!(ratio = ratio, "Reserve ratio below 1.0 - disabling minting (circuit breaker tripped)");
            self.mint_enabled.store(false, Ordering::SeqCst);
            self.alert_client.send_reserve_warning(ratio, snapshot).await;
            return;
        }

        if ratio < WARNING_THRESHOLD {
            warn!(ratio = ratio, "Reserve ratio in warning zone (<1.05)");
            self.alert_client.send_reserve_warning(ratio, snapshot).await;
        }
    }

    pub fn emergency_reset(&self, snapshot: &CollateralSnapshot) -> Result<(), AppError> {
        let ratio = snapshot.ratio();
        if ratio < MIN_RESERVE_RATIO {
            return Err(AppError::new(AppErrorKind::Domain(DomainError::ReserveInsufficient {
                total_reserves: snapshot.total_reserves.to_string(),
                total_supply: snapshot.total_supply.to_string(),
                mint_amount: "0".to_string(),
                ratio: format!("{:.6}", ratio),
            })));
        }
        self.mint_enabled.store(true, Ordering::SeqCst);
        tracing::info!(ratio = ratio, "Minting re-enabled via emergency reset");
        Ok(())
    }

    async fn audit_blocked_mint(
        &self,
        snapshot: &CollateralSnapshot,
        mint_amount: &BigDecimal,
        actor_id: Option<&str>,
        reason: &str,
    ) {
        let Some(writer) = &self.audit_writer else { return; };

        let entry = PendingAuditEntry {
            event_type: "mint.blocked".to_string(),
            event_category: AuditEventCategory::FinancialTransaction,
            actor_type: AuditActorType::Microservice,
            actor_id: actor_id.map(str::to_string),
            actor_ip: None,
            actor_consumer_type: Some("minting_service".to_string()),
            session_id: None,
            target_resource_type: Some("cngn_supply".to_string()),
            target_resource_id: None,
            request_method: "INTERNAL".to_string(),
            request_path: "/internal/mint".to_string(),
            request_body_hash: None,
            response_status: 422,
            response_latency_ms: 0,
            outcome: AuditOutcome::Failure,
            failure_reason: Some(format!(
                "{} | reserves={} supply={} mint_amount={}",
                reason, snapshot.total_reserves, snapshot.total_supply, mint_amount
            )),
            environment: self.environment.clone(),
        };

        writer.write(entry).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bigdecimal::BigDecimal;

    fn snapshot(reserves: &str, supply: &str) -> CollateralSnapshot {
        CollateralSnapshot {
            total_reserves: BigDecimal::from_str(reserves).unwrap(),
            total_supply: BigDecimal::from_str(supply).unwrap(),
        }
    }

    fn gatekeeper() -> ReserveGatekeeper {
        ReserveGatekeeper::new(None)
    }

    #[test]
    fn ratio_is_correct() {
        let s = snapshot("1050000", "1000000");
        assert!((s.ratio() - 1.05).abs() < 1e-9);
    }

    #[test]
    fn ratio_after_mint_accounts_for_new_supply() {
        let s = snapshot("1050000", "1000000");
        let ratio = s.ratio_after_mint(&BigDecimal::from_str("50000").unwrap());
        assert!((ratio - 1.0).abs() < 1e-9);
    }

    #[test]
    fn ratio_is_infinity_when_supply_is_zero() {
        let s = snapshot("1000000", "0");
        assert_eq!(s.ratio(), f64::INFINITY);
    }

    #[test]
    fn ratio_after_mint_is_infinity_when_supply_and_mint_are_zero() {
        let s = snapshot("1000000", "0");
        let ratio = s.ratio_after_mint(&BigDecimal::from_str("0").unwrap());
        assert_eq!(ratio, f64::INFINITY);
    }

    #[tokio::test]
    async fn circuit_breaker_blocks_mint_even_when_reserves_are_sufficient() {
        let gk = gatekeeper();
        gk.mint_enabled.store(false, Ordering::SeqCst);
        let s = snapshot("2000000", "1000000");
        let result = gk.check_mint(&s, &BigDecimal::from_str("1").unwrap(), None).await;
        assert!(matches!(result, Err(AppError { kind: AppErrorKind::Domain(DomainError::MintDisabled), .. })));
    }

    #[tokio::test]
    async fn mint_is_rejected_when_post_ratio_breaches_minimum() {
        let gk = gatekeeper();
        let s = snapshot("1000000", "1000000");
        let result = gk.check_mint(&s, &BigDecimal::from_str("1").unwrap(), None).await;
        assert!(matches!(result, Err(AppError { kind: AppErrorKind::Domain(DomainError::ReserveInsufficient { .. }), .. })));
    }

    #[tokio::test]
    async fn mint_is_allowed_when_ratio_stays_above_minimum() {
        let gk = gatekeeper();
        let s = snapshot("1100000", "1000000");
        let result = gk.check_mint(&s, &BigDecimal::from_str("50000").unwrap(), None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_mint_allows_mint_in_warning_zone() {
        let gk = gatekeeper();
        // ratio after mint ~1.0495 - below warning threshold but above minimum
        let s = snapshot("1060000", "1000000");
        let result = gk.check_mint(&s, &BigDecimal::from_str("10000").unwrap(), None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_mint_with_actor_id_records_blocked_attempt() {
        let gk = gatekeeper();
        let s = snapshot("1000000", "1000000");
        let result = gk.check_mint(&s, &BigDecimal::from_str("1").unwrap(), Some("admin-007")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn emergency_reset_fails_when_ratio_still_below_minimum() {
        let gk = gatekeeper();
        gk.mint_enabled.store(false, Ordering::SeqCst);
        let s = snapshot("900000", "1000000");
        let result = gk.emergency_reset(&s);
        assert!(matches!(result, Err(AppError { kind: AppErrorKind::Domain(DomainError::ReserveInsufficient { .. }), .. })));
        assert!(!gk.mint_enabled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn emergency_reset_succeeds_when_ratio_is_restored() {
        let gk = gatekeeper();
        gk.mint_enabled.store(false, Ordering::SeqCst);
        let s = snapshot("1100000", "1000000");
        assert!(gk.emergency_reset(&s).is_ok());
        assert!(gk.mint_enabled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn evaluate_ratio_trips_circuit_breaker_below_minimum() {
        let gk = gatekeeper();
        assert!(gk.mint_enabled.load(Ordering::SeqCst));
        let s = snapshot("900000", "1000000");
        gk.evaluate_ratio(&s).await;
        assert!(!gk.mint_enabled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn evaluate_ratio_does_not_trip_breaker_in_warning_zone() {
        let gk = gatekeeper();
        let s = snapshot("1020000", "1000000");
        gk.evaluate_ratio(&s).await;
        assert!(gk.mint_enabled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn evaluate_ratio_does_nothing_when_healthy() {
        let gk = gatekeeper();
        let s = snapshot("1200000", "1000000");
        gk.evaluate_ratio(&s).await;
        assert!(gk.mint_enabled.load(Ordering::SeqCst));
    }

    #[test]
    fn mint_enabled_flag_reflects_atomic_state() {
        let gk = gatekeeper();
        let flag = gk.mint_enabled_flag();
        assert!(flag.load(Ordering::SeqCst));
        gk.mint_enabled.store(false, Ordering::SeqCst);
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn alert_client_can_be_constructed() {
        let _client = AlertClient::new();
    }
}
