/// Concentration Limit Alert System
///
/// Fires when any custodian's reserve share exceeds its `max_concentration_bps`.
/// Notifies treasury operators via Slack and PagerDuty.
///
/// Severity rules:
///   excess ≤ 200 bps  → Warning
///   excess  > 200 bps → Critical
use super::repository::AllocationRepository;
use super::types::{AlertSeverity, ConcentrationAlert, ConcentrationSnapshot, CustodianInstitution};
use std::sync::Arc;
use tracing::{error, info, warn};

pub struct ConcentrationAlertService {
    repo: Arc<AllocationRepository>,
    http: reqwest::Client,
}

impl ConcentrationAlertService {
    pub fn new(repo: Arc<AllocationRepository>) -> Self {
        Self {
            repo,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Evaluate a freshly computed concentration snapshot.
    /// If breached, persist an alert and dispatch notifications.
    /// Returns the alert if one was created.
    pub async fn evaluate(
        &self,
        snapshot: &ConcentrationSnapshot,
        custodian: &CustodianInstitution,
    ) -> Option<ConcentrationAlert> {
        if !snapshot.is_breached {
            // Resolve any open alert for this custodian
            self.try_resolve_open_alerts(custodian).await;
            return None;
        }

        let excess_bps = snapshot.concentration_bps - snapshot.max_concentration_bps;
        let severity = if excess_bps > 200 {
            AlertSeverity::Critical
        } else {
            AlertSeverity::Warning
        };

        let message = format!(
            "[{}] {} concentration at {:.2}% exceeds limit of {:.2}% (excess: {:.2}%)",
            severity_label(severity),
            custodian.public_alias,
            snapshot.concentration_bps as f64 / 100.0,
            snapshot.max_concentration_bps as f64 / 100.0,
            excess_bps as f64 / 100.0,
        );

        warn!(
            custodian = %custodian.public_alias,
            concentration_bps = snapshot.concentration_bps,
            max_bps = snapshot.max_concentration_bps,
            excess_bps,
            severity = ?severity,
            "Concentration limit breach detected"
        );

        let alert = match self
            .repo
            .insert_alert(
                custodian.id,
                snapshot.id,
                severity,
                snapshot.concentration_bps,
                snapshot.max_concentration_bps,
                &message,
            )
            .await
        {
            Ok(a) => a,
            Err(e) => {
                error!(error = %e, "Failed to persist concentration alert");
                return None;
            }
        };

        // Dispatch notifications (non-blocking — failures are logged, not fatal)
        self.dispatch_notifications(&alert, custodian, severity, &message).await;

        Some(alert)
    }

    async fn dispatch_notifications(
        &self,
        alert: &ConcentrationAlert,
        custodian: &CustodianInstitution,
        severity: AlertSeverity,
        message: &str,
    ) {
        let emoji = match severity {
            AlertSeverity::Critical => "🚨",
            AlertSeverity::Warning => "⚠️",
            AlertSeverity::Resolved => "✅",
        };

        // ── Slack ─────────────────────────────────────────────────────────────
        if let Ok(url) = std::env::var("SLACK_TREASURY_WEBHOOK_URL") {
            let payload = serde_json::json!({
                "text": format!("{} *Treasury Concentration Alert*", emoji),
                "attachments": [{
                    "color": if matches!(severity, AlertSeverity::Critical) { "danger" } else { "warning" },
                    "fields": [
                        { "title": "Institution", "value": custodian.public_alias, "short": true },
                        { "title": "Severity",    "value": severity_label(severity), "short": true },
                        { "title": "Concentration",
                          "value": format!("{:.2}%", alert.concentration_bps as f64 / 100.0),
                          "short": true },
                        { "title": "Limit",
                          "value": format!("{:.2}%", alert.max_allowed_bps as f64 / 100.0),
                          "short": true },
                        { "title": "Excess",
                          "value": format!("{:.2}%", alert.excess_bps as f64 / 100.0),
                          "short": true },
                        { "title": "Alert ID", "value": alert.id.to_string(), "short": true },
                    ],
                    "footer": "cNGN Treasury Allocation Engine",
                    "ts": alert.created_at.timestamp(),
                }]
            });

            let http = self.http.clone();
            let url_clone = url.clone();
            tokio::spawn(async move {
                if let Err(e) = http.post(&url_clone).json(&payload).send().await {
                    warn!(error = %e, "Failed to send Slack concentration alert");
                }
            });
        }

        // ── PagerDuty ─────────────────────────────────────────────────────────
        if let Ok(routing_key) = std::env::var("PAGERDUTY_ROUTING_KEY") {
            let pd_severity = match severity {
                AlertSeverity::Critical => "critical",
                AlertSeverity::Warning => "warning",
                AlertSeverity::Resolved => "info",
            };

            let payload = serde_json::json!({
                "routing_key": routing_key,
                "event_action": "trigger",
                "dedup_key": format!("treasury-concentration-{}", custodian.id),
                "payload": {
                    "summary": message,
                    "severity": pd_severity,
                    "source": "treasury-allocation-engine",
                    "custom_details": {
                        "alert_id": alert.id,
                        "custodian_alias": custodian.public_alias,
                        "concentration_bps": alert.concentration_bps,
                        "max_allowed_bps": alert.max_allowed_bps,
                        "excess_bps": alert.excess_bps,
                    }
                }
            });

            let http = self.http.clone();
            tokio::spawn(async move {
                if let Err(e) = http
                    .post("https://events.pagerduty.com/v2/enqueue")
                    .json(&payload)
                    .send()
                    .await
                {
                    warn!(error = %e, "Failed to send PagerDuty concentration alert");
                }
            });
        }

        info!(
            alert_id = %alert.id,
            custodian = %custodian.public_alias,
            "Concentration alert dispatched"
        );
    }

    /// Resolve open alerts for a custodian that is no longer in breach.
    async fn try_resolve_open_alerts(&self, custodian: &CustodianInstitution) {
        match self.repo.list_unresolved_alerts().await {
            Ok(alerts) => {
                for alert in alerts.iter().filter(|a| a.custodian_id == custodian.id) {
                    if let Err(e) = self.repo.resolve_alert(alert.id).await {
                        error!(error = %e, alert_id = %alert.id, "Failed to resolve alert");
                    } else {
                        info!(
                            alert_id = %alert.id,
                            custodian = %custodian.public_alias,
                            "Concentration alert auto-resolved (breach cleared)"
                        );
                        self.send_resolution_notification(custodian).await;
                    }
                }
            }
            Err(e) => error!(error = %e, "Failed to fetch unresolved alerts for resolution"),
        }
    }

    async fn send_resolution_notification(&self, custodian: &CustodianInstitution) {
        if let Ok(url) = std::env::var("SLACK_TREASURY_WEBHOOK_URL") {
            let payload = serde_json::json!({
                "text": format!(
                    "✅ *Concentration Alert Resolved* — {} is back within limits.",
                    custodian.public_alias
                )
            });
            let http = self.http.clone();
            tokio::spawn(async move {
                let _ = http.post(&url).json(&payload).send().await;
            });
        }
    }
}

fn severity_label(s: AlertSeverity) -> &'static str {
    match s {
        AlertSeverity::Critical => "CRITICAL",
        AlertSeverity::Warning => "WARNING",
        AlertSeverity::Resolved => "RESOLVED",
    }
}
