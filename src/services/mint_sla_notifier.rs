/// Mint SLA Notification Dispatcher
///
/// Sends Slack and Email alerts for:
///   - 4-hour inactivity warning (Tier-1 approver)
///   - 12-hour escalation (Tier-2 manager + department lead)
///   - 24-hour auto-expiration (all relevant parties)
///
/// All dispatches are fire-and-forget (tokio::spawn). Failures are logged
/// but never propagate — notification failure must not block SLA state updates.
use crate::services::mint_sla::StalledRequest;
use tracing::{info, warn};

pub struct MintSlaNotifier {
    http: reqwest::Client,
}

impl MintSlaNotifier {
    pub fn new(http: reqwest::Client) -> Self {
        Self { http }
    }

    // ── Public dispatch methods ───────────────────────────────────────────────

    /// 4-hour warning: remind the Tier-1 approver.
    pub async fn send_warning(&self, req: &StalledRequest, elapsed_hours: i64) {
        let id = req.mint_request_id;
        let amount = req.amount_ngn.to_string();
        let submitter = req.submitted_by.clone();

        let slack_msg = serde_json::json!({
            "text": "⚠️ *Mint Request SLA Warning*",
            "attachments": [{
                "color": "warning",
                "fields": [
                    { "title": "Request ID",    "value": id.to_string(),  "short": true },
                    { "title": "Amount (NGN)",  "value": amount,          "short": true },
                    { "title": "Submitted By",  "value": submitter,       "short": true },
                    { "title": "Elapsed",       "value": format!("{elapsed_hours}h"), "short": true },
                    { "title": "Action Required",
                      "value": "Tier-1 approver has been inactive for 4+ hours. Please review.",
                      "short": false },
                ],
                "footer": "cNGN Mint SLA Engine",
            }]
        });

        let email_subject = format!("[ACTION REQUIRED] Mint Request {id} awaiting approval");
        let email_body = format!(
            "Mint request {id} submitted by {submitter} for ₦{amount} \
             has been pending for {elapsed_hours} hours.\n\n\
             Please log in and approve or reject this request before the 24-hour deadline."
        );

        self.dispatch_slack(slack_msg, "SLACK_MINT_OPS_WEBHOOK_URL").await;
        self.dispatch_email(
            &email_subject,
            &email_body,
            "MINT_TIER1_APPROVER_EMAIL",
        )
        .await;

        info!(mint_request_id = %id, elapsed_hours, "SLA warning notifications dispatched");
    }

    /// 12-hour escalation: notify Tier-2 manager and department lead.
    pub async fn send_escalation(
        &self,
        req: &StalledRequest,
        elapsed_hours: i64,
        tier2_manager: Option<&str>,
    ) {
        let id = req.mint_request_id;
        let amount = req.amount_ngn.to_string();
        let manager = tier2_manager.unwrap_or("treasury-manager");

        let slack_msg = serde_json::json!({
            "text": "🚨 *Mint Request SLA Escalation — Tier 2 Manager Notified*",
            "attachments": [{
                "color": "danger",
                "fields": [
                    { "title": "Request ID",    "value": id.to_string(),  "short": true },
                    { "title": "Amount (NGN)",  "value": amount,          "short": true },
                    { "title": "Elapsed",       "value": format!("{elapsed_hours}h"), "short": true },
                    { "title": "Escalated To",  "value": manager,         "short": true },
                    { "title": "Approval Tier", "value": req.approval_tier.to_string(), "short": true },
                    { "title": "Action Required",
                      "value": "Tier-1 approver inactive for 12+ hours. Tier-2 manager must take over.",
                      "short": false },
                ],
                "footer": "cNGN Mint SLA Engine",
            }]
        });

        let email_subject = format!("[ESCALATION] Mint Request {id} requires Tier-2 approval");
        let email_body = format!(
            "ESCALATION NOTICE\n\n\
             Mint request {id} for ₦{amount} has been pending for {elapsed_hours} hours \
             without Tier-1 action.\n\n\
             You ({manager}) have been granted visibility and must take over approval.\n\n\
             Auto-expiration will occur at 24 hours if no action is taken."
        );

        self.dispatch_slack(slack_msg, "SLACK_MINT_OPS_WEBHOOK_URL").await;
        self.dispatch_slack(
            serde_json::json!({ "text": format!("🚨 Escalation: Mint {id} needs Tier-2 review") }),
            "SLACK_TREASURY_WEBHOOK_URL",
        )
        .await;
        self.dispatch_email(&email_subject, &email_body, "MINT_TIER2_MANAGER_EMAIL").await;
        self.dispatch_email(&email_subject, &email_body, "MINT_DEPT_LEAD_EMAIL").await;

        warn!(mint_request_id = %id, elapsed_hours, escalated_to = manager, "SLA escalation notifications dispatched");
    }

    /// 24-hour expiration: notify all parties.
    pub async fn send_expiration(&self, req: &StalledRequest, elapsed_hours: i64) {
        let id = req.mint_request_id;
        let amount = req.amount_ngn.to_string();

        let slack_msg = serde_json::json!({
            "text": "🔴 *Mint Request AUTO-EXPIRED*",
            "attachments": [{
                "color": "danger",
                "fields": [
                    { "title": "Request ID",   "value": id.to_string(), "short": true },
                    { "title": "Amount (NGN)", "value": amount,         "short": true },
                    { "title": "Elapsed",      "value": format!("{elapsed_hours}h"), "short": true },
                    { "title": "Status",       "value": "EXPIRED — cannot be re-approved. Fresh re-submission required.", "short": false },
                ],
                "footer": "cNGN Mint SLA Engine",
            }]
        });

        let email_subject = format!("[EXPIRED] Mint Request {id} has been auto-expired");
        let email_body = format!(
            "Mint request {id} for ₦{amount} has been automatically expired \
             after {elapsed_hours} hours without approval.\n\n\
             Per policy (#123), this request cannot be re-approved. \
             A fresh submission is required."
        );

        self.dispatch_slack(slack_msg.clone(), "SLACK_MINT_OPS_WEBHOOK_URL").await;
        self.dispatch_slack(slack_msg, "SLACK_TREASURY_WEBHOOK_URL").await;
        self.dispatch_email(&email_subject, &email_body, "MINT_TIER1_APPROVER_EMAIL").await;
        self.dispatch_email(&email_subject, &email_body, "MINT_TIER2_MANAGER_EMAIL").await;
        self.dispatch_email(&email_subject, &email_body, "MINT_DEPT_LEAD_EMAIL").await;
    }

    // ── Internal dispatch helpers ─────────────────────────────────────────────

    async fn dispatch_slack(&self, payload: serde_json::Value, env_key: &'static str) {
        let url = match std::env::var(env_key) {
            Ok(u) => u,
            Err(_) => {
                warn!(env_key, "Slack webhook URL not configured — skipping");
                return;
            }
        };
        let http = self.http.clone();
        tokio::spawn(async move {
            if let Err(e) = http.post(&url).json(&payload).send().await {
                warn!(error = %e, "Slack SLA notification failed");
            }
        });
    }

    async fn dispatch_email(&self, subject: &str, body: &str, recipient_env_key: &'static str) {
        let recipient = match std::env::var(recipient_env_key) {
            Ok(r) => r,
            Err(_) => {
                warn!(recipient_env_key, "Email recipient not configured — skipping");
                return;
            }
        };
        let subject = subject.to_string();
        let body = body.to_string();
        let smtp_host = std::env::var("SMTP_HOST").unwrap_or_default();
        let smtp_user = std::env::var("SMTP_USER").unwrap_or_default();
        let smtp_pass = std::env::var("SMTP_PASS").unwrap_or_default();
        let from_addr = std::env::var("SMTP_FROM").unwrap_or_else(|_| "noreply@cngn.io".to_string());

        tokio::spawn(async move {
            use lettre::{
                message::Mailbox, transport::smtp::asynchronous::AsyncSmtpTransport,
                AsyncTransport, Message, Tokio1Executor,
            };

            let Ok(to) = recipient.parse::<lettre::Address>() else {
                warn!(recipient, "Invalid email address for SLA notification");
                return;
            };
            let Ok(from) = from_addr.parse::<lettre::Address>() else {
                warn!("Invalid SMTP_FROM address");
                return;
            };

            let Ok(email) = Message::builder()
                .from(Mailbox::new(None, from))
                .to(Mailbox::new(None, to))
                .subject(&subject)
                .body(body)
            else {
                warn!("Failed to build SLA email");
                return;
            };

            let Ok(transport) = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_host)
                .map(|b| {
                    b.credentials(lettre::transport::smtp::authentication::Credentials::new(
                        smtp_user, smtp_pass,
                    ))
                    .build()
                })
            else {
                warn!("Failed to build SMTP transport for SLA email");
                return;
            };

            if let Err(e) = transport.send(email).await {
                warn!(error = %e, "SLA email dispatch failed");
            } else {
                info!(recipient, "SLA email dispatched");
            }
        });
    }
}
