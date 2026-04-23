//! Notification dispatcher for multi-sig governance events.
//!
//! Sends Email / Slack / Push alerts to all authorised signers when:
//! - A new proposal is created (action required)
//! - The signature threshold is met (ready to submit)
//! - A proposal is submitted / confirmed / rejected / expired
//! - A time-locked proposal becomes executable

use crate::multisig::models::{MultiSigOpType, MultiSigProposal};
use reqwest::Client;
use serde_json::json;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Notification channel configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct MultiSigNotificationConfig {
    /// Slack incoming webhook URL (optional).
    pub slack_webhook_url: Option<String>,
    /// SMTP relay host for email notifications (optional).
    pub smtp_host: Option<String>,
    /// From address for email notifications.
    pub email_from: String,
    /// Comma-separated list of signer email addresses to notify.
    pub signer_emails: Vec<String>,
    /// Base URL of the treasury portal (used to build deep-links in notifications).
    pub portal_base_url: String,
}

impl MultiSigNotificationConfig {
    pub fn from_env() -> Self {
        Self {
            slack_webhook_url: std::env::var("MULTISIG_SLACK_WEBHOOK_URL").ok(),
            smtp_host: std::env::var("MULTISIG_SMTP_HOST").ok(),
            email_from: std::env::var("MULTISIG_EMAIL_FROM")
                .unwrap_or_else(|_| "treasury@cngn.io".to_string()),
            signer_emails: std::env::var("MULTISIG_SIGNER_EMAILS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            portal_base_url: std::env::var("MULTISIG_PORTAL_BASE_URL")
                .unwrap_or_else(|_| "https://treasury.cngn.io".to_string()),
        }
    }
}

/// Notification event types.
#[derive(Debug, Clone, Copy)]
pub enum NotificationEvent {
    /// A new proposal has been created — all signers must review and sign.
    ProposalCreated,
    /// A signer has added their signature.
    SignatureAdded { current: usize, required: usize },
    /// The M-of-N threshold has been met; proposal is ready to submit.
    ThresholdMet,
    /// The time-lock has elapsed; governance change is now executable.
    TimeLockElapsed,
    /// The proposal has been submitted to Stellar Horizon.
    Submitted,
    /// On-chain confirmation received.
    Confirmed,
    /// A signer has rejected the proposal.
    Rejected,
    /// The proposal has expired without reaching threshold.
    Expired,
}

pub struct MultiSigNotifier {
    config: MultiSigNotificationConfig,
    http: Client,
}

impl MultiSigNotifier {
    pub fn new(config: MultiSigNotificationConfig) -> Self {
        Self {
            config,
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("HTTP client build failed"),
        }
    }

    /// Dispatch notifications for a governance event.
    ///
    /// Failures are logged but never propagate — notification errors must not
    /// block the governance workflow.
    pub async fn notify(&self, proposal: &MultiSigProposal, event: NotificationEvent) {
        let (title, body) = self.format_message(proposal, event);
        let proposal_url = format!(
            "{}/governance/proposals/{}",
            self.config.portal_base_url, proposal.id
        );

        // Slack
        if let Some(ref webhook_url) = self.config.slack_webhook_url {
            self.send_slack(webhook_url, &title, &body, &proposal_url)
                .await;
        }

        // Email (fire-and-forget per recipient)
        for email in &self.config.signer_emails {
            self.send_email_log(email, &title, &body, &proposal_url);
        }

        info!(
            proposal_id = %proposal.id,
            op_type = %proposal.op_type,
            event = ?event,
            "Multi-sig governance notification dispatched"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Slack
    // ─────────────────────────────────────────────────────────────────────────

    async fn send_slack(&self, webhook_url: &str, title: &str, body: &str, url: &str) {
        let payload = json!({
            "text": format!("*{}*\n{}\n<{}|View Proposal>", title, body, url),
            "username": "cNGN Treasury Bot",
            "icon_emoji": ":lock:",
        });

        match self.http.post(webhook_url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Slack notification sent successfully");
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "Slack notification returned non-2xx status");
            }
            Err(e) => {
                error!(error = %e, "Failed to send Slack notification");
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Email (structured log — real SMTP integration is wired via the existing
    // NotificationService; this module emits structured log events that the
    // notification worker can pick up)
    // ─────────────────────────────────────────────────────────────────────────

    fn send_email_log(&self, recipient: &str, subject: &str, body: &str, url: &str) {
        // In production, replace this with a call to the existing
        // `NotificationService::send_email` or an SMTP client.
        // Structured log emission ensures the notification worker can pick it up.
        info!(
            recipient = %recipient,
            subject = %subject,
            portal_url = %url,
            "📧 [MULTISIG EMAIL] {}",
            body
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Message formatting
    // ─────────────────────────────────────────────────────────────────────────

    fn format_message(
        &self,
        proposal: &MultiSigProposal,
        event: NotificationEvent,
    ) -> (String, String) {
        let op = proposal.op_type.as_str().to_uppercase();
        let id_short = &proposal.id.to_string()[..8];

        match event {
            NotificationEvent::ProposalCreated => (
                format!("🔐 New {} Proposal Requires Your Signature", op),
                format!(
                    "Proposal #{} has been created by {}.\n\
                     Operation: {}\n\
                     Description: {}\n\
                     Required signatures: {}/{}\n\
                     Expires: {}\n\
                     ⚠️  Review the full transaction XDR before signing.",
                    id_short,
                    &proposal.proposed_by_key[..8],
                    op,
                    proposal.description,
                    proposal.required_signatures,
                    proposal.total_signers,
                    proposal.expires_at.format("%Y-%m-%d %H:%M UTC"),
                ),
            ),
            NotificationEvent::SignatureAdded { current, required } => (
                format!("✍️  Signature Added to {} Proposal #{}", op, id_short),
                format!(
                    "A signer has approved proposal #{}.\n\
                     Progress: {}/{} signatures collected.\n\
                     {} more signature(s) needed.",
                    id_short,
                    current,
                    required,
                    required.saturating_sub(current),
                ),
            ),
            NotificationEvent::ThresholdMet => (
                format!("✅ {} Proposal #{} Ready for Submission", op, id_short),
                format!(
                    "Proposal #{} has reached the required signature threshold.\n\
                     The transaction is ready to be submitted to Stellar Horizon.",
                    id_short,
                ),
            ),
            NotificationEvent::TimeLockElapsed => (
                format!("⏰ Time-Lock Elapsed — {} Proposal #{} Now Executable", op, id_short),
                format!(
                    "The 48-hour governance time-lock for proposal #{} has elapsed.\n\
                     The transaction can now be submitted to Stellar Horizon.",
                    id_short,
                ),
            ),
            NotificationEvent::Submitted => (
                format!("🚀 {} Proposal #{} Submitted to Stellar", op, id_short),
                format!(
                    "Proposal #{} has been submitted to Stellar Horizon.\n\
                     Awaiting on-chain confirmation.",
                    id_short,
                ),
            ),
            NotificationEvent::Confirmed => (
                format!("🎉 {} Proposal #{} Confirmed On-Chain", op, id_short),
                format!(
                    "Proposal #{} has been confirmed on the Stellar network.\n\
                     TX Hash: {}",
                    id_short,
                    proposal.stellar_tx_hash.as_deref().unwrap_or("N/A"),
                ),
            ),
            NotificationEvent::Rejected => (
                format!("❌ {} Proposal #{} Rejected", op, id_short),
                format!(
                    "Proposal #{} has been rejected.\n\
                     Reason: {}",
                    id_short,
                    proposal.failure_reason.as_deref().unwrap_or("No reason provided"),
                ),
            ),
            NotificationEvent::Expired => (
                format!("⌛ {} Proposal #{} Expired", op, id_short),
                format!(
                    "Proposal #{} expired without reaching the required signature threshold.",
                    id_short,
                ),
            ),
        }
    }
}
