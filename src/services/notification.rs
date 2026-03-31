use crate::database::{
    notification_repository::{NotificationRepository, NotificationHistory},
    transaction_repository::{Transaction, TransactionRepository},
};
use crate::services::templates::TemplateService;
use anyhow::{Context, Result};
use lettre::{
    message::Mailbox,
    transport::smtp::asynchronous::AsyncSmtpTransport,
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use reqwest::Client;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde_json::Value;
use std::sync::Arc;
use tokio::try_join;
use tracing::{error, info};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, serde::Serialize)]
pub enum NotificationEvent {
    MintReceived,
    FiatConfirmed,
    PendingApproval,
    MintSuccessful,
    MintRejected,
}

impl NotificationEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MintReceived => "MINT_RECEIVED",
            Self::FiatConfirmed => "FIAT_CONFIRMED",
            Self::PendingApproval => "PENDING_APPROVAL",
            Self::MintSuccessful => "MINT_SUCCESSFUL",
            Self::MintRejected => "MINT_REJECTED",
        }
    }
}

/// Full NotificationService with multi-channel support
pub struct NotificationService {
    repo: Arc<NotificationRepository>,
    tx_repo: Arc<TransactionRepository>,
    templates: Arc<TemplateService>,
    http_client: Client,
    smtp: AsyncSmtpTransport<Tokio1Executor>,
    webhook_secret: String, // For HMAC sig
    partner_webhook_url: String, // Configurable
    support_email: String,
}

impl NotificationService {
    pub fn new(
        repo: Arc<NotificationRepository>,
        tx_repo: Arc<TransactionRepository>,
        templates: Arc<TemplateService>,
        smtp_server: &str,
        smtp_port: u16,
        smtp_user: &str,
        smtp_pass: &str,
        webhook_secret: &str,
        partner_webhook_url: &str,
        support_email: &str,
    ) -> Result<Self> {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let smtp = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(smtp_server)?
            .credentials((smtp_user.to_string(), smtp_pass.to_string()))
            .port(smtp_port)
            .build();

        Ok(Self {
            repo,
            tx_repo,
            templates,
            http_client,
            smtp,
            webhook_secret: webhook_secret.to_string(),
            partner_webhook_url: partner_webhook_url.to_string(),
            support_email,
        })
    }

    /// Dispatch notification for tx state change
    pub async fn dispatch(&self, tx_id: Uuid, event: NotificationEvent) -> Result<()> {
        let tx = self.tx_repo.find_by_id(&tx_id.to_string()).await?
            .context("Transaction not found")?;

        let event_str = event.as_str().to_string();
        let tx_arc = Arc::new(tx);

        // Render payloads
        let webhook_payload = self.templates.render_webhook(&event_str, &tx_arc).context("Webhook render")?;
        let email_payload = self.templates.render_email(&event_str, &tx_arc).context("Email render")?;

        // Log to history (pending)
        let recipient_webhook = Some(self.partner_webhook_url.clone());
        let recipient_email = Some(format!("user@example.com")); // TODO: From tx metadata or DB

        let _history_webhook = self.repo.log_notification(
            tx_id,
            &event_str,
            "webhook",
            recipient_webhook.as_deref(),
            serde_json::from_str(&webhook_payload)?,
        ).await?;

        let _history_email = self.repo.log_notification(
            tx_id,
            &event_str,
            "email",
            recipient_email.as_deref(),
            serde_json::json!({"html": email_payload}),
        ).await?;

        self.repo.log_notification(
            tx_id,
            &event_str,
            "internal",
            None,
            serde_json::json!({"event": event_str, "tx_id": tx_id}),
        ).await?;

        // Parallel dispatch
        let webhook_res = self.send_webhook(&webhook_payload, &tx_id, &_history_webhook);
        let email_res = self.send_email(&email_payload, &tx_arc, &event_str, &tx_id, &_history_email);

        let (webhook_result, email_result) = try_join!(webhook_res, email_res,)?;

        // Update status
        if let Some(hw) = webhook_result {
            let _ = self.repo.mark_delivered(hw.id).await;
        }
        if let Some(he) = email_result {
            let _ = self.repo.mark_delivered(he.id).await;
        }

        info!(tx_id = %tx_id, event = %event_str, "Notification dispatched");
        Ok(())
    }

    async fn send_webhook(
        &self,
        payload: &str,
        tx_id: &Uuid,
        history: &NotificationHistory,
    ) -> Result<Option<NotificationHistory>> {
        let mut mac = HmacSha256::new_from_slice(self.webhook_secret.as_bytes())
            .expect("HMAC secret valid");
        mac.update(payload.as_bytes());
        let sig = base64::encode(mac.finalize().into_bytes());

        let res = self.http_client
            .post(&self.partner_webhook_url)
            .header("X-Signature", sig)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await;

        match res {
            Ok(resp) if resp.status().is_success() => {
                info!(tx_id = %tx_id, "Webhook delivered");
                Ok(Some(history.clone()))
            }
            Ok(_) => {
                error!(tx_id = %tx_id, status = %res.unwrap().status(), "Webhook failed");
                let _ = self.repo.mark_failed(history.id, "HTTP error").await;
                Ok(None)
            }
            Err(e) => {
                error!(tx_id = %tx_id, error = %e, "Webhook send failed");
                let _ = self.repo.mark_failed(history.id, &e.to_string()).await;
                Ok(None)
            }
        }
    }

    async fn send_email(
        &self,
        html: &str,
        tx: &Arc<Transaction>,
        event: &str,
        tx_id: &Uuid,
        history: &NotificationHistory,
    ) -> Result<Option<NotificationHistory>> {
        // TODO: Real user email from tx.metadata.user_email
        let email = Mailbox::new(None, "user@example.com".parse().unwrap());
        let from = Mailbox::new(None, self.support_email.parse().unwrap());

        let message = lettre::message::Builder::new()
            .from(from.to_owned())
            .to(email.to_owned())
            .subject(format!("cNGN Mint Update: {}", event))
            .html(html.to_string())?;

        let res = self.smtp.send_raw_message(message.formatted()).await;

        match res {
            Ok(_) => {
                info!(tx_id = %tx_id, "Email delivered");
                Ok(Some(history.clone()))
            }
            Err(e) => {
                error!(tx_id = %tx_id, error = %e, "Email failed");
                let _ = self.repo.mark_failed(history.id, &e.to_string()).await;
                Ok(None)
            }
        }
    }
}

// Backward compat
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NotificationType {
    OfframpCompleted,
    OfframpFailed,
    OfframpRefunded,
    CngnReceived,
}

#[allow(dead_code)]
pub async fn send_notification(tx: &Transaction, notification_type: NotificationType, message: &str) {
    // Legacy logging
    match notification_type {
        // ... same as before
        _ => {}
    }

    pub async fn send_system_alert(&self, alert_id: &str, message: &str) {
        // High-priority system alert for operations, treasury, etc.
        // For now, persistent logging at WARN/ERROR level + placeholder for pager/slack.
        error!(alert_id = %alert_id, "🚨 SYSTEM ALERT: {}", message);
    }
}

