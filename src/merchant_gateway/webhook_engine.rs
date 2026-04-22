//! High-Speed Webhook Engine with Exponential Backoff
//! Sends cryptographically signed webhooks to merchants

use crate::merchant_gateway::models::*;
use crate::merchant_gateway::repository::WebhookDeliveryRepository;
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// WEBHOOK ENGINE
// ============================================================================

pub struct WebhookEngine {
    webhook_repo: Arc<WebhookDeliveryRepository>,
    http_client: Client,
    max_retries: u32,
    timeout_secs: u64,
}

impl WebhookEngine {
    pub fn new(pool: PgPool) -> Self {
        let timeout_secs = std::env::var("WEBHOOK_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        let http_client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            webhook_repo: Arc::new(WebhookDeliveryRepository::new(pool)),
            http_client,
            max_retries: 5,
            timeout_secs,
        }
    }

    /// Send webhook notification to merchant
    /// Returns immediately after queuing - actual delivery is async
    #[instrument(skip(self, merchant, payment_intent))]
    pub async fn send_webhook(
        &self,
        merchant: &Merchant,
        payment_intent: &MerchantPaymentIntent,
        event_type: &str,
    ) -> Result<Uuid, String> {
        // Determine webhook URL (payment intent override or merchant default)
        let webhook_url = payment_intent
            .callback_url
            .as_ref()
            .or(merchant.webhook_url.as_ref())
            .ok_or_else(|| "No webhook URL configured".to_string())?;

        // Build webhook payload
        let payload = WebhookPayload {
            event_type: event_type.to_string(),
            payment_intent_id: payment_intent.id,
            merchant_reference: payment_intent.merchant_reference.clone(),
            amount_cngn: payment_intent.amount_cngn,
            status: payment_intent.status.clone(),
            stellar_tx_hash: payment_intent.stellar_tx_hash.clone(),
            paid_at: payment_intent.paid_at,
            confirmed_at: payment_intent.confirmed_at,
            metadata: payment_intent.metadata.clone(),
            timestamp: Utc::now(),
        };

        let payload_json = serde_json::to_value(&payload)
            .map_err(|e| format!("Failed to serialize payload: {}", e))?;

        // Generate HMAC signature
        let signature = self.generate_signature(&merchant.webhook_secret, &payload_json)?;

        // Queue webhook delivery
        let webhook_delivery = self
            .webhook_repo
            .create(
                payment_intent.id,
                merchant.id,
                webhook_url,
                event_type,
                payload_json,
                &signature,
            )
            .await
            .map_err(|e| format!("Failed to queue webhook: {}", e))?;

        info!(
            webhook_id = %webhook_delivery.id,
            payment_intent_id = %payment_intent.id,
            merchant_id = %merchant.id,
            event_type = %event_type,
            "Webhook queued for delivery"
        );

        // Trigger immediate delivery attempt (async)
        let engine = self.clone_for_delivery();
        let webhook_id = webhook_delivery.id;
        tokio::spawn(async move {
            if let Err(e) = engine.deliver_webhook(webhook_id).await {
                warn!(webhook_id = %webhook_id, error = %e, "Initial webhook delivery failed");
            }
        });

        Ok(webhook_delivery.id)
    }

    /// Deliver a single webhook (called by worker or immediate delivery)
    #[instrument(skip(self))]
    async fn deliver_webhook(&self, webhook_id: Uuid) -> Result<(), String> {
        // Fetch webhook details
        let webhook = self
            .webhook_repo
            .find_by_id(webhook_id)
            .await
            .map_err(|e| format!("Failed to fetch webhook: {}", e))?
            .ok_or_else(|| "Webhook not found".to_string())?;

        if webhook.status == WebhookStatus::Delivered {
            return Ok(()); // Already delivered
        }

        if webhook.retry_count >= self.max_retries as i32 {
            warn!(webhook_id = %webhook_id, "Webhook abandoned after max retries");
            return Err("Max retries exceeded".to_string());
        }

        // Prepare HTTP request
        let payload_str = serde_json::to_string(&webhook.payload)
            .map_err(|e| format!("Failed to serialize payload: {}", e))?;

        let response = self
            .http_client
            .post(&webhook.webhook_url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Signature", &webhook.signature)
            .header("X-Webhook-Event", &webhook.event_type)
            .header("X-Webhook-Id", webhook_id.to_string())
            .header("X-Webhook-Timestamp", Utc::now().to_rfc3339())
            .body(payload_str)
            .send()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                let response_body = resp
                    .text()
                    .await
                    .unwrap_or_else(|_| "Failed to read response".to_string());

                if status.is_success() {
                    // Success - mark as delivered
                    self.webhook_repo
                        .mark_delivered(webhook_id, status.as_u16() as i32, Some(&response_body))
                        .await
                        .map_err(|e| format!("Failed to mark webhook delivered: {}", e))?;

                    info!(
                        webhook_id = %webhook_id,
                        http_status = status.as_u16(),
                        "Webhook delivered successfully"
                    );
                    Ok(())
                } else {
                    // HTTP error - schedule retry
                    let error_msg = format!("HTTP {}: {}", status.as_u16(), response_body);
                    self.webhook_repo
                        .mark_failed(webhook_id, Some(status.as_u16() as i32), &error_msg)
                        .await
                        .map_err(|e| format!("Failed to mark webhook failed: {}", e))?;

                    warn!(
                        webhook_id = %webhook_id,
                        http_status = status.as_u16(),
                        retry_count = webhook.retry_count + 1,
                        "Webhook delivery failed, will retry"
                    );
                    Err(error_msg)
                }
            }
            Err(e) => {
                // Network error - schedule retry
                let error_msg = format!("Network error: {}", e);
                self.webhook_repo
                    .mark_failed(webhook_id, None, &error_msg)
                    .await
                    .map_err(|e| format!("Failed to mark webhook failed: {}", e))?;

                warn!(
                    webhook_id = %webhook_id,
                    error = %e,
                    retry_count = webhook.retry_count + 1,
                    "Webhook delivery failed, will retry"
                );
                Err(error_msg)
            }
        }
    }

    /// Generate HMAC-SHA256 signature for webhook payload
    fn generate_signature(
        &self,
        secret: &str,
        payload: &serde_json::Value,
    ) -> Result<String, String> {
        let payload_str = serde_json::to_string(payload)
            .map_err(|e| format!("Failed to serialize payload: {}", e))?;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| format!("Invalid HMAC key: {}", e))?;
        mac.update(payload_str.as_bytes());

        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    /// Verify webhook signature (for merchant to use)
    pub fn verify_signature(
        secret: &str,
        payload: &serde_json::Value,
        signature: &str,
    ) -> Result<bool, String> {
        let payload_str = serde_json::to_string(payload)
            .map_err(|e| format!("Failed to serialize payload: {}", e))?;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| format!("Invalid HMAC key: {}", e))?;
        mac.update(payload_str.as_bytes());

        let expected_signature = hex::encode(mac.finalize().into_bytes());
        Ok(expected_signature == signature)
    }

    fn clone_for_delivery(&self) -> Self {
        Self {
            webhook_repo: self.webhook_repo.clone(),
            http_client: self.http_client.clone(),
            max_retries: self.max_retries,
            timeout_secs: self.timeout_secs,
        }
    }
}

// Extension trait for repository
trait WebhookRepositoryExt {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<WebhookDelivery>, crate::database::error::DatabaseError>;
}

impl WebhookRepositoryExt for WebhookDeliveryRepository {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<WebhookDelivery>, crate::database::error::DatabaseError> {
        sqlx::query_as::<_, WebhookDelivery>(
            "SELECT * FROM merchant_webhook_deliveries WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(crate::database::error::DatabaseError::from_sqlx)
    }
}

// Access to pool
trait RepositoryPool {
    fn pool(&self) -> &PgPool;
}

impl RepositoryPool for WebhookDeliveryRepository {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// ============================================================================
// WEBHOOK RETRY WORKER
// ============================================================================

pub struct WebhookRetryWorker {
    webhook_repo: Arc<WebhookDeliveryRepository>,
    webhook_engine: Arc<WebhookEngine>,
    poll_interval_secs: u64,
    batch_size: i64,
}

impl WebhookRetryWorker {
    pub fn new(pool: PgPool, webhook_engine: Arc<WebhookEngine>) -> Self {
        let poll_interval_secs = std::env::var("WEBHOOK_RETRY_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);

        let batch_size = std::env::var("WEBHOOK_RETRY_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);

        Self {
            webhook_repo: Arc::new(WebhookDeliveryRepository::new(pool)),
            webhook_engine,
            poll_interval_secs,
            batch_size,
        }
    }

    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            poll_interval_secs = self.poll_interval_secs,
            batch_size = self.batch_size,
            "Webhook retry worker started"
        );

        let mut ticker = interval(Duration::from_secs(self.poll_interval_secs));
        ticker.tick().await; // Skip first immediate tick

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Webhook retry worker: shutdown signal received");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.process_pending_webhooks().await {
                        error!(error = %e, "Webhook retry cycle failed");
                    }
                }
            }
        }

        info!("Webhook retry worker stopped");
    }

    async fn process_pending_webhooks(&self) -> Result<(), String> {
        let pending = self
            .webhook_repo
            .find_pending_for_retry(self.batch_size)
            .await
            .map_err(|e| format!("Failed to fetch pending webhooks: {}", e))?;

        if pending.is_empty() {
            return Ok(());
        }

        info!(count = pending.len(), "Processing pending webhooks");

        for webhook in pending {
            let engine = self.webhook_engine.clone();
            let webhook_id = webhook.id;
            tokio::spawn(async move {
                if let Err(e) = engine.deliver_webhook(webhook_id).await {
                    warn!(webhook_id = %webhook_id, error = %e, "Webhook retry failed");
                }
            });
        }

        Ok(())
    }
}
