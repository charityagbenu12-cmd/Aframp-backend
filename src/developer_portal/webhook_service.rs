use super::models::*;
use super::repositories::{WebhookConfigurationRepository, WebhookDeliveryLogRepository};
use crate::database::error::DatabaseError;
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct WebhookService {
    webhook_config_repo: WebhookConfigurationRepository,
    delivery_log_repo: WebhookDeliveryLogRepository,
}

impl WebhookService {
    pub fn new(
        webhook_config_repo: WebhookConfigurationRepository,
        delivery_log_repo: WebhookDeliveryLogRepository,
    ) -> Self {
        Self {
            webhook_config_repo,
            delivery_log_repo,
        }
    }

    pub async fn create_webhook_configuration(
        &self,
        application_id: Uuid,
        request: CreateWebhookConfigurationRequest,
    ) -> Result<WebhookConfiguration, DeveloperPortalError> {
        let webhook = self
            .webhook_config_repo
            .create(application_id, request)
            .await?;

        info!(
            "Webhook configuration created: {} for application: {}",
            webhook.id, application_id
        );

        Ok(webhook)
    }

    pub async fn get_webhook_configurations(
        &self,
        application_id: Uuid,
    ) -> Result<Vec<WebhookConfiguration>, DeveloperPortalError> {
        let webhooks = self
            .webhook_config_repo
            .find_by_application(application_id)
            .await?;

        Ok(webhooks)
    }

    pub async fn update_webhook_configuration(
        &self,
        webhook_id: Uuid,
        request: UpdateWebhookConfigurationRequest,
    ) -> Result<WebhookConfiguration, DeveloperPortalError> {
        let webhook = self
            .webhook_config_repo
            .update(webhook_id, request)
            .await?;

        info!("Webhook configuration updated: {}", webhook_id);

        Ok(webhook)
    }

    pub async fn delete_webhook_configuration(
        &self,
        webhook_id: Uuid,
    ) -> Result<(), DeveloperPortalError> {
        self.webhook_config_repo.soft_delete(webhook_id).await?;
        info!("Webhook configuration deleted: {}", webhook_id);

        Ok(())
    }

    pub async fn deliver_webhook(
        &self,
        webhook_id: Uuid,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<(), DeveloperPortalError> {
        let webhook = self
            .webhook_config_repo
            .find_by_id(webhook_id)
            .await?
            .ok_or(DeveloperPortalError::WebhookConfigurationNotFound)?;

        // Check if webhook is active and handles this event type
        if webhook.status != "active" || !webhook.events.contains(&event_type.to_string()) {
            return Ok(());
        }

        // Create delivery log entry
        let delivery_log = self
            .delivery_log_repo
            .create(
                webhook_id,
                event_type,
                payload.clone(),
                webhook.webhook_url.clone(),
            )
            .await?;

        // Attempt delivery
        let delivery_result = self
            .attempt_webhook_delivery(&webhook, event_type, &payload)
            .await;

        match delivery_result {
            Ok(_) => {
                self.delivery_log_repo
                    .mark_delivered(delivery_log.id, None, None)
                    .await?;
                info!(
                    "Webhook delivered successfully: {} to {}",
                    event_type, webhook.webhook_url
                );
            }
            Err(e) => {
                self.delivery_log_repo
                    .mark_failed(delivery_log.id, Some(&e.to_string()))
                    .await?;
                error!(
                    "Webhook delivery failed: {} to {} - {}",
                    event_type, webhook.webhook_url, e
                );
            }
        }

        // Update webhook statistics
        self.update_webhook_statistics(webhook_id).await?;

        Ok(())
    }

    pub async fn get_webhook_delivery_logs(
        &self,
        webhook_id: Uuid,
        page: i64,
        per_page: i64,
    ) -> Result<Vec<WebhookDeliveryLog>, DeveloperPortalError> {
        let logs = self
            .delivery_log_repo
            .find_by_webhook(webhook_id, page, per_page)
            .await?;

        Ok(logs)
    }

    pub async fn get_webhook_metrics(
        &self,
        webhook_id: Uuid,
    ) -> Result<WebhookMetrics, DeveloperPortalError> {
        let metrics = self
            .delivery_log_repo
            .get_metrics(webhook_id)
            .await?;

        Ok(metrics)
    }

    async fn attempt_webhook_delivery(
        &self,
        webhook: &WebhookConfiguration,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();
        
        let mut request = client
            .post(&webhook.webhook_url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "Bitmesh-Webhook/1.0")
            .header("X-Webhook-Event", event_type)
            .json(payload);

        // Add signature if secret token is configured
        if let Some(ref secret) = webhook.secret_token {
            let signature = self.generate_signature(payload, secret)?;
            request = request.header("X-Webhook-Signature", signature);
        }

        let response = request.send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(format!("Webhook returned status {}: {}", status, body).into())
        }
    }

    fn generate_signature(
        &self,
        payload: &serde_json::Value,
        secret: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let payload_str = serde_json::to_string(payload)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
        mac.update(payload_str.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        
        Ok(format!("sha256={}", signature))
    }

    async fn update_webhook_statistics(&self, webhook_id: Uuid) -> Result<(), DeveloperPortalError> {
        let metrics = self
            .delivery_log_repo
            .get_metrics(webhook_id)
            .await?;

        let success_rate = if metrics.total_deliveries > 0 {
            (metrics.successful_deliveries as f64 / metrics.total_deliveries as f64) * 100.0
        } else {
            0.0
        };

        let average_latency = if metrics.successful_deliveries > 0 {
            // TODO: Calculate average latency from delivery logs
            0.0
        } else {
            0.0
        };

        self.webhook_config_repo
            .update_statistics(
                webhook_id,
                rust_decimal::Decimal::from_f64_retain(success_rate).unwrap_or_default(),
                average_latency as i32,
                metrics.failed_deliveries as i32,
            )
            .await?;

        Ok(())
    }

    pub async fn retry_failed_webhooks(&self) -> Result<(), DeveloperPortalError> {
        let failed_logs = self
            .delivery_log_repo
            .find_failed_for_retry()
            .await?;

        for log in failed_logs {
            if log.delivery_attempts >= 5 {
                // Max retries reached, mark as permanently failed
                self.delivery_log_repo
                    .mark_failed(log.id, Some("Max retries exceeded"))
                    .await?;
                continue;
            }

            let webhook = self
                .webhook_config_repo
                .find_by_id(log.webhook_configuration_id)
                .await?
                .ok_or(DeveloperPortalError::WebhookConfigurationNotFound)?;

            // Update attempt count and schedule next retry
            self.delivery_log_repo
                .increment_attempts(log.id)
                .await?;

            // TODO: Schedule retry using background job system
            info!(
                "Scheduling webhook retry: {} for webhook: {}",
                log.id, log.webhook_configuration_id
            );
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct WebhookConfigurationRepository {
    pool: Arc<sqlx::PgPool>,
}

impl WebhookConfigurationRepository {
    pub fn new(pool: Arc<sqlx::PgPool>) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        application_id: Uuid,
        request: CreateWebhookConfigurationRequest,
    ) -> Result<WebhookConfiguration, DeveloperPortalError> {
        let webhook = sqlx::query_as!(
            WebhookConfiguration,
            r#"
            INSERT INTO webhook_configurations (
                application_id, webhook_url, secret_token, events
            ) VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
            application_id,
            request.webhook_url,
            request.secret_token,
            &request.events
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(webhook)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<WebhookConfiguration>, DeveloperPortalError> {
        let webhook = sqlx::query_as!(
            WebhookConfiguration,
            "SELECT * FROM webhook_configurations WHERE id = $1",
            id
        )
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(webhook)
    }

    pub async fn find_by_application(
        &self,
        application_id: Uuid,
    ) -> Result<Vec<WebhookConfiguration>, DeveloperPortalError> {
        let webhooks = sqlx::query_as!(
            WebhookConfiguration,
            "SELECT * FROM webhook_configurations WHERE application_id = $1 AND status != 'deleted' ORDER BY created_at DESC",
            application_id
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(webhooks)
    }

    pub async fn update(
        &self,
        webhook_id: Uuid,
        request: UpdateWebhookConfigurationRequest,
    ) -> Result<WebhookConfiguration, DeveloperPortalError> {
        let webhook = sqlx::query_as!(
            WebhookConfiguration,
            r#"
            UPDATE webhook_configurations 
            SET webhook_url = COALESCE($1, webhook_url),
                secret_token = COALESCE($2, secret_token),
                events = COALESCE($3, events),
                updated_at = now()
            WHERE id = $4
            RETURNING *
            "#,
            request.webhook_url,
            request.secret_token,
            request.events.as_ref(),
            webhook_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(webhook)
    }

    pub async fn soft_delete(&self, webhook_id: Uuid) -> Result<WebhookConfiguration, DeveloperPortalError> {
        let webhook = sqlx::query_as!(
            WebhookConfiguration,
            r#"
            UPDATE webhook_configurations 
            SET status = 'deleted',
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
            webhook_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(webhook)
    }

    pub async fn update_statistics(
        &self,
        webhook_id: Uuid,
        success_rate: rust_decimal::Decimal,
        average_latency: i32,
        failed_count: i32,
    ) -> Result<(), DeveloperPortalError> {
        sqlx::query!(
            r#"
            UPDATE webhook_configurations 
            SET delivery_success_rate = $1,
                average_delivery_latency = $2,
                failed_delivery_count = $3,
                updated_at = now()
            WHERE id = $4
            "#,
            success_rate,
            average_latency,
            failed_count,
            webhook_id
        )
        .execute(self.pool.as_ref())
        .await?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct WebhookDeliveryLogRepository {
    pool: Arc<sqlx::PgPool>,
}

impl WebhookDeliveryLogRepository {
    pub fn new(pool: Arc<sqlx::PgPool>) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        webhook_configuration_id: Uuid,
        event_type: &str,
        payload: serde_json::Value,
        delivery_url: String,
    ) -> Result<WebhookDeliveryLog, DeveloperPortalError> {
        let log = sqlx::query_as!(
            WebhookDeliveryLog,
            r#"
            INSERT INTO webhook_delivery_logs (
                webhook_configuration_id, event_type, payload, delivery_url
            ) VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
            webhook_configuration_id,
            event_type,
            payload,
            delivery_url
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(log)
    }

    pub async fn find_by_webhook(
        &self,
        webhook_id: Uuid,
        page: i64,
        per_page: i64,
    ) -> Result<Vec<WebhookDeliveryLog>, DeveloperPortalError> {
        let offset = (page - 1) * per_page;

        let logs = sqlx::query_as!(
            WebhookDeliveryLog,
            "SELECT * FROM webhook_delivery_logs WHERE webhook_configuration_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            webhook_id,
            per_page,
            offset
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(logs)
    }

    pub async fn mark_delivered(
        &self,
        log_id: Uuid,
        http_status_code: Option<i32>,
        response_body: Option<String>,
    ) -> Result<WebhookDeliveryLog, DeveloperPortalError> {
        let log = sqlx::query_as!(
            WebhookDeliveryLog,
            r#"
            UPDATE webhook_delivery_logs 
            SET status = 'delivered',
                http_status_code = $1,
                response_body = $2,
                delivered_at = now(),
                updated_at = now()
            WHERE id = $3
            RETURNING *
            "#,
            http_status_code,
            response_body,
            log_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(log)
    }

    pub async fn mark_failed(
        &self,
        log_id: Uuid,
        error_message: Option<String>,
    ) -> Result<WebhookDeliveryLog, DeveloperPortalError> {
        let log = sqlx::query_as!(
            WebhookDeliveryLog,
            r#"
            UPDATE webhook_delivery_logs 
            SET status = 'failed',
                error_message = $1,
                updated_at = now()
            WHERE id = $2
            RETURNING *
            "#,
            error_message,
            log_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(log)
    }

    pub async fn increment_attempts(&self, log_id: Uuid) -> Result<WebhookDeliveryLog, DeveloperPortalError> {
        let log = sqlx::query_as!(
            WebhookDeliveryLog,
            r#"
            UPDATE webhook_delivery_logs 
            SET delivery_attempts = delivery_attempts + 1,
                status = 'retrying',
                next_retry_at = now() + interval '5 minutes',
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
            log_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(log)
    }

    pub async fn find_failed_for_retry(&self) -> Result<Vec<WebhookDeliveryLog>, DeveloperPortalError> {
        let logs = sqlx::query_as!(
            WebhookDeliveryLog,
            r#"
            SELECT * FROM webhook_delivery_logs 
            WHERE status = 'retrying' 
            AND next_retry_at <= now()
            AND delivery_attempts < 5
            ORDER BY next_retry_at ASC
            LIMIT 100
            "#
        )
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(logs)
    }

    pub async fn get_metrics(&self, webhook_id: Uuid) -> Result<WebhookMetrics, DeveloperPortalError> {
        let metrics = sqlx::query!(
            r#"
            SELECT 
                COUNT(*) as total_count,
                COUNT(CASE WHEN status = 'delivered' THEN 1 END) as successful_count,
                COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_count,
                COUNT(CASE WHEN status = 'pending' OR status = 'retrying' THEN 1 END) as pending_count
            FROM webhook_delivery_logs 
            WHERE webhook_configuration_id = $1
            "#,
            webhook_id
        )
        .fetch_one(self.pool.as_ref())
        .await?;

        let total_count = metrics.total_count.unwrap_or(0) as i64;
        let successful_count = metrics.successful_count.unwrap_or(0) as i64;
        let failed_count = metrics.failed_count.unwrap_or(0) as i64;
        let pending_count = metrics.pending_count.unwrap_or(0) as i64;

        let success_rate = if total_count > 0 {
            (successful_count as f64 / total_count as f64) * 100.0
        } else {
            0.0
        };

        // TODO: Calculate average latency from delivered logs
        let average_latency = 0.0;

        Ok(WebhookMetrics {
            total_deliveries: total_count,
            successful_deliveries: successful_count,
            failed_deliveries: failed_count,
            success_rate,
            average_latency,
            pending_deliveries: pending_count,
        })
    }
}
