//! Service token manager with proactive rotation

use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

use super::types::{ServiceAuthError, ServiceAuthResult, ServiceTokenClaims};
use crate::metrics::service_auth;

// ── Token cache ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    claims: ServiceTokenClaims,
    expires_at: i64,
}

// ── Token manager ───────────────────────────────────────────────────────────

pub struct ServiceTokenManager {
    service_name: String,
    client_id: String,
    client_secret: String,
    token_endpoint: String,
    http_client: Client,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
    refresh_threshold: f64,
    max_retries: u32,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
}

#[derive(Debug, Clone)]
pub struct TokenRefreshConfig {
    pub refresh_threshold: f64,
    pub max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl Default for TokenRefreshConfig {
    fn default() -> Self {
        Self {
            refresh_threshold: 0.2,
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        }
    }
}

// ── Token endpoint response ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    scope: Option<String>,
}

impl ServiceTokenManager {
    pub fn new(
        service_name: String,
        client_id: String,
        client_secret: String,
        token_endpoint: String,
        config: TokenRefreshConfig,
    ) -> Self {
        Self {
            service_name,
            client_id,
            client_secret,
            token_endpoint,
            http_client: Client::new(),
            cached_token: Arc::new(RwLock::new(None)),
            refresh_threshold: config.refresh_threshold,
            max_retries: config.max_retries,
            initial_backoff_ms: config.initial_backoff_ms,
            max_backoff_ms: config.max_backoff_ms,
        }
    }

    /// Initialize token manager and acquire initial token
    pub async fn initialize(&self) -> ServiceAuthResult<()> {
        info!(
            service_name = %self.service_name,
            "Initializing service token manager"
        );

        self.acquire_token().await?;

        info!(
            service_name = %self.service_name,
            "Service token manager initialized"
        );

        Ok(())
    }

    /// Get current valid token, refreshing if necessary
    pub async fn get_token(&self) -> ServiceAuthResult<String> {
        let token = self.cached_token.read().await;

        if let Some(cached) = token.as_ref() {
            let now = Utc::now().timestamp();
            let lifetime = cached.expires_at - cached.claims.iat;
            let remaining = cached.expires_at - now;

            // Check if token needs refresh
            if remaining as f64 / lifetime as f64 > self.refresh_threshold {
                debug!(
                    service_name = %self.service_name,
                    remaining_secs = %remaining,
                    "Using cached service token"
                );
                return Ok(cached.access_token.clone());
            }

            info!(
                service_name = %self.service_name,
                remaining_secs = %remaining,
                threshold = %self.refresh_threshold,
                "Token below refresh threshold, acquiring new token"
            );
        }

        drop(token); // Release read lock

        // Acquire new token
        self.acquire_token().await?;

        let token = self.cached_token.read().await;
        Ok(token
            .as_ref()
            .expect("Token should exist after acquire")
            .access_token
            .clone())
    }

    /// Acquire a new token via Client Credentials flow
    pub async fn acquire_token(&self) -> ServiceAuthResult<()> {
        let mut attempt = 0;
        let mut backoff_ms = self.initial_backoff_ms;

        loop {
            match self.try_acquire_token().await {
                Ok(()) => {
                    service_auth::token_acquisitions()
                        .with_label_values(&[&self.service_name])
                        .inc();
                    return Ok(());
                }
                Err(e) => {
                    attempt += 1;
                    service_auth::token_refresh_failures()
                        .with_label_values(&[&self.service_name])
                        .inc();

                    if attempt >= self.max_retries {
                        error!(
                            service_name = %self.service_name,
                            attempts = %attempt,
                            error = %e,
                            "Service token acquisition failed after all retries"
                        );
                        return Err(ServiceAuthError::TokenRefreshFailed(format!(
                            "Failed after {} attempts: {}",
                            attempt, e
                        )));
                    }

                    warn!(
                        service_name = %self.service_name,
                        attempt = %attempt,
                        backoff_ms = %backoff_ms,
                        error = %e,
                        "Token acquisition failed, retrying"
                    );

                    sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(self.max_backoff_ms);
                }
            }
        }
    }

    async fn try_acquire_token(&self) -> ServiceAuthResult<()> {
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("scope", "microservice:internal"),
        ];

        let response = self
            .http_client
            .post(&self.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| ServiceAuthError::TokenRefreshFailed(format!("HTTP error: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ServiceAuthError::TokenRefreshFailed(format!(
                "Token endpoint returned {}: {}",
                status, body
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| ServiceAuthError::TokenRefreshFailed(format!("Parse error: {}", e)))?;

        // Decode token to extract claims
        let claims = self.decode_token(&token_response.access_token)?;

        let cached = CachedToken {
            access_token: token_response.access_token,
            expires_at: claims.exp,
            claims,
        };

        *self.cached_token.write().await = Some(cached);

        service_auth::token_refresh_events()
            .with_label_values(&[&self.service_name])
            .inc();

        debug!(
            service_name = %self.service_name,
            expires_in = %token_response.expires_in,
            "Service token acquired"
        );

        Ok(())
    }

    fn decode_token(&self, token: &str) -> ServiceAuthResult<ServiceTokenClaims> {
        // For now, just decode without verification (verification happens at target service)
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(ServiceAuthError::Internal("Invalid JWT format".to_string()));
        }

        let payload = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD)
            .map_err(|e| ServiceAuthError::Internal(format!("Base64 decode error: {}", e)))?;

        serde_json::from_slice(&payload)
            .map_err(|e| ServiceAuthError::Internal(format!("JSON parse error: {}", e)))
    }

    /// Start background refresh task
    pub fn start_refresh_task(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                // Check every 30 seconds
                sleep(Duration::from_secs(30)).await;

                let should_refresh = {
                    let token = self.cached_token.read().await;
                    if let Some(cached) = token.as_ref() {
                        let now = Utc::now().timestamp();
                        let lifetime = cached.expires_at - cached.claims.iat;
                        let remaining = cached.expires_at - now;

                        remaining as f64 / lifetime as f64 <= self.refresh_threshold
                    } else {
                        true // No token, acquire one
                    }
                };

                if should_refresh {
                    if let Err(e) = self.acquire_token().await {
                        error!(
                            service_name = %self.service_name,
                            error = %e,
                            "Background token refresh failed"
                        );
                    }
                }
            }
        });
    }
}
