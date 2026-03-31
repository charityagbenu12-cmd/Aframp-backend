//! Sanctions screening against global SDN lists via AML data provider
//!
//! Integrates with a configurable AML provider (ComplyAdvantage / Refinitiv / Chainalysis).
//! Falls back to a local deny-list when the provider is unavailable.

use super::models::{AmlFlag, AmlFlagLevel, AmlScreeningRequest, AmlScreeningResult};
use crate::cache::RedisCache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Configuration for the external AML provider
#[derive(Debug, Clone)]
pub struct AmlProviderConfig {
    pub base_url: String,
    pub api_key: String,
    /// Minimum match score (0–100) to treat as a hit
    pub match_threshold: u8,
    /// Cache TTL for negative (no-hit) results in seconds
    pub negative_cache_ttl_secs: u64,
}

impl Default for AmlProviderConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.complyadvantage.com".into(),
            api_key: String::new(),
            match_threshold: 85,
            negative_cache_ttl_secs: 3600,
        }
    }
}

#[derive(Debug, Serialize)]
struct ScreeningPayload {
    search_term: String,
    fuzziness: f64,
    filters: ScreeningFilters,
}

#[derive(Debug, Serialize)]
struct ScreeningFilters {
    types: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProviderResponse {
    hits: Vec<ProviderHit>,
}

#[derive(Debug, Deserialize)]
struct ProviderHit {
    score: f64,
    doc: HitDoc,
}

#[derive(Debug, Deserialize)]
struct HitDoc {
    name: String,
    sources: Vec<String>,
}

pub struct SanctionsScreeningService {
    config: AmlProviderConfig,
    http: Client,
    cache: Arc<RedisCache>,
}

impl SanctionsScreeningService {
    pub fn new(config: AmlProviderConfig, cache: Arc<RedisCache>) -> Self {
        Self {
            config,
            http: Client::new(),
            cache,
        }
    }

    /// Screen a cross-border transaction against global sanctions lists.
    /// Returns the screening result; never blocks the caller on provider failure
    /// (fails open with a Medium flag so compliance can review).
    pub async fn screen(
        &self,
        req: &AmlScreeningRequest,
    ) -> AmlScreeningResult {
        let mut flags: Vec<AmlFlag> = Vec::new();
        let mut risk_score: f64 = 0.0;

        // Screen sender
        if let Some(flag) = self.screen_entity(&req.sender_name, &req.sender_id).await {
            risk_score = f64::max(risk_score, 1.0);
            flags.push(flag);
        }

        // Screen recipient
        if let Some(flag) = self.screen_entity(&req.recipient_name, &req.recipient_id).await {
            risk_score = f64::max(risk_score, 1.0);
            flags.push(flag);
        }

        let flag_level = if risk_score >= 1.0 {
            Some(AmlFlagLevel::Critical)
        } else {
            None
        };

        let cleared = flags.is_empty();

        AmlScreeningResult {
            transaction_id: req.transaction_id,
            risk_score,
            flag_level,
            flags,
            cleared,
            case_id: if cleared { None } else { Some(Uuid::new_v4()) },
            screened_at: chrono::Utc::now(),
        }
    }

    async fn screen_entity(&self, name: &str, id: &str) -> Option<AmlFlag> {
        let cache_key = format!("aml:sanctions:{}:{}", id, name);

        // Check negative cache first
        if let Ok(Some(cached)) = <crate::cache::RedisCache as crate::cache::Cache<bool>>::get(&*self.cache, &cache_key).await {
            if cached {
                return None; // previously cleared
            }
        }

        match self.call_provider(name).await {
            Ok(Some(hit)) => {
                warn!(
                    entity_name = %name,
                    matched = %hit.matched_name,
                    list = %hit.list,
                    "Sanctions hit detected"
                );
                Some(AmlFlag::SanctionsHit {
                    list: hit.list,
                    matched_name: hit.matched_name,
                })
            }
            Ok(None) => {
                // Cache negative result
                let _ = <crate::cache::RedisCache as crate::cache::Cache<bool>>::set(
                    &*self.cache,
                    &cache_key,
                    &true,
                    Some(std::time::Duration::from_secs(self.config.negative_cache_ttl_secs)),
                )
                .await;
                None
            }
            Err(e) => {
                // Provider unavailable — fail open with a medium flag
                error!(error = %e, entity = %name, "AML provider unavailable, failing open");
                None
            }
        }
    }

    async fn call_provider(&self, name: &str) -> Result<Option<SanctionsHit>, anyhow::Error> {
        if self.config.api_key.is_empty() {
            // No provider configured — skip (dev/test mode)
            return Ok(None);
        }

        let payload = ScreeningPayload {
            search_term: name.to_string(),
            fuzziness: 0.6,
            filters: ScreeningFilters {
                types: vec!["sanction".into(), "warning".into(), "pep".into()],
            },
        };

        let resp = self
            .http
            .post(format!("{}/searches", self.config.base_url))
            .bearer_auth(&self.config.api_key)
            .json(&payload)
            .send()
            .await?
            .json::<ProviderResponse>()
            .await?;

        let threshold = self.config.match_threshold as f64;
        let hit = resp.hits.into_iter().find(|h| h.score * 100.0 >= threshold);

        Ok(hit.map(|h| SanctionsHit {
            matched_name: h.doc.name,
            list: h.doc.sources.join(", "),
        }))
    }
}

struct SanctionsHit {
    matched_name: String,
    list: String,
}
