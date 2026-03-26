//! Geo-Restriction Service
//!
//! Handles policy enforcement for geographic restrictions based on IP geolocation.

use crate::cache::RedisCache;
use crate::database::geo_restriction_repository::{
    ConsumerGeoOverride, CountryAccessPolicy, GeoRestrictionRepository, RegionGrouping,
};
use crate::error::AppError;
use crate::services::geolocation::{GeolocationResult, GeolocationService};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Policy enforcement result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyResult {
    Allowed,
    Restricted,
    Blocked,
    RequiresVerification,
}

/// Policy evaluation context
#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub consumer_id: Option<Uuid>,
    pub ip_address: String,
    pub transaction_type: Option<String>,
    pub enhanced_verification: bool,
}

/// Geo-restriction service configuration
#[derive(Debug, Clone)]
pub struct GeoRestrictionConfig {
    pub enable_geo_restriction: bool,
    pub cache_policy_ttl_secs: i64,
    pub audit_all_decisions: bool,
}

impl Default for GeoRestrictionConfig {
    fn default() -> Self {
        Self {
            enable_geo_restriction: true,
            cache_policy_ttl_secs: 3600, // 1 hour
            audit_all_decisions: true,
        }
    }
}

impl GeoRestrictionConfig {
    pub fn from_env() -> Self {
        Self {
            enable_geo_restriction: std::env::var("ENABLE_GEO_RESTRICTION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            cache_policy_ttl_secs: std::env::var("GEO_POLICY_CACHE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            audit_all_decisions: std::env::var("AUDIT_ALL_GEO_DECISIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
        }
    }
}

/// Geo-restriction service
pub struct GeoRestrictionService {
    config: GeoRestrictionConfig,
    repository: Arc<GeoRestrictionRepository>,
    geolocation: Arc<GeolocationService>,
    cache: Arc<RedisCache>,
    policy_cache: Arc<RwLock<HashMap<String, (PolicyResult, i64)>>>,
}

impl GeoRestrictionService {
    pub fn new(
        repository: Arc<GeoRestrictionRepository>,
        geolocation: Arc<GeolocationService>,
        cache: Arc<RedisCache>,
        config: GeoRestrictionConfig,
    ) -> Self {
        Self {
            config,
            repository,
            geolocation,
            cache,
            policy_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Evaluate geo-restriction policy for a request
    pub async fn evaluate_policy(&self, context: &PolicyContext) -> Result<PolicyResult, AppError> {
        if !self.config.enable_geo_restriction {
            return Ok(PolicyResult::Allowed);
        }

        // Resolve geolocation
        let geo_result = self.geolocation.resolve_country(&context.ip_address).await?;

        // Get country code or use default policy
        let country_code = match geo_result.country_code {
            Some(code) => code,
            None => {
                let default_policy = self.geolocation.default_policy_for_unresolvable();
                return self.handle_unresolvable_ip(default_policy, context).await;
            }
        };

        // Check cache first
        let cache_key = self.build_cache_key(&country_code, context);
        if let Some(cached_result) = self.check_policy_cache(&cache_key).await {
            return Ok(cached_result);
        }

        // Evaluate policy hierarchy
        let result = self.evaluate_policy_hierarchy(&country_code, context).await?;

        // Cache the result
        self.cache_policy_result(&cache_key, &result).await;

        // Audit the decision if configured
        if self.config.audit_all_decisions {
            self.audit_decision(&country_code, context, &result, &geo_result).await?;
        }

        Ok(result)
    }

    /// Evaluate policy hierarchy: consumer override > country policy > region policy > default
    async fn evaluate_policy_hierarchy(
        &self,
        country_code: &str,
        context: &PolicyContext,
    ) -> Result<PolicyResult, AppError> {
        // 1. Check consumer-specific override
        if let Some(consumer_id) = context.consumer_id {
            if let Some(override_policy) = self.repository.get_consumer_override(consumer_id, country_code).await? {
                if !override_policy.is_expired() {
                    return self.map_policy_to_result(&override_policy.policy_type, context);
                }
            }
        }

        // 2. Check country-specific policy
        if let Some(country_policy) = self.repository.get_country_policy(country_code).await? {
            return self.map_policy_to_result(&country_policy.policy_type, context);
        }

        // 3. Check region policy
        if let Some(region) = self.get_region_for_country(country_code).await? {
            if let Some(region_policy) = self.repository.get_region_policy(&region.region_code).await? {
                return self.map_policy_to_result(&region_policy.policy_type, context);
            }
        }

        // 4. Default policy
        Ok(PolicyResult::Allowed)
    }

    /// Get region grouping for a country
    async fn get_region_for_country(&self, country_code: &str) -> Result<Option<RegionGrouping>, AppError> {
        self.repository.get_region_for_country(country_code).await
    }

    /// Map policy type string to PolicyResult enum
    fn map_policy_to_result(&self, policy_type: &str, context: &PolicyContext) -> Result<PolicyResult, AppError> {
        match policy_type {
            "allowed" => Ok(PolicyResult::Allowed),
            "restricted" => {
                if context.enhanced_verification {
                    Ok(PolicyResult::RequiresVerification)
                } else {
                    Ok(PolicyResult::Restricted)
                }
            }
            "blocked" => Ok(PolicyResult::Blocked),
            _ => {
                warn!("Unknown policy type: {}, defaulting to allowed", policy_type);
                Ok(PolicyResult::Allowed)
            }
        }
    }

    /// Handle unresolvable IP addresses
    async fn handle_unresolvable_ip(&self, default_policy: &str, context: &PolicyContext) -> Result<PolicyResult, AppError> {
        match default_policy {
            "allowed" => Ok(PolicyResult::Allowed),
            "restricted" => {
                if context.enhanced_verification {
                    Ok(PolicyResult::RequiresVerification)
                } else {
                    Ok(PolicyResult::Restricted)
                }
            }
            "blocked" => Ok(PolicyResult::Blocked),
            _ => Ok(PolicyResult::Allowed),
        }
    }

    /// Build cache key for policy evaluation
    fn build_cache_key(&self, country_code: &str, context: &PolicyContext) -> String {
        format!(
            "geo_policy:{}:{}:{}:{}",
            country_code,
            context.consumer_id.map(|id| id.to_string()).unwrap_or_else(|| "none".to_string()),
            context.transaction_type.as_deref().unwrap_or("none"),
            context.enhanced_verification
        )
    }

    /// Check policy cache
    async fn check_policy_cache(&self, cache_key: &str) -> Option<PolicyResult> {
        let cache = self.policy_cache.read().await;
        if let Some((result, expiry)) = cache.get(cache_key) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            if now < *expiry {
                return Some(result.clone());
            }
        }
        None
    }

    /// Cache policy result
    async fn cache_policy_result(&self, cache_key: &str, result: &PolicyResult) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let expiry = now + self.config.cache_policy_ttl_secs;

        let mut cache = self.policy_cache.write().await;
        cache.insert(cache_key.to_string(), (result.clone(), expiry));
    }

    /// Audit policy decision
    async fn audit_decision(
        &self,
        country_code: &str,
        context: &PolicyContext,
        result: &PolicyResult,
        geo_result: &GeolocationResult,
    ) -> Result<(), AppError> {
        let decision_str = match result {
            PolicyResult::Allowed => "allowed",
            PolicyResult::Restricted => "restricted",
            PolicyResult::Blocked => "blocked",
            PolicyResult::RequiresVerification => "requires_verification",
        };

        self.repository.log_audit_event(
            context.consumer_id,
            &context.ip_address,
            country_code,
            decision_str,
            &format!("Transaction type: {:?}, Enhanced verification: {}", context.transaction_type, context.enhanced_verification),
        ).await?;

        info!(
            consumer_id = ?context.consumer_id,
            ip = %context.ip_address,
            country = %country_code,
            decision = %decision_str,
            "Geo-restriction policy evaluated"
        );

        Ok(())
    }

    /// Clear policy cache (useful after policy updates)
    pub async fn clear_policy_cache(&self) {
        let mut cache = self.policy_cache.write().await;
        cache.clear();
        info!("Geo-restriction policy cache cleared");
    }

    /// Get all country policies (for admin API)
    pub async fn get_all_country_policies(&self) -> Result<Vec<CountryAccessPolicy>, AppError> {
        self.repository.get_all_country_policies().await
    }

    /// Update country policy (for admin API)
    pub async fn update_country_policy(
        &self,
        country_code: &str,
        policy_type: &str,
        updated_by: Uuid,
    ) -> Result<(), AppError> {
        self.repository.update_country_policy(country_code, policy_type, updated_by).await?;
        self.clear_policy_cache().await;
        Ok(())
    }

    /// Create consumer override (for admin API)
    pub async fn create_consumer_override(
        &self,
        consumer_id: Uuid,
        country_code: &str,
        policy_type: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        created_by: Uuid,
    ) -> Result<(), AppError> {
        self.repository.create_consumer_override(
            consumer_id,
            country_code,
            policy_type,
            expires_at,
            created_by,
        ).await?;
        self.clear_policy_cache().await;
        Ok(())
    }

    /// Get consumer overrides (for admin API)
    pub async fn get_consumer_overrides(&self, consumer_id: Uuid) -> Result<Vec<ConsumerGeoOverride>, AppError> {
        self.repository.get_consumer_overrides(consumer_id).await
    }

    /// Delete consumer override (for admin API)
    pub async fn delete_consumer_override(&self, override_id: Uuid) -> Result<(), AppError> {
        self.repository.delete_consumer_override(override_id).await?;
        self.clear_policy_cache().await;
        Ok(())
    }

    /// Cleanup expired overrides (maintenance task)
    pub async fn cleanup_expired_overrides(&self) -> Result<(), AppError> {
        let deleted_count = self.repository.cleanup_expired_overrides().await?;
        if deleted_count > 0 {
            info!("Cleaned up {} expired geo-restriction overrides", deleted_count);
            self.clear_policy_cache().await;
        }
        Ok(())
    }
}