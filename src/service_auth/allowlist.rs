//! Service call allowlist management

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;

use super::types::{ServiceAuthError, ServiceAuthResult};
use crate::cache::{Cache, RedisCache};

// ── Allowlist entry ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub calling_service: String,
    pub target_endpoint: String,
    pub allowed: bool,
}

// ── Service allowlist ────────────────────────────────────────────────────────

pub struct ServiceAllowlist {
    pool: Arc<PgPool>,
    cache: Arc<RedisCache>,
    /// In-memory cache: calling_service -> (endpoint_pattern -> allowed)
    memory_cache: Arc<RwLock<HashMap<String, HashMap<String, bool>>>>,
}

impl ServiceAllowlist {
    pub fn new(pool: Arc<PgPool>, cache: Arc<RedisCache>) -> Self {
        Self {
            pool,
            cache,
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if a service is allowed to call an endpoint
    pub async fn is_allowed(
        &self,
        calling_service: &str,
        target_endpoint: &str,
    ) -> ServiceAuthResult<bool> {
        // Check memory cache first
        {
            let cache = self.memory_cache.read().await;
            if let Some(service_rules) = cache.get(calling_service) {
                if let Some(allowed) = self.match_endpoint(service_rules, target_endpoint) {
                    debug!(
                        calling_service = %calling_service,
                        target_endpoint = %target_endpoint,
                        allowed = %allowed,
                        "Allowlist check (memory cache hit)"
                    );
                    return Ok(allowed);
                }
            }
        }

        // Check Redis cache
        let cache_key = format!("service_allowlist:{}", calling_service);
        if let Ok(Some(cached)) = self.cache.get::<HashMap<String, bool>>(&cache_key).await {
            if let Some(allowed) = self.match_endpoint(&cached, target_endpoint) {
                // Update memory cache
                self.memory_cache
                    .write()
                    .await
                    .insert(calling_service.to_string(), cached);

                debug!(
                    calling_service = %calling_service,
                    target_endpoint = %target_endpoint,
                    allowed = %allowed,
                    "Allowlist check (Redis cache hit)"
                );
                return Ok(allowed);
            }
        }

        // Load from database
        let rules = self.load_service_rules(calling_service).await?;

        // Cache in Redis (5 minute TTL)
        let _ = self.cache.set(&cache_key, &rules, 300).await;

        // Cache in memory
        self.memory_cache
            .write()
            .await
            .insert(calling_service.to_string(), rules.clone());

        let allowed = self.match_endpoint(&rules, target_endpoint).unwrap_or(false);

        debug!(
            calling_service = %calling_service,
            target_endpoint = %target_endpoint,
            allowed = %allowed,
            "Allowlist check (database)"
        );

        Ok(allowed)
    }

    /// Add or update an allowlist entry
    pub async fn set_permission(
        &self,
        calling_service: &str,
        target_endpoint: &str,
        allowed: bool,
    ) -> ServiceAuthResult<()> {
        let now = Utc::now();

        sqlx::query!(
            r#"
            INSERT INTO service_call_allowlist (calling_service, target_endpoint, allowed, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $4)
            ON CONFLICT (calling_service, target_endpoint)
            DO UPDATE SET allowed = $3, updated_at = $4
            "#,
            calling_service,
            target_endpoint,
            allowed,
            now,
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        // Invalidate caches
        self.invalidate_cache(calling_service).await;

        info!(
            calling_service = %calling_service,
            target_endpoint = %target_endpoint,
            allowed = %allowed,
            "Service allowlist updated"
        );

        Ok(())
    }

    /// Remove an allowlist entry
    pub async fn remove_permission(
        &self,
        calling_service: &str,
        target_endpoint: &str,
    ) -> ServiceAuthResult<()> {
        sqlx::query!(
            "DELETE FROM service_call_allowlist WHERE calling_service = $1 AND target_endpoint = $2",
            calling_service,
            target_endpoint,
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        // Invalidate caches
        self.invalidate_cache(calling_service).await;

        info!(
            calling_service = %calling_service,
            target_endpoint = %target_endpoint,
            "Service allowlist entry removed"
        );

        Ok(())
    }

    /// List all allowlist entries for a service
    pub async fn list_permissions(
        &self,
        calling_service: &str,
    ) -> ServiceAuthResult<Vec<AllowlistEntry>> {
        let rows = sqlx::query!(
            r#"
            SELECT calling_service, target_endpoint, allowed
            FROM service_call_allowlist
            WHERE calling_service = $1
            ORDER BY target_endpoint
            "#,
            calling_service
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| AllowlistEntry {
                calling_service: row.calling_service,
                target_endpoint: row.target_endpoint,
                allowed: row.allowed,
            })
            .collect())
    }

    /// List all allowlist entries
    pub async fn list_all(&self) -> ServiceAuthResult<Vec<AllowlistEntry>> {
        let rows = sqlx::query!(
            r#"
            SELECT calling_service, target_endpoint, allowed
            FROM service_call_allowlist
            ORDER BY calling_service, target_endpoint
            "#
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| AllowlistEntry {
                calling_service: row.calling_service,
                target_endpoint: row.target_endpoint,
                allowed: row.allowed,
            })
            .collect())
    }

    // ── Helper methods ───────────────────────────────────────────────────────

    async fn load_service_rules(
        &self,
        calling_service: &str,
    ) -> ServiceAuthResult<HashMap<String, bool>> {
        let rows = sqlx::query!(
            "SELECT target_endpoint, allowed FROM service_call_allowlist WHERE calling_service = $1",
            calling_service
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| ServiceAuthError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| (row.target_endpoint, row.allowed))
            .collect())
    }

    fn match_endpoint(&self, rules: &HashMap<String, bool>, endpoint: &str) -> Option<bool> {
        // Exact match first
        if let Some(&allowed) = rules.get(endpoint) {
            return Some(allowed);
        }

        // Pattern matching (supports wildcards)
        for (pattern, &allowed) in rules {
            if self.matches_pattern(pattern, endpoint) {
                return Some(allowed);
            }
        }

        None
    }

    fn matches_pattern(&self, pattern: &str, endpoint: &str) -> bool {
        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len() - 2];
            endpoint.starts_with(prefix)
        } else if pattern.contains('*') {
            // Simple glob matching
            let parts: Vec<&str> = pattern.split('*').collect();
            let mut pos = 0;
            for (i, part) in parts.iter().enumerate() {
                if i == 0 {
                    if !endpoint.starts_with(part) {
                        return false;
                    }
                    pos = part.len();
                } else if i == parts.len() - 1 {
                    if !endpoint.ends_with(part) {
                        return false;
                    }
                } else if let Some(idx) = endpoint[pos..].find(part) {
                    pos += idx + part.len();
                } else {
                    return false;
                }
            }
            true
        } else {
            pattern == endpoint
        }
    }

    async fn invalidate_cache(&self, calling_service: &str) {
        // Remove from memory cache
        self.memory_cache.write().await.remove(calling_service);

        // Remove from Redis
        let cache_key = format!("service_allowlist:{}", calling_service);
        let _ = self.cache.delete(&cache_key).await;
    }
}

// ── Repository for admin endpoints ───────────────────────────────────────────

pub struct ServiceAllowlistRepository {
    allowlist: Arc<ServiceAllowlist>,
}

impl ServiceAllowlistRepository {
    pub fn new(allowlist: Arc<ServiceAllowlist>) -> Self {
        Self { allowlist }
    }

    pub async fn add_permission(
        &self,
        calling_service: &str,
        target_endpoint: &str,
    ) -> ServiceAuthResult<()> {
        self.allowlist
            .set_permission(calling_service, target_endpoint, true)
            .await
    }

    pub async fn remove_permission(
        &self,
        calling_service: &str,
        target_endpoint: &str,
    ) -> ServiceAuthResult<()> {
        self.allowlist
            .remove_permission(calling_service, target_endpoint)
            .await
    }

    pub async fn deny_permission(
        &self,
        calling_service: &str,
        target_endpoint: &str,
    ) -> ServiceAuthResult<()> {
        self.allowlist
            .set_permission(calling_service, target_endpoint, false)
            .await
    }

    pub async fn list_all(&self) -> ServiceAuthResult<Vec<AllowlistEntry>> {
        self.allowlist.list_all().await
    }

    pub async fn list_for_service(
        &self,
        calling_service: &str,
    ) -> ServiceAuthResult<Vec<AllowlistEntry>> {
        self.allowlist.list_permissions(calling_service).await
    }
}
