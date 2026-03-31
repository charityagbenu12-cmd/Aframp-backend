//! Corridor Router Service — dynamic route lookup, kill-switch, health tracking.

use crate::corridors::router::models::*;
use crate::corridors::router::repository::CorridorRouterRepository;
use rust_decimal::Decimal;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("corridor not supported: {0} → {1}")]
    NotSupported(String, String),

    #[error("corridor suspended: {0}")]
    Suspended(String),

    #[error("amount {0} below minimum {1}")]
    BelowMinimum(Decimal, Decimal),

    #[error("amount {0} exceeds maximum {1}")]
    ExceedsMaximum(Decimal, Decimal),

    #[error("delivery method '{0}' not supported on this corridor")]
    UnsupportedDeliveryMethod(String),

    #[error("database error: {0}")]
    Database(String),
}

pub struct CorridorRouterService {
    repo: Arc<CorridorRouterRepository>,
}

impl CorridorRouterService {
    pub fn new(repo: Arc<CorridorRouterRepository>) -> Self {
        Self { repo }
    }

    // -----------------------------------------------------------------------
    // Route lookup
    // -----------------------------------------------------------------------

    /// Resolve the best route for a transfer request.
    /// Returns a specific error code when the corridor is unsupported.
    pub async fn resolve_route(
        &self,
        req: &RouteRequest,
    ) -> Result<RouteResponse, RouterError> {
        // 1. Find active corridor.
        let corridor = self
            .repo
            .find_active(
                &req.source_country,
                &req.destination_country,
                &req.source_currency,
                &req.destination_currency,
            )
            .await
            .map_err(|e| RouterError::Database(e.to_string()))?
            .ok_or_else(|| {
                RouterError::NotSupported(
                    req.source_country.clone(),
                    req.destination_country.clone(),
                )
            })?;

        // 2. Validate amount limits.
        if let Some(min) = corridor.min_transfer_amount {
            if req.amount < min {
                return Err(RouterError::BelowMinimum(req.amount, min));
            }
        }
        if let Some(max) = corridor.max_transfer_amount {
            if req.amount > max {
                return Err(RouterError::ExceedsMaximum(req.amount, max));
            }
        }

        // 3. Validate delivery method.
        if let Some(method) = &req.delivery_method {
            if !corridor.delivery_methods.contains(method) {
                return Err(RouterError::UnsupportedDeliveryMethod(method.clone()));
            }
        }

        // 4. Load route hops.
        let hops = self
            .repo
            .get_hops(corridor.id)
            .await
            .map_err(|e| RouterError::Database(e.to_string()))?;

        let required_kyc = corridor.kyc_tier_for_amount(req.amount).to_string();
        let estimated_minutes = corridor.estimated_minutes;

        let route = ResolvedRoute {
            corridor,
            hops,
            estimated_minutes,
        };

        Ok(RouteResponse {
            required_kyc_tier: required_kyc,
            transfer_allowed: true,
            denial_reason: None,
            route,
        })
    }

    // -----------------------------------------------------------------------
    // Admin operations (no restart required)
    // -----------------------------------------------------------------------

    pub async fn create_corridor(
        &self,
        req: &CreateCorridorConfigRequest,
        actor: Option<Uuid>,
        actor_role: Option<&str>,
    ) -> Result<CorridorConfig, RouterError> {
        let corridor = self
            .repo
            .create(req)
            .await
            .map_err(|e| RouterError::Database(e.to_string()))?;

        let _ = self
            .repo
            .write_audit(
                corridor.id,
                "created",
                actor,
                actor_role,
                None,
                serde_json::to_value(&corridor).ok(),
                None,
            )
            .await;

        info!(
            corridor_id = %corridor.id,
            route = %format!("{} → {}", corridor.source_country, corridor.destination_country),
            "New payment corridor created"
        );

        Ok(corridor)
    }

    pub async fn update_corridor(
        &self,
        id: Uuid,
        req: &UpdateCorridorConfigRequest,
        actor: Option<Uuid>,
        actor_role: Option<&str>,
    ) -> Result<CorridorConfig, RouterError> {
        let prev = self
            .repo
            .get_by_id(id)
            .await
            .map_err(|e| RouterError::Database(e.to_string()))?;
        let prev_json = prev.as_ref().and_then(|c| serde_json::to_value(c).ok());

        let updated = self
            .repo
            .update_config(id, req, actor)
            .await
            .map_err(|e| RouterError::Database(e.to_string()))?;

        let _ = self
            .repo
            .write_audit(
                id,
                "updated",
                actor,
                actor_role,
                prev_json,
                serde_json::to_value(&updated).ok(),
                req.reason.as_deref(),
            )
            .await;

        info!(corridor_id = %id, "Corridor config updated");
        Ok(updated)
    }

    /// Kill-switch: instantly pause or resume a corridor.
    pub async fn toggle_corridor(
        &self,
        id: Uuid,
        req: &ToggleCorridorRequest,
        actor_role: Option<&str>,
    ) -> Result<CorridorConfig, RouterError> {
        let prev = self
            .repo
            .get_by_id(id)
            .await
            .map_err(|e| RouterError::Database(e.to_string()))?;
        let prev_json = prev.as_ref().and_then(|c| serde_json::to_value(c).ok());

        let updated = self
            .repo
            .toggle(id, req.enabled, req.reason.clone(), req.updated_by)
            .await
            .map_err(|e| RouterError::Database(e.to_string()))?;

        let action = if req.enabled { "enabled" } else { "kill_switch" };

        let _ = self
            .repo
            .write_audit(
                id,
                action,
                req.updated_by,
                actor_role,
                prev_json,
                serde_json::to_value(&updated).ok(),
                req.reason.as_deref(),
            )
            .await;

        if req.enabled {
            info!(corridor_id = %id, "Corridor enabled");
        } else {
            warn!(
                corridor_id = %id,
                reason = ?req.reason,
                "Corridor kill-switch activated — corridor suspended"
            );
        }

        Ok(updated)
    }

    // -----------------------------------------------------------------------
    // Health
    // -----------------------------------------------------------------------

    pub async fn record_outcome(&self, event: HealthEvent) -> Result<(), RouterError> {
        self.repo
            .record_health_event(&event)
            .await
            .map_err(|e| RouterError::Database(e.to_string()))
    }

    pub async fn get_health(
        &self,
        corridor_id: Uuid,
    ) -> Result<CorridorHealthSummary, RouterError> {
        self.repo
            .get_health_summary(corridor_id)
            .await
            .map_err(|e| RouterError::Database(e.to_string()))
    }

    pub async fn list_corridors(&self) -> Result<Vec<CorridorConfig>, RouterError> {
        self.repo
            .list_all()
            .await
            .map_err(|e| RouterError::Database(e.to_string()))
    }

    pub async fn get_corridor(&self, id: Uuid) -> Result<Option<CorridorConfig>, RouterError> {
        self.repo
            .get_by_id(id)
            .await
            .map_err(|e| RouterError::Database(e.to_string()))
    }
}
