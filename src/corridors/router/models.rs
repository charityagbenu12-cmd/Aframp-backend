//! Domain models for the Payment Corridor Router.

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Re-export compliance registry status types
// ---------------------------------------------------------------------------
pub use crate::compliance_registry::models::CorridorStatus;

// ---------------------------------------------------------------------------
// Core corridor config
// ---------------------------------------------------------------------------

/// Full corridor definition including routing metadata.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CorridorConfig {
    pub id: Uuid,
    pub source_country: String,
    pub destination_country: String,
    pub source_currency: String,
    pub destination_currency: String,
    pub status: CorridorStatus,
    pub status_reason: Option<String>,
    // Routing metadata
    pub min_transfer_amount: Option<Decimal>,
    pub max_transfer_amount: Option<Decimal>,
    pub delivery_methods: Vec<String>,
    pub bridge_asset: Option<String>,
    pub risk_score: i16,
    pub required_kyc_tier: String,
    pub display_name: Option<String>,
    pub estimated_minutes: Option<i32>,
    pub is_featured: bool,
    pub config: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

impl CorridorConfig {
    pub fn is_active(&self) -> bool {
        self.status.is_open()
    }

    /// Determine required KYC tier based on risk score.
    pub fn kyc_tier_for_amount(&self, amount: Decimal) -> &str {
        // High-risk corridors or large amounts require enhanced KYC.
        if self.risk_score >= 70 {
            return "enhanced";
        }
        if let Some(max) = self.max_transfer_amount {
            if amount > max / Decimal::new(2, 0) {
                return "standard";
            }
        }
        &self.required_kyc_tier
    }
}

/// A single hop in the asset conversion path.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RouteHop {
    pub id: Uuid,
    pub corridor_id: Uuid,
    pub hop_order: i16,
    pub from_asset: String,
    pub to_asset: String,
    pub provider: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Resolved route for a transaction — corridor + ordered hops.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedRoute {
    pub corridor: CorridorConfig,
    pub hops: Vec<RouteHop>,
    /// Estimated total settlement time in minutes.
    pub estimated_minutes: Option<i32>,
}

// ---------------------------------------------------------------------------
// Health tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CorridorHealthBucket {
    pub id: Uuid,
    pub corridor_id: Uuid,
    pub bucket_start: DateTime<Utc>,
    pub total_attempts: i32,
    pub successful: i32,
    pub failed: i32,
    pub avg_latency_ms: Option<i32>,
    pub p95_latency_ms: Option<i32>,
    pub total_volume: Decimal,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CorridorHealthBucket {
    pub fn success_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            return 1.0;
        }
        self.successful as f64 / self.total_attempts as f64
    }

    pub fn failure_rate(&self) -> f64 {
        1.0 - self.success_rate()
    }
}

/// Aggregated health summary for a corridor.
#[derive(Debug, Clone, Serialize)]
pub struct CorridorHealthSummary {
    pub corridor_id: Uuid,
    pub display_name: Option<String>,
    pub status: CorridorStatus,
    pub last_24h_success_rate: f64,
    pub last_24h_total: i64,
    pub last_24h_volume: Decimal,
    pub avg_latency_ms: Option<i32>,
    pub is_healthy: bool,
}

// ---------------------------------------------------------------------------
// Request / Response DTOs
// ---------------------------------------------------------------------------

/// Create a new corridor (admin).
#[derive(Debug, Deserialize)]
pub struct CreateCorridorConfigRequest {
    pub source_country: String,
    pub destination_country: String,
    pub source_currency: String,
    pub destination_currency: String,
    pub min_transfer_amount: Option<Decimal>,
    pub max_transfer_amount: Option<Decimal>,
    pub delivery_methods: Vec<String>,
    pub bridge_asset: Option<String>,
    pub risk_score: Option<i16>,
    pub required_kyc_tier: Option<String>,
    pub display_name: Option<String>,
    pub estimated_minutes: Option<i32>,
    pub is_featured: Option<bool>,
    pub config: Option<serde_json::Value>,
}

/// Update corridor routing metadata (admin, no restart needed).
#[derive(Debug, Deserialize)]
pub struct UpdateCorridorConfigRequest {
    pub min_transfer_amount: Option<Decimal>,
    pub max_transfer_amount: Option<Decimal>,
    pub delivery_methods: Option<Vec<String>>,
    pub bridge_asset: Option<String>,
    pub risk_score: Option<i16>,
    pub required_kyc_tier: Option<String>,
    pub display_name: Option<String>,
    pub estimated_minutes: Option<i32>,
    pub is_featured: Option<bool>,
    pub config: Option<serde_json::Value>,
    pub reason: Option<String>,
}

/// Kill-switch / enable request.
#[derive(Debug, Deserialize)]
pub struct ToggleCorridorRequest {
    pub enabled: bool,
    pub reason: Option<String>,
    pub updated_by: Option<Uuid>,
}

/// Route lookup request.
#[derive(Debug, Deserialize)]
pub struct RouteRequest {
    pub source_country: String,
    pub destination_country: String,
    pub source_currency: String,
    pub destination_currency: String,
    pub amount: Decimal,
    pub delivery_method: Option<String>,
}

/// Route lookup response.
#[derive(Debug, Serialize)]
pub struct RouteResponse {
    pub route: ResolvedRoute,
    pub required_kyc_tier: String,
    pub transfer_allowed: bool,
    pub denial_reason: Option<String>,
}

/// Error returned when no route exists for a country pair.
#[derive(Debug, Serialize)]
pub struct UnsupportedCorridorError {
    pub code: &'static str,
    pub message: String,
    pub source_country: String,
    pub destination_country: String,
}

impl UnsupportedCorridorError {
    pub fn new(src: &str, dst: &str) -> Self {
        Self {
            code: "CORRIDOR_NOT_SUPPORTED",
            message: format!(
                "No active payment corridor exists for {} → {}",
                src, dst
            ),
            source_country: src.to_string(),
            destination_country: dst.to_string(),
        }
    }
}

/// Health event recorded after each transaction attempt.
#[derive(Debug)]
pub struct HealthEvent {
    pub corridor_id: Uuid,
    pub success: bool,
    pub latency_ms: Option<i32>,
    pub amount: Decimal,
}
