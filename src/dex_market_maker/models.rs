use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single order placed on the Stellar DEX.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DexOrder {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Stellar offer ID returned by Horizon.
    pub stellar_offer_id: Option<i64>,
    pub side: OrderSide,
    pub order_type: OrderType,
    /// Price in counter-asset per cNGN.
    pub price: f64,
    /// Amount of cNGN.
    pub amount_cngn: f64,
    pub status: OrderStatus,
    /// Reference price at time of placement.
    pub reference_price: f64,
    /// Ladder rung index (0 = closest to mid).
    pub rung: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "dex_order_side", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OrderSide {
    Bid,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "dex_order_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OrderType {
    /// Stellar passive offer — does not consume existing offers.
    Passive,
    /// Stellar active offer — can cross the book.
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "dex_order_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Open,
    Filled,
    Cancelled,
    Requoted,
}

/// A market-making cycle log entry.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MmCycleLog {
    pub id: Uuid,
    pub cycle_at: DateTime<Utc>,
    pub reference_price: f64,
    pub bid_price: f64,
    pub ask_price: f64,
    pub spread_pct: f64,
    pub orders_placed: i32,
    pub orders_cancelled: i32,
    pub circuit_breaker_tripped: bool,
    pub inventory_cngn: f64,
    pub inventory_counter: f64,
    pub notes: Option<String>,
}

/// Inventory snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    pub cngn: f64,
    pub counter: f64,
}

/// Horizon offer entry (for parsing existing offers).
#[derive(Debug, Deserialize)]
pub struct HorizonOffer {
    pub id: i64,
    pub selling: HorizonAsset,
    pub buying: HorizonAsset,
    pub amount: String,
    pub price: String,
}

#[derive(Debug, Deserialize)]
pub struct HorizonAsset {
    pub asset_type: String,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
}

/// Horizon offers list response.
#[derive(Debug, Deserialize)]
pub struct HorizonOffersResponse {
    #[serde(rename = "_embedded")]
    pub embedded: HorizonOffersEmbedded,
}

#[derive(Debug, Deserialize)]
pub struct HorizonOffersEmbedded {
    pub records: Vec<HorizonOffer>,
}

/// Dashboard summary for the Market Operations Dashboard.
#[derive(Debug, Serialize)]
pub struct MarketMakerStatus {
    pub active: bool,
    pub circuit_breaker_tripped: bool,
    pub last_cycle_at: Option<DateTime<Utc>>,
    pub current_spread_pct: f64,
    pub bid_price: f64,
    pub ask_price: f64,
    pub open_orders: usize,
    pub inventory_cngn: f64,
    pub inventory_counter: f64,
}
