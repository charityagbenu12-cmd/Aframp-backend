use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OraclePrice {
    pub pair: String,
    pub price: f64,
    pub sources_used: usize,
    pub fetched_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceHealth {
    pub name: String,
    pub healthy: bool,
    pub last_seen: Option<DateTime<Utc>>,
    pub failures: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleState {
    Active,
    PriceFrozen,
}

#[derive(Debug, Clone)]
pub struct RawPrice {
    pub source: String,
    pub pair: String,
    pub price: f64,
    pub fetched_at: DateTime<Utc>,
}
