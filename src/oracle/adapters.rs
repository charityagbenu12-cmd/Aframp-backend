//! Price source adapters: Binance, Coinbase, and a Band Protocol stub.

use super::types::RawPrice;
use async_trait::async_trait;
use chrono::Utc;
use tracing::warn;

#[async_trait]
pub trait PriceAdapter: Send + Sync {
    fn name(&self) -> &str;
    async fn fetch(&self, pair: &str) -> Option<RawPrice>;
}

// ── Binance ──────────────────────────────────────────────────────────────────

pub struct BinanceAdapter {
    client: reqwest::Client,
}

impl BinanceAdapter {
    pub fn new() -> Self {
        Self { client: reqwest::Client::new() }
    }
}

#[async_trait]
impl PriceAdapter for BinanceAdapter {
    fn name(&self) -> &str { "binance" }

    async fn fetch(&self, pair: &str) -> Option<RawPrice> {
        // Binance uses XLMUSDT style symbols
        let symbol = pair.replace('/', "");
        let url = format!("https://api.binance.com/api/v3/ticker/price?symbol={}", symbol);
        let resp = self.client.get(&url).send().await.ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        let price: f64 = json["price"].as_str()?.parse().ok()?;
        Some(RawPrice { source: self.name().into(), pair: pair.into(), price, fetched_at: Utc::now() })
    }
}

// ── Coinbase ─────────────────────────────────────────────────────────────────

pub struct CoinbaseAdapter {
    client: reqwest::Client,
}

impl CoinbaseAdapter {
    pub fn new() -> Self {
        Self { client: reqwest::Client::new() }
    }
}

#[async_trait]
impl PriceAdapter for CoinbaseAdapter {
    fn name(&self) -> &str { "coinbase" }

    async fn fetch(&self, pair: &str) -> Option<RawPrice> {
        // Coinbase uses XLM-USD style product IDs
        let product = pair.replace('/', "-");
        let url = format!("https://api.coinbase.com/v2/prices/{}/spot", product);
        let resp = self.client.get(&url).send().await.ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        let price: f64 = json["data"]["amount"].as_str()?.parse().ok()?;
        Some(RawPrice { source: self.name().into(), pair: pair.into(), price, fetched_at: Utc::now() })
    }
}

// ── Band Protocol stub (decentralised oracle) ─────────────────────────────────
// In production this would query a Band Protocol REST endpoint or an on-chain
// reference contract. The stub reads from an env var so it can be driven by
// integration tests or a sidecar without a live chain connection.

pub struct BandProtocolAdapter {
    client: reqwest::Client,
    endpoint: String,
}

impl BandProtocolAdapter {
    pub fn new() -> Self {
        let endpoint = std::env::var("BAND_PROTOCOL_ENDPOINT")
            .unwrap_or_else(|_| "https://laozi1.bandchain.org/api/oracle/v1/request_prices".into());
        Self { client: reqwest::Client::new(), endpoint }
    }
}

#[async_trait]
impl PriceAdapter for BandProtocolAdapter {
    fn name(&self) -> &str { "band_protocol" }

    async fn fetch(&self, pair: &str) -> Option<RawPrice> {
        // Band REST: POST {"symbols":["XLM"],"min_count":3,"ask_count":4}
        let symbol = pair.split('/').next()?;
        let body = serde_json::json!({ "symbols": [symbol], "min_count": 3, "ask_count": 4 });
        let resp = self.client.post(&self.endpoint).json(&body).send().await
            .map_err(|e| warn!(source = "band_protocol", error = %e, "fetch failed"))
            .ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        let price_str = json["price_results"]
            .as_array()?
            .first()?["px"]
            .as_str()?;
        // Band returns price * 1e9
        let raw: f64 = price_str.parse().ok()?;
        let price = raw / 1_000_000_000.0;
        Some(RawPrice { source: self.name().into(), pair: pair.into(), price, fetched_at: Utc::now() })
    }
}
