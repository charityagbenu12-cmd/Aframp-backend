/// Liquidity Monitor — Stellar DEX order-book depth & slippage surveillance.
///
/// Proactively monitors cNGN market health every 60 seconds:
/// - Simulates a configurable-size market buy to measure slippage
/// - Classifies depth as Healthy / Warning / Critical
/// - Triggers rebalancing vault requests via the multi-sig framework
/// - Monitors Stellar AMM constant-product k for pool exhaustion
/// - Sends Discord/Slack alerts within 30 s of detection
pub mod engine;
pub mod handlers;
pub mod routes;
pub mod types;
pub mod worker;
