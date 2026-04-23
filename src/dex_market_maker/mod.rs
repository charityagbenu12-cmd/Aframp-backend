/// DEX Market Maker — cNGN Spread Strategy Engine
///
/// Maintains tight bid-ask spreads on the Stellar DEX for cNGN trading pairs
/// by placing laddered passive/active orders and dynamically re-quoting on
/// price movement. Includes a circuit breaker for toxic-flow detection.
pub mod bot;
pub mod circuit_breaker;
pub mod config;
pub mod models;
pub mod routes;
pub mod handlers;

#[cfg(test)]
mod tests;
