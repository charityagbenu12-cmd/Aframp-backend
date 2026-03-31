/// Treasury Emergency Intervention Framework
///
/// Provides the "Lender of Last Resort" tooling for the Treasury team:
/// - One-click market buy/sell on the Stellar DEX
/// - Hardware-token (YubiKey) authorization
/// - Tamper-evident Crisis Report generation
/// - Automatic revert to Normal Mode once peg is stable
pub mod engine;
pub mod handlers;
pub mod routes;
pub mod types;
