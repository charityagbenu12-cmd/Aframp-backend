//! Nostro Account & Liquidity Management
//!
//! Tracks real-time balances of pre-funded foreign accounts (Nostro accounts)
//! held with local partner banks (KCB Kenya, Zenith Ghana, etc.).
//!
//! Features:
//! - Shadow Ledger mirroring actual foreign bank balances
//! - Real-time balance polling (ISO 20022 / MT940)
//! - Low-balance refill alerts to Treasury
//! - End-of-Day reconciliation against on-chain cNGN burns/locks

pub mod models;
pub mod shadow_ledger;
pub mod balance_poller;
pub mod reconciliation;
pub mod repository;
pub mod handlers;

pub use models::{NostroAccount, NostroBalance, CorridorStatus, LiquidityAlert};
pub use shadow_ledger::ShadowLedger;
pub use balance_poller::BalancePoller;
pub use reconciliation::EodReconciliationWorker;
