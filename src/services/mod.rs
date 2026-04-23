//! Services module for business logic and integrations

pub mod balance;
#[cfg(feature = "database")]
pub mod bank_verification;
#[cfg(feature = "database")]
pub mod cngn_payment_builder;
#[cfg(feature = "database")]
pub mod cngn_trustline;
#[cfg(feature = "database")]
pub mod conversion_audit;
#[cfg(feature = "database")]
pub mod exchange_rate;
#[cfg(feature = "database")]
pub mod fee_calculation;
#[cfg(feature = "database")]
pub mod fee_structure;
#[cfg(feature = "database")]
pub mod geolocation;
#[cfg(feature = "database")]
pub mod geo_restriction;
#[cfg(feature = "database")]
pub mod geo_restriction_tests;
#[cfg(feature = "database")]
pub mod ip_detection;
#[cfg(feature = "database")]
pub mod key_rotation;
pub mod notification;
pub mod mint_queue;
#[cfg(feature = "database")]
pub mod mint_approval;
#[cfg(feature = "database")]
pub mod mint_sla;
#[cfg(feature = "database")]
pub mod mint_sla_notifier;
#[cfg(feature = "database")]
pub mod mint_timebound_guard;
#[cfg(feature = "database")]
pub mod onramp_quote;
#[cfg(feature = "database")]
pub mod reserve_gatekeeper;
#[cfg(feature = "database")]
pub mod payment_orchestrator;
#[cfg(feature = "database")]
pub mod rate_providers;
#[cfg(feature = "database")]
pub mod transaction;
#[cfg(feature = "database")]
pub mod trustline_operation;
pub mod webhook_processor;
#[cfg(feature = "database")]
pub mod reconciliation;
pub mod transparency;

// Re-export blockchain traits for convenience
#[cfg(feature = "database")]
pub use crate::chains::traits::{
    AggregatedBalance, BlockchainError, BlockchainResult, BlockchainService, ChainHealthStatus,
    ChainType, FeeEstimate, MultiChainBalanceAggregator, TotalBalance, TransactionBuilder,
    TransactionHandler, TransactionResult, TxParams,
};

// Re-export orchestrator types
#[cfg(feature = "database")]
pub use crate::services::payment_orchestrator::{
    OrchestrationState, OrchestratorConfig, OrchestratorError, OrchestratorResult,
    PaymentInitiationRequest, PaymentOrchestrator, ProviderHealth, ProviderMetrics,
    SelectionContext, SelectionStrategy,
};
