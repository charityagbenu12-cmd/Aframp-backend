//! Reserve Vault module
//!
//! Provides the NGN collateral management layer for cNGN 1:1 backing:
//!
//! - [`provider::BalanceProvider`] — trait abstracting custodian/banking APIs
//! - [`mock_provider::MockBalanceProvider`] — dev/test implementation
//! - [`multisig::MultiSigGuard`] — M-of-N approval for outbound transfers
//! - [`service::VaultService`] — orchestration layer
//! - [`webhook`] — inbound deposit webhook handler (triggers mint lifecycle)

pub mod mock_provider;
pub mod multisig;
pub mod provider;
pub mod service;
pub mod types;
pub mod webhook;

pub use service::VaultService;
pub use types::{
    AccountType, InboundDepositEvent, OutboundTransferRequest, ReserveBalance, VaultError,
    VaultResult,
};
