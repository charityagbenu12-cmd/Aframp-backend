//! Multi-Signature Governance Framework
//!
//! Implements M-of-N signing for all high-privilege Stellar treasury operations:
//! Mint, Burn, and SetOptions (signer management / threshold changes).
//!
//! # Architecture
//!
//! ```text
//! Treasury Officer
//!       │
//!       ▼
//! [propose]  ──► multisig_proposals (unsigned_xdr stored)
//!       │
//!       ▼
//! [notify]   ──► Email / Slack / Push to all N signers
//!       │
//!       ▼
//! [sign]     ──► Each signer reviews XDR, submits DecoratedSignature
//!       │         (hardware wallet: Ledger / Trezor)
//!       ▼
//! [threshold met?]
//!   ├── governance change? ──► time_lock_until = NOW() + 48h  (status: time_locked)
//!   └── mint/burn?         ──► status: ready
//!       │
//!       ▼
//! [submit]   ──► Stellar Horizon  (status: submitted → confirmed)
//!       │
//!       ▼
//! [governance_log] ──► every event appended with actor public key + timestamp
//! ```
//!
//! # Acceptance Criteria
//! - Issuing account rejects transactions with fewer than M signatures (enforced on-chain
//!   by Stellar threshold configuration; enforced off-chain by this module before submission).
//! - Signers can view the full transaction XDR before signing.
//! - Governance changes (add/remove signer, change threshold) are time-locked for 48 hours.

pub mod error;
pub mod governance_log;
pub mod handlers;
pub mod models;
pub mod notification;
pub mod repository;
pub mod routes;
pub mod service;
pub mod xdr_builder;

pub use error::MultiSigError;
pub use models::{
    GovernanceLogEntry, MultiSigOpType, MultiSigProposal, MultiSigProposalStatus,
    MultiSigSignature, QuorumConfig,
};
pub use service::MultiSigService;
