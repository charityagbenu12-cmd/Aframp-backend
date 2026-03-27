//! # Data Classification Framework
//!
//! This module is the single authoritative source for how every category of
//! sensitive data is classified and handled across the Aframp platform.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   Data Classification Framework                  │
//! │                                                                   │
//! │  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
//! │  │   registry   │   │    types     │   │       policy         │ │
//! │  │              │   │              │   │                      │ │
//! │  │  DataField   │──▶│ ClassTier    │──▶│  PolicyEngine        │ │
//! │  │  (every      │   │ DataCategory │   │  HandlingRequirements│ │
//! │  │   field)     │   │ MaskStrategy │   │  TransmissionDecision│ │
//! │  └──────────────┘   └──────────────┘   └──────────────────────┘ │
//! │                                                  │               │
//! │                              ┌───────────────────┘               │
//! │                              ▼                                    │
//! │  ┌──────────────────────────────────────────────────────────┐    │
//! │  │                      enforcer                             │    │
//! │  │  mask_field · sanitize_json · ClassifiedString           │    │
//! │  │  LogSanitizer · guard_transmission                       │    │
//! │  └──────────────────────────────────────────────────────────┘    │
//! │                              │                                    │
//! │                              ▼                                    │
//! │  ┌──────────────────────────────────────────────────────────┐    │
//! │  │                       audit                               │    │
//! │  │  ClassificationAuditRepository · report_violation        │    │
//! │  └──────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick-start
//!
//! ### Check if a field may appear in a log line
//! ```rust,no_run
//! use Bitmesh_backend::data_classification::policy::{
//!     transmission_decision, TransmissionContext, TransmissionDecision,
//! };
//! use Bitmesh_backend::data_classification::registry::DataField;
//!
//! let decision = transmission_decision(DataField::UserEmail, TransmissionContext::LogLine);
//! // → AllowMasked(PartialMask { show_first: 2, show_last: 4 })
//! ```
//!
//! ### Mask a field value for logging
//! ```rust,no_run
//! use Bitmesh_backend::data_classification::enforcer::mask_field;
//! use Bitmesh_backend::data_classification::registry::DataField;
//!
//! let masked = mask_field(
//!     DataField::WalletAddress,
//!     "GABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRS",
//! );
//! // → "GABC****...****PQRS"
//! ```
//!
//! ### Sanitize a JSON payload before logging
//! ```rust,no_run
//! use Bitmesh_backend::data_classification::enforcer::sanitize_json;
//! use Bitmesh_backend::data_classification::policy::TransmissionContext;
//! use serde_json::json;
//!
//! let payload = json!({ "email": "user@example.com", "private_key": "SECRET" });
//! let safe = sanitize_json(payload, TransmissionContext::LogLine);
//! // email → masked, private_key → "[REDACTED]"
//! ```
//!
//! ### Wrap a sensitive value so it can never be accidentally logged
//! ```rust,no_run
//! use Bitmesh_backend::data_classification::enforcer::ClassifiedString;
//! use Bitmesh_backend::data_classification::registry::DataField;
//!
//! let email = ClassifiedString::new("user@example.com", DataField::UserEmail);
//! tracing::info!(email = %email); // logs the masked form automatically
//! ```
//!
//! ## Classification Tiers
//!
//! | Tier | Encrypt at rest | Mask in logs | Audit on access | Never log |
//! |------|----------------|--------------|-----------------|-----------|
//! | Critical | ✓ | ✓ | ✓ | ✓ |
//! | Restricted | ✓ | ✓ | ✓ | ✗ |
//! | Confidential | ✓ | ✓ | ✗ | ✗ |
//! | Internal | ✗ | ✗ | ✗ | ✗ |
//! | Public | ✗ | ✗ | ✗ | ✗ |

pub mod audit;
pub mod enforcer;
pub mod policy;
pub mod registry;
pub mod types;

// Re-export the most commonly used items at the module root for ergonomics.
pub use enforcer::{mask_field, sanitize_json, ClassifiedString, LogSanitizer};
pub use policy::{
    requirements_for_field, transmission_decision, PolicyEngine, TransmissionContext,
    TransmissionDecision,
};
pub use registry::DataField;
pub use types::{ClassificationTier, DataCategory, HandlingRequirements, MaskingStrategy};
