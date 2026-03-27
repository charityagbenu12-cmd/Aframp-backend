//! Adaptive rate limiting and throttling system (Issue #XXX).
//!
//! Dynamically adjusts rate limits in response to real-time platform health
//! signals, consumer behaviour patterns, and detected anomalies.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  AdaptiveRateLimiter                        │
//! │                                                             │
//! │  ┌──────────────┐   ┌──────────────┐   ┌───────────────┐  │
//! │  │ SignalCollector│  │ ModeEngine   │   │ ThrottleEngine│  │
//! │  │ (background) │   │ (transitions)│   │ (per-consumer)│  │
//! │  └──────────────┘   └──────────────┘   └───────────────┘  │
//! │                                                             │
//! │  ┌──────────────┐   ┌──────────────┐                       │
//! │  │ RequestQueue │   │ AdminOverride│                       │
//! │  │ (emergency)  │   │ (manual ctrl)│                       │
//! │  └──────────────┘   └──────────────┘                       │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Adaptation Modes
//!
//! | Mode      | Standard multiplier | High-priority | Non-essential endpoints |
//! |-----------|---------------------|---------------|-------------------------|
//! | Normal    | 1.0 (static limits) | 1.0           | Allowed                 |
//! | Elevated  | 0.5                 | 1.0           | Allowed                 |
//! | Critical  | 0.2 (no burst)      | 1.0           | Throttled               |
//! | Emergency | minimal             | reduced       | 503                     |

pub mod config;
pub mod engine;
pub mod handlers;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod queue;
pub mod repository;
pub mod signals;
pub mod tests;
pub mod worker;

pub use config::AdaptiveRateLimitConfig;
pub use engine::AdaptiveRateLimitEngine;
pub use models::{AdaptationMode, ConsumerPriorityTier, SignalSnapshot};
