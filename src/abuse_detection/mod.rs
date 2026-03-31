//! Comprehensive API Abuse Detection and Automated Response System
//!
//! This module implements a multi-layered abuse detection framework that identifies
//! and neutralizes malicious or negligent API usage patterns in real time.
//!
//! ## Detection Categories
//! - Authentication abuse (credential stuffing, brute force, token harvesting, key enumeration)
//! - Endpoint abuse (scraping, quote farming, status polling abuse, error farming)
//! - Transaction abuse (structuring, velocity abuse, round-trip detection, new consumer high value)
//! - Coordinated abuse (multi-consumer coordination, distributed attacks, Sybil detection)
//!
//! ## Response Tiers
//! - Monitor: Log and alert only, no consumer-facing action
//! - Soft: Rate limit tightening, re-authentication required
//! - Hard: Temporary suspension of API keys and tokens
//! - Critical: Immediate revocation, security team notification
//!
//! ## Detection Windows
//! - Short (1 minute): Fast-moving attacks
//! - Medium (1 hour): Sustained abuse patterns
//! - Long (24 hours): Slow and low abuse strategies

pub mod config;
pub mod detector;
pub mod signals;
pub mod response;
pub mod case_management;
pub mod repository;
pub mod middleware;
pub mod handlers;
pub mod metrics;

pub use config::AbuseDetectionConfig;
pub use detector::AbuseDetector;
pub use signals::{DetectionSignal, SignalCategory, DetectionWindow};
pub use response::{ResponseTier, ResponseAction};
pub use case_management::{AbuseCase, AbuseCaseStatus};
