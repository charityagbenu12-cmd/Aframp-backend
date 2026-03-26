//! DDoS protection and traffic shaping for Aframp.
//!
//! Layers:
//!   - Connection-level: slow HTTP detection, per-IP connection limits
//!   - Request-level: volumetric spike detection, endpoint flood, fingerprinting
//!   - Traffic shaping: fair queuing by consumer tier, WRED, in-flight tx priority
//!   - Challenge-response: proof-of-work for suspected automated sources
//!   - CDN integration: Cloudflare/CloudFront under-attack mode, IP sync
//!   - Emergency lockdown: admin-triggered full lockdown with auto-expiry

pub mod config;
pub mod detector;
pub mod fingerprint;
pub mod queue;
pub mod challenge;
pub mod cdn;
pub mod lockdown;
pub mod middleware;
pub mod admin;
pub mod metrics;
pub mod state;

pub use config::DdosConfig;
pub use state::DdosState;
