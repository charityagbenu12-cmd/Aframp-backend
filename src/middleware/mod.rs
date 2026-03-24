//! Middleware modules for Aframp backend
//!
//! Provides request/response logging and error handling middleware

#[cfg(feature = "database")]
pub mod logging;

#[cfg(feature = "database")]
pub mod error;

#[cfg(feature = "database")]
pub mod api_key;
