//! Unit tests for payment provider adapters.
//!
//! All tests use wiremock to intercept HTTP calls — no real network requests are made.

#[cfg(feature = "database")]
pub mod flutterwave_tests;
#[cfg(feature = "database")]
pub mod mpesa_tests;
#[cfg(feature = "database")]
pub mod paystack_tests;
#[cfg(feature = "database")]
pub mod shared_error_tests;
