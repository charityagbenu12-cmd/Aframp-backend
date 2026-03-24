//! Payment provider implementations
//!
//! Concrete implementations of the PaymentProvider trait for different providers.

#[cfg(feature = "database")]
pub mod flutterwave;
#[cfg(feature = "database")]
pub mod mpesa;
#[cfg(feature = "database")]
pub mod paystack;

#[cfg(feature = "database")]
pub mod mock;

#[cfg(feature = "database")]
pub use flutterwave::FlutterwaveProvider;
#[cfg(feature = "database")]
pub use mpesa::MpesaProvider;
#[cfg(feature = "database")]
pub use paystack::PaystackProvider;

#[cfg(all(test, feature = "database"))]
mod tests;
#[cfg(feature = "database")]
pub use mock::MockProvider;
