//! Logging and tracing configuration for Aframp backend
//!
//! Provides structured logging with JSON formatting in production and
//! human-readable output in development. Includes sensitive data redaction
//! and environment-based log level configuration.

#[cfg(feature = "database")]
use std::env;
#[cfg(feature = "database")]
use tracing::Level;
#[cfg(feature = "database")]
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

/// Environment types for logging configuration
#[cfg(feature = "database")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

#[cfg(feature = "database")]
impl Environment {
    /// Detect environment from ENV variable
    pub fn from_env() -> Self {
        match env::var("ENVIRONMENT")
            .or_else(|_| env::var("ENV"))
            .unwrap_or_else(|_| "development".to_string())
            .to_lowercase()
            .as_str()
        {
            "prod" | "production" => Self::Production,
            "staging" | "stage" => Self::Staging,
            _ => Self::Development,
        }
    }

    /// Get default log level for environment
    pub fn default_log_level(&self) -> Level {
        match self {
            Self::Development => Level::DEBUG,
            Self::Staging => Level::INFO,
            Self::Production => Level::INFO,
        }
    }

    /// Check if running in production
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }
}

/// Initialize the tracing subscriber with appropriate formatting
///
/// # Environment Variables
/// - `ENVIRONMENT` or `ENV`: Set to "production", "staging", or "development"
/// - `RUST_LOG`: Override log level (e.g., "info", "debug", "warn")
/// - `LOG_FORMAT`: Force format to "json" or "pretty"
///
/// # Examples
/// ```no_run
/// # use aframp::logging::init_tracing;
/// // Initialize with default settings based on environment
/// init_tracing();
/// ```
#[cfg(feature = "database")]
pub fn init_tracing() {
    let environment = Environment::from_env();

    // JSON-only logging to ensure structured output in all environments
    let use_json = true;

    // Build the environment filter
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| {
            // Default filter: info level for our app, warn for dependencies
            EnvFilter::try_new(format!(
                "{}={},tower_http=debug,axum=debug,sqlx=warn,hyper=warn,reqwest=warn",
                env!("CARGO_PKG_NAME").replace('-', "_"),
                environment.default_log_level()
            ))
        })
        .unwrap();

    if use_json {
        // JSON formatting for production (machine-readable)
        let json_layer = fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_target(true)
            .with_level(true)
            .with_file(false)
            .with_line_number(false)
            .with_filter(env_filter);

        tracing_subscriber::registry().with(json_layer).init();
    } else {
        // Pretty formatting for development (human-readable)
        let pretty_layer = fmt::layer()
            .pretty()
            .with_target(true)
            .with_level(true)
            .with_file(true)
            .with_line_number(true)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_span_events(FmtSpan::CLOSE)
            .with_filter(env_filter);

        tracing_subscriber::registry().with(pretty_layer).init();
    }

    tracing::info!(
        environment = ?environment,
        format = if use_json { "json" } else { "pretty" },
        "Tracing initialized"
    );
}

/// Mask sensitive parts of a wallet address for logging
///
/// Shows first 4 and last 4 characters, masks the rest
///
/// # Examples
/// ```
/// # #[cfg(feature = "database")]
/// # use aframp::logging::mask_wallet_address;
/// # #[cfg(feature = "database")]
/// # {
/// let address = "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
/// let masked = mask_wallet_address(address);
/// assert_eq!(masked, "GXXX...XXXX");
/// # }
/// ```
#[cfg(feature = "database")]
pub fn mask_wallet_address(address: &str) -> String {
    if address.len() <= 8 {
        return "****".to_string();
    }
    format!("{}...{}", &address[..4], &address[address.len() - 4..])
}

/// Redact sensitive fields from JSON-like structures.
/// Delegates to the masking engine for consistent behaviour.
#[cfg(feature = "database")]
pub fn redact_sensitive_data(text: &str) -> String {
    // Try to parse as JSON and use the engine; fall back to pattern scanner.
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(text) {
        crate::masking::engine::mask_json_value(&mut v);
        return v.to_string();
    }
    // Unstructured string — use pattern scanner.
    let (sanitised, _) = crate::masking::patterns::scan_and_redact(text);
    sanitised
}

/// Log a transaction event with full AFRI context
///
/// This is a convenience macro for logging AFRI-related operations with
/// consistent structure and required fields.
///
/// # Examples
/// ```no_run
/// # #[cfg(feature = "database")]
/// # use aframp::log_transaction;
/// # #[cfg(feature = "database")]
/// # {
/// log_transaction!(
///     event = "afri_purchase",
///     transaction_id = "tx_123",
///     wallet = "GXXX...XXX",
///     amount = 100.0,
///     currency = "NGN",
///     fiat_amount = 50000.0,
/// );
/// # }
/// ```
#[cfg(feature = "database")]
#[macro_export]
macro_rules! log_transaction {
    ($($key:tt = $value:expr),* $(,)?) => {
        tracing::info!(
            event_type = "transaction",
            $($key = tracing::field::debug(&$value)),*
        );
    };
}

/// Log a performance metric
///
/// Use this to track operation durations and identify bottlenecks
///
/// # Examples
/// ```no_run
/// # #[cfg(feature = "database")]
/// # use aframp::log_performance;
/// # #[cfg(feature = "database")]
/// # {
/// log_performance!(
///     operation = "database_query",
///     duration_ms = 145,
///     query = "SELECT * FROM wallets",
/// );
/// # }
/// ```
#[cfg(feature = "database")]
#[macro_export]
macro_rules! log_performance {
    ($($key:tt = $value:expr),* $(,)?) => {
        tracing::debug!(
            event_type = "performance",
            $($key = tracing::field::debug(&$value)),*
        );
    };
}

/// Create a tracing span for a request with context
///
/// # Examples
/// ```no_run
/// # #[cfg(feature = "database")]
/// # use aframp::request_span;
/// # #[cfg(feature = "database")]
/// # {
/// let span = request_span!(
///     "onramp_initiate",
///     request_id = "req_abc123",
///     wallet = "GXXX...XXX",
/// );
/// let _guard = span.enter();
/// // All logs within this scope will include the span context
/// # }
/// ```
#[cfg(feature = "database")]
#[macro_export]
macro_rules! request_span {
    ($name:expr, $($key:tt = $value:expr),* $(,)?) => {
        tracing::info_span!(
            $name,
            $($key = tracing::field::debug(&$value)),*
        )
    };
}

#[cfg(all(test, feature = "database"))]
mod tests {
    use super::*;

    #[test]
    fn test_environment_detection() {
        env::set_var("ENVIRONMENT", "production");
        assert_eq!(Environment::from_env(), Environment::Production);
        assert!(Environment::from_env().is_production());

        env::set_var("ENVIRONMENT", "development");
        assert_eq!(Environment::from_env(), Environment::Development);
        assert!(!Environment::from_env().is_production());
    }

    #[test]
    fn test_mask_wallet_address() {
        let address = "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let masked = mask_wallet_address(address);
        assert_eq!(masked, "GXXX...XXXX");

        let short = "GXX";
        assert_eq!(mask_wallet_address(short), "****");
    }

    #[test]
    fn test_default_log_levels() {
        assert_eq!(Environment::Development.default_log_level(), Level::DEBUG);
        assert_eq!(Environment::Production.default_log_level(), Level::INFO);
        assert_eq!(Environment::Staging.default_log_level(), Level::INFO);
    }

    #[test]
    fn test_redact_sensitive_data() {
        let data = r#"{"private_key": "SECRET123", "amount": 100}"#;
        let redacted = redact_sensitive_data(data);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("SECRET123"));
        assert!(redacted.contains("100")); // Non-sensitive data preserved
    }
}
