//! Application configuration module
//! Handles environment variable loading, configuration validation, and application settings

use std::env;

/// Main application configuration
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub cache: CacheConfig,
    pub logging: LoggingConfig,
    pub stellar: StellarConfig,
    /// Distributed tracing configuration (Issue #104 — OpenTelemetry).
    pub telemetry: TelemetryConfig,
    pub kyc: KycConfig,
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub cors_allowed_origins: Vec<String>,
}

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: u64,   // seconds
    pub idle_timeout: Option<u64>, // seconds
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub redis_url: String,
    pub default_ttl: u64, // seconds
    pub max_connections: u32,
}

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub format: LogFormat,
    pub enable_tracing: bool,
}

/// Log format options
#[derive(Debug, Clone)]
pub enum LogFormat {
    Json,
    Plain,
}

/// Stellar-specific configuration
#[derive(Debug, Clone)]
pub struct StellarConfig {
    pub network: String,
    pub horizon_url: String,
    pub request_timeout: u64, // seconds
    pub max_retries: u32,
    pub health_check_interval: u64, // seconds
}

// ---------------------------------------------------------------------------
// Telemetry configuration  (Issue #104 — Distributed Tracing)
// ---------------------------------------------------------------------------

/// OpenTelemetry / distributed-tracing configuration.
///
/// All fields are loaded from environment variables so the tracing backend,
/// service name, environment tag, and sampling rate can be changed without
/// recompiling the binary.
///
/// Environment variables
/// ─────────────────────
/// | Variable                        | Default                   | Description                                          |
/// |---------------------------------|---------------------------|------------------------------------------------------|
/// | `OTEL_SERVICE_NAME`             | `"aframp-backend"`        | Service name emitted in every span.                  |
/// | `APP_ENV`                       | `"development"`           | Deployment environment tag on every span.            |
/// | `OTEL_SAMPLING_RATE`            | `1.0`                     | Fraction of root spans sampled (0.0 – 1.0).          |
/// | `OTEL_EXPORTER_OTLP_ENDPOINT`   | `"http://localhost:4317"` | gRPC endpoint of the OTLP collector (Jaeger / Tempo).|
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Human-readable service name attached to every exported span as
    /// the `service.name` resource attribute.
    pub service_name: String,

    /// Deployment environment (e.g. `"development"`, `"staging"`, `"production"`).
    /// Attached to every span as the `deployment.environment` resource attribute.
    pub environment: String,

    /// Fraction of root spans to sample (0.0 = none, 1.0 = all).
    ///
    /// Child spans always inherit the sampling decision of their parent, so a
    /// trace is never split mid-flight.  Error traces are always exported
    /// regardless of this value — the SDK uses `ParentBased(AlwaysOn)` when
    /// the rate is 1.0 and `ParentBased(TraceIdRatioBased(rate))` otherwise.
    ///
    /// For production, start at `0.1` (10 %) and tune based on volume.
    pub sampling_rate: f64,

    /// OTLP gRPC collector endpoint.
    ///
    /// Typical values:
    /// * Jaeger all-in-one:          `http://localhost:4317`
    /// * Grafana Agent / Tempo:      `http://localhost:4317`
    /// * OpenTelemetry Collector:    `http://otel-collector:4317`
    pub otlp_endpoint: String,
}

impl TelemetryConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(TelemetryConfig {
            service_name: env::var("OTEL_SERVICE_NAME")
                .unwrap_or_else(|_| "aframp-backend".to_string()),

            environment: env::var("APP_ENV")
                .unwrap_or_else(|_| "development".to_string()),

            sampling_rate: env::var("OTEL_SAMPLING_RATE")
                .unwrap_or_else(|_| "1.0".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("OTEL_SAMPLING_RATE".to_string()))?,

            otlp_endpoint: env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:4317".to_string()),
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        // Sampling rate must be in [0.0, 1.0].
        if !(0.0..=1.0).contains(&self.sampling_rate) {
            return Err(ConfigError::InvalidValue(
                "OTEL_SAMPLING_RATE must be between 0.0 and 1.0".to_string(),
            ));
        }

        // Service name must not be blank.
        if self.service_name.trim().is_empty() {
            return Err(ConfigError::InvalidValue(
                "OTEL_SERVICE_NAME cannot be empty".to_string(),
            ));
        }

        // OTLP endpoint must look like an HTTP/HTTPS URL.
        if !self.otlp_endpoint.starts_with("http://")
            && !self.otlp_endpoint.starts_with("https://")
        {
            return Err(ConfigError::InvalidValue(
                "OTEL_EXPORTER_OTLP_ENDPOINT must start with http:// or https://".to_string(),
            ));
        }

        // APP_ENV must be one of the known deployment tiers.
        let valid_envs = ["development", "staging", "production", "test"];
        if !valid_envs.contains(&self.environment.as_str()) {
            return Err(ConfigError::InvalidValue(format!(
                "APP_ENV must be one of: {}",
                valid_envs.join(", ")
            )));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AppConfig
// ---------------------------------------------------------------------------

impl AppConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load .env file if it exists
        let _ = dotenv::dotenv().ok();

        Ok(AppConfig {
            server: ServerConfig::from_env()?,
            database: DatabaseConfig::from_env()?,
            cache: CacheConfig::from_env()?,
            logging: LoggingConfig::from_env()?,
            stellar: StellarConfig::from_env()?,
            telemetry: TelemetryConfig::from_env()?,
            kyc: KycConfig::from_env()?,
        })
    }

    /// Validate the entire configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.server.validate()?;
        self.database.validate()?;
        self.cache.validate()?;
        self.stellar.validate()?;
        self.telemetry.validate()?;
        self.kyc.validate()?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Existing config impls (unchanged)
// ---------------------------------------------------------------------------

impl ServerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(ServerConfig {
            host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8000".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("SERVER_PORT".to_string()))?,
            cors_allowed_origins: env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "http://localhost,http://127.0.0.1".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::InvalidValue(
                "SERVER_PORT cannot be 0".to_string(),
            ));
        }

        if self.host.is_empty() {
            return Err(ConfigError::InvalidValue(
                "SERVER_HOST cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

impl DatabaseConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(DatabaseConfig {
            url: env::var("DATABASE_URL")
                .map_err(|_| ConfigError::MissingVariable("DATABASE_URL".to_string()))?,
            max_connections: env::var("DB_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "20".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("DB_MAX_CONNECTIONS".to_string()))?,
            min_connections: env::var("DB_MIN_CONNECTIONS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("DB_MIN_CONNECTIONS".to_string()))?,
            connection_timeout: env::var("DB_CONNECTION_TIMEOUT")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("DB_CONNECTION_TIMEOUT".to_string()))?,
            idle_timeout: env::var("DB_IDLE_TIMEOUT")
                .ok()
                .and_then(|val| val.parse().ok()),
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.url.is_empty() {
            return Err(ConfigError::InvalidValue("DATABASE_URL".to_string()));
        }

        if self.max_connections == 0 {
            return Err(ConfigError::InvalidValue("DB_MAX_CONNECTIONS".to_string()));
        }

        if self.min_connections > self.max_connections {
            return Err(ConfigError::InvalidValue(
                "DB_MIN_CONNECTIONS must be <= DB_MAX_CONNECTIONS".to_string(),
            ));
        }

        Ok(())
    }
}

impl CacheConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(CacheConfig {
            redis_url: env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            default_ttl: env::var("CACHE_DEFAULT_TTL")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("CACHE_DEFAULT_TTL".to_string()))?,
            max_connections: env::var("CACHE_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("CACHE_MAX_CONNECTIONS".to_string()))?,
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.redis_url.is_empty() {
            return Err(ConfigError::InvalidValue("REDIS_URL".to_string()));
        }

        // Basic validation of Redis URL format
        if !self.redis_url.starts_with("redis://") && !self.redis_url.starts_with("rediss://") {
            return Err(ConfigError::InvalidValue(
                "REDIS_URL must start with redis:// or rediss://".to_string(),
            ));
        }

        Ok(())
    }
}

impl LoggingConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(LoggingConfig {
            level: env::var("LOG_LEVEL").unwrap_or_else(|_| "INFO".to_string()),
            format: match env::var("LOG_FORMAT")
                .unwrap_or_else(|_| "plain".to_string())
                .as_str()
            {
                "json" => LogFormat::Json,
                _ => LogFormat::Plain,
            },
            enable_tracing: env::var("ENABLE_TRACING")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("ENABLE_TRACING".to_string()))?,
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let valid_levels = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
        if !valid_levels.contains(&self.level.to_uppercase().as_str()) {
            return Err(ConfigError::InvalidValue("LOG_LEVEL".to_string()));
        }

        Ok(())
    }
}

impl StellarConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(StellarConfig {
            network: env::var("STELLAR_NETWORK").unwrap_or_else(|_| "testnet".to_string()),
            horizon_url: env::var("STELLAR_HORIZON_URL").unwrap_or_else(|_| {
                if env::var("STELLAR_NETWORK").unwrap_or_else(|_| "testnet".to_string())
                    == "mainnet"
                {
                    "https://horizon.stellar.org".to_string()
                } else {
                    "https://horizon-testnet.stellar.org".to_string()
                }
            }),
            request_timeout: env::var("STELLAR_REQUEST_TIMEOUT")
                .unwrap_or_else(|_| "15".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("STELLAR_REQUEST_TIMEOUT".to_string()))?,
            max_retries: env::var("STELLAR_MAX_RETRIES")
                .unwrap_or_else(|_| "3".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("STELLAR_MAX_RETRIES".to_string()))?,
            health_check_interval: env::var("STELLAR_HEALTH_CHECK_INTERVAL")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .map_err(|_| {
                    ConfigError::InvalidValue("STELLAR_HEALTH_CHECK_INTERVAL".to_string())
                })?,
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let valid_networks = ["testnet", "mainnet", "futurenet"];
        if !valid_networks.contains(&self.network.as_str()) {
            return Err(ConfigError::InvalidValue("STELLAR_NETWORK".to_string()));
        }

        if self.horizon_url.is_empty() {
            return Err(ConfigError::InvalidValue("STELLAR_HORIZON_URL".to_string()));
        }

        if !self.horizon_url.starts_with("http://") && !self.horizon_url.starts_with("https://") {
            return Err(ConfigError::InvalidValue(
                "STELLAR_HORIZON_URL must be a valid URL".to_string(),
            ));
        }

        if self.request_timeout == 0 {
            return Err(ConfigError::InvalidValue(
                "STELLAR_REQUEST_TIMEOUT".to_string(),
            ));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Error types (unchanged)
// ---------------------------------------------------------------------------

/// Configuration error types
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingVariable(String),

    #[error("Invalid value for configuration: {0}")]
    InvalidValue(String),

    #[error("Validation failed: {0}")]
    ValidationFailed(String),
}

impl From<std::num::ParseIntError> for ConfigError {
    fn from(_: std::num::ParseIntError) -> Self {
        ConfigError::InvalidValue("Failed to parse integer value".to_string())
    }
}

impl From<std::num::ParseFloatError> for ConfigError {
    fn from(_: std::num::ParseFloatError) -> Self {
        ConfigError::InvalidValue("Failed to parse float value".to_string())
    }
}

// ---------------------------------------------------------------------------
// KYC Configuration
// ---------------------------------------------------------------------------

/// KYC (Know Your Customer) verification configuration
#[derive(Debug, Clone)]
pub struct KycConfig {
    pub default_provider: String,
    pub providers: Vec<KycProviderConfig>,
    pub session_timeout_hours: u64,
    pub webhook_timeout_seconds: u64,
    pub max_document_size_mb: usize,
    pub compliance: KycComplianceConfig,
    pub limits: KycLimitsConfig,
}

/// Individual KYC provider configuration
#[derive(Debug, Clone)]
pub struct KycProviderConfig {
    pub name: String,
    pub api_key: String,
    pub api_secret: String,
    pub webhook_secret: String,
    pub base_url: String,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
    pub enabled: bool,
}

/// KYC compliance and EDD configuration
#[derive(Debug, Clone)]
pub struct KycComplianceConfig {
    pub manual_review_queue_threshold: i64,
    pub webhook_failure_rate_threshold: f64,
    pub auto_approve_enabled: bool,
    pub enhanced_due_diligence_enabled: bool,
    pub audit_retention_days: u64,
    pub compliance_report_schedule_hours: u64,
}

/// KYC transaction limits configuration
#[derive(Debug, Clone)]
pub struct KycLimitsConfig {
    pub daily_reset_hour: u8, // 0-23
    pub monthly_reset_day: u8, // 1-28
    pub volume_check_enabled: bool,
    pub violation_alert_threshold: f64, // 0.0-1.0
}

impl KycConfig {
    /// Load KYC configuration from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        let default_provider = env::var("KYC_DEFAULT_PROVIDER")
            .unwrap_or_else(|_| "smile_identity".to_string());

        let session_timeout_hours = env::var("KYC_SESSION_TIMEOUT_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidValue("KYC_SESSION_TIMEOUT_HOURS".to_string()))?;

        let webhook_timeout_seconds = env::var("KYC_WEBHOOK_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidValue("KYC_WEBHOOK_TIMEOUT_SECONDS".to_string()))?;

        let max_document_size_mb = env::var("KYC_MAX_DOCUMENT_SIZE_MB")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidValue("KYC_MAX_DOCUMENT_SIZE_MB".to_string()))?;

        // Load provider configurations
        let providers = Self::load_providers()?;

        let compliance = KycComplianceConfig {
            manual_review_queue_threshold: env::var("KYC_MANUAL_REVIEW_QUEUE_THRESHOLD")
                .unwrap_or_else(|_| "50".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("KYC_MANUAL_REVIEW_QUEUE_THRESHOLD".to_string()))?,
            webhook_failure_rate_threshold: env::var("KYC_WEBHOOK_FAILURE_RATE_THRESHOLD")
                .unwrap_or_else(|_| "0.1".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("KYC_WEBHOOK_FAILURE_RATE_THRESHOLD".to_string()))?,
            auto_approve_enabled: env::var("KYC_AUTO_APPROVE_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("KYC_AUTO_APPROVE_ENABLED".to_string()))?,
            enhanced_due_diligence_enabled: env::var("KYC_EDD_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("KYC_EDD_ENABLED".to_string()))?,
            audit_retention_days: env::var("KYC_AUDIT_RETENTION_DAYS")
                .unwrap_or_else(|_| "2555".to_string()) // 7 years
                .parse()
                .map_err(|_| ConfigError::InvalidValue("KYC_AUDIT_RETENTION_DAYS".to_string()))?,
            compliance_report_schedule_hours: env::var("KYC_COMPLIANCE_REPORT_SCHEDULE_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("KYC_COMPLIANCE_REPORT_SCHEDULE_HOURS".to_string()))?,
        };

        let limits = KycLimitsConfig {
            daily_reset_hour: env::var("KYC_DAILY_RESET_HOUR")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("KYC_DAILY_RESET_HOUR".to_string()))?,
            monthly_reset_day: env::var("KYC_MONTHLY_RESET_DAY")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("KYC_MONTHLY_RESET_DAY".to_string()))?,
            volume_check_enabled: env::var("KYC_VOLUME_CHECK_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("KYC_VOLUME_CHECK_ENABLED".to_string()))?,
            violation_alert_threshold: env::var("KYC_VIOLATION_ALERT_THRESHOLD")
                .unwrap_or_else(|_| "0.8".to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidValue("KYC_VIOLATION_ALERT_THRESHOLD".to_string()))?,
        };

        Ok(KycConfig {
            default_provider,
            providers,
            session_timeout_hours,
            webhook_timeout_seconds,
            max_document_size_mb,
            compliance,
            limits,
        })
    }

    fn load_providers() -> Result<Vec<KycProviderConfig>, ConfigError> {
        let mut providers = Vec::new();

        // Load Smile Identity configuration if available
        if let (Ok(api_key), Ok(api_secret)) = (
            env::var("SMILE_IDENTITY_API_KEY"),
            env::var("SMILE_IDENTITY_API_SECRET"),
        ) {
            providers.push(KycProviderConfig {
                name: "smile_identity".to_string(),
                api_key,
                api_secret,
                webhook_secret: env::var("SMILE_IDENTITY_WEBHOOK_SECRET").unwrap_or_default(),
                base_url: env::var("SMILE_IDENTITY_BASE_URL")
                    .unwrap_or_else(|_| "https://api.smileidentity.com".to_string()),
                timeout_seconds: env::var("SMILE_IDENTITY_TIMEOUT_SECONDS")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()
                    .map_err(|_| ConfigError::InvalidValue("SMILE_IDENTITY_TIMEOUT_SECONDS".to_string()))?,
                retry_attempts: env::var("SMILE_IDENTITY_RETRY_ATTEMPTS")
                    .unwrap_or_else(|_| "3".to_string())
                    .parse()
                    .map_err(|_| ConfigError::InvalidValue("SMILE_IDENTITY_RETRY_ATTEMPTS".to_string()))?,
                enabled: env::var("SMILE_IDENTITY_ENABLED")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .map_err(|_| ConfigError::InvalidValue("SMILE_IDENTITY_ENABLED".to_string()))?,
            });
        }

        Ok(providers)
    }

    /// Validate KYC configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.providers.is_empty() {
            return Err(ConfigError::Validation("No KYC providers configured".to_string()));
        }

        // Check if default provider exists and is enabled
        if !self.providers.iter().any(|p| p.name == self.default_provider && p.enabled) {
            return Err(ConfigError::Validation(format!(
                "Default provider '{}' not found or not enabled",
                self.default_provider
            )));
        }

        if self.session_timeout_hours == 0 {
            return Err(ConfigError::Validation("Session timeout must be greater than 0".to_string()));
        }

        if self.max_document_size_mb == 0 {
            return Err(ConfigError::Validation("Max document size must be greater than 0".to_string()));
        }

        if self.limits.daily_reset_hour > 23 {
            return Err(ConfigError::Validation("Daily reset hour must be 0-23".to_string()));
        }

        if self.limits.monthly_reset_day == 0 || self.limits.monthly_reset_day > 28 {
            return Err(ConfigError::Validation("Monthly reset day must be 1-28".to_string()));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── existing tests (unchanged) ──────────────────────────────────────────

    #[test]
    fn test_server_config_validation() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8000,
            cors_allowed_origins: vec!["http://localhost".to_string()],
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_port_validation() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0, // Invalid port
            cors_allowed_origins: vec![],
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_empty_host_validation() {
        let config = ServerConfig {
            host: "".to_string(),
            port: 8000,
            cors_allowed_origins: vec![],
        };

        assert!(config.validate().is_err());
    }

    // ── TelemetryConfig tests (Issue #104) ──────────────────────────────────

    fn valid_telemetry_config() -> TelemetryConfig {
        TelemetryConfig {
            service_name: "aframp-backend".to_string(),
            environment: "development".to_string(),
            sampling_rate: 1.0,
            otlp_endpoint: "http://localhost:4317".to_string(),
        }
    }

    #[test]
    fn test_telemetry_config_valid_defaults() {
        assert!(valid_telemetry_config().validate().is_ok());
    }

    #[test]
    fn test_telemetry_sampling_rate_boundaries() {
        // 0.0 (sample nothing) is valid.
        let cfg = TelemetryConfig { sampling_rate: 0.0, ..valid_telemetry_config() };
        assert!(cfg.validate().is_ok());

        // 1.0 (sample everything) is valid.
        let cfg = TelemetryConfig { sampling_rate: 1.0, ..valid_telemetry_config() };
        assert!(cfg.validate().is_ok());

        // 0.25 (25 %) is valid.
        let cfg = TelemetryConfig { sampling_rate: 0.25, ..valid_telemetry_config() };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_telemetry_sampling_rate_out_of_range() {
        // Above 1.0 must fail.
        let cfg = TelemetryConfig { sampling_rate: 1.1, ..valid_telemetry_config() };
        assert!(cfg.validate().is_err());

        // Negative must fail.
        let cfg = TelemetryConfig { sampling_rate: -0.1, ..valid_telemetry_config() };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_telemetry_empty_service_name() {
        let cfg = TelemetryConfig {
            service_name: "  ".to_string(), // whitespace only
            ..valid_telemetry_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_telemetry_invalid_otlp_endpoint() {
        // No scheme at all.
        let cfg = TelemetryConfig {
            otlp_endpoint: "localhost:4317".to_string(),
            ..valid_telemetry_config()
        };
        assert!(cfg.validate().is_err());

        // Wrong scheme.
        let cfg = TelemetryConfig {
            otlp_endpoint: "grpc://localhost:4317".to_string(),
            ..valid_telemetry_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_telemetry_https_otlp_endpoint_is_valid() {
        let cfg = TelemetryConfig {
            otlp_endpoint: "https://otel-collector.example.com:4317".to_string(),
            ..valid_telemetry_config()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_telemetry_invalid_environment() {
        let cfg = TelemetryConfig {
            environment: "local".to_string(), // not in the allowed list
            ..valid_telemetry_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_telemetry_all_valid_environments() {
        for env_name in &["development", "staging", "production", "test"] {
            let cfg = TelemetryConfig {
                environment: env_name.to_string(),
                ..valid_telemetry_config()
            };
            assert!(
                cfg.validate().is_ok(),
                "environment '{}' should be valid",
                env_name
            );
        }
    }

    #[test]
    fn test_telemetry_env_var_defaults() {
        // Remove all four OTel env vars so defaults are exercised.
        std::env::remove_var("OTEL_SERVICE_NAME");
        std::env::remove_var("APP_ENV");
        std::env::remove_var("OTEL_SAMPLING_RATE");
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");

        let cfg = TelemetryConfig::from_env().expect("should load from defaults");

        assert_eq!(cfg.service_name, "aframp-backend");
        assert_eq!(cfg.environment, "development");
        assert!((cfg.sampling_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(cfg.otlp_endpoint, "http://localhost:4317");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_telemetry_env_var_overrides() {
        std::env::set_var("OTEL_SERVICE_NAME", "payment-worker");
        std::env::set_var("APP_ENV", "production");
        std::env::set_var("OTEL_SAMPLING_RATE", "0.1");
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317");

        let cfg = TelemetryConfig::from_env().expect("should load from env vars");

        assert_eq!(cfg.service_name, "payment-worker");
        assert_eq!(cfg.environment, "production");
        assert!((cfg.sampling_rate - 0.1).abs() < f64::EPSILON);
        assert_eq!(cfg.otlp_endpoint, "http://otel-collector:4317");
        assert!(cfg.validate().is_ok());

        // Clean up so other tests are not affected.
        std::env::remove_var("OTEL_SERVICE_NAME");
        std::env::remove_var("APP_ENV");
        std::env::remove_var("OTEL_SAMPLING_RATE");
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    }

    #[test]
    fn test_telemetry_invalid_sampling_rate_env_var() {
        std::env::set_var("OTEL_SAMPLING_RATE", "not-a-number");
        let result = TelemetryConfig::from_env();
        assert!(result.is_err());
        std::env::remove_var("OTEL_SAMPLING_RATE");
    }
}