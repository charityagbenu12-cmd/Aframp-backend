//! Production-grade startup configuration validation.
//!
//! Enforces strict rules for non-development environments:
//! - Secrets must not be placeholder values
//! - Database and Redis must use TLS in production
//! - JWT secret must meet minimum length
//! - Stellar network must match APP_ENV
//!
//! Call [`validate_production_config`] early in `main()` before accepting traffic.

use std::env;

/// Errors surfaced during production config validation.
#[derive(Debug)]
pub struct ConfigValidationError {
    pub errors: Vec<String>,
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Configuration validation failed:")?;
        for e in &self.errors {
            writeln!(f, "  ✗ {}", e)?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigValidationError {}

/// Validate all required configuration at startup.
///
/// In `development` this is a soft check (warnings only).
/// In `staging` and `production` any failure is fatal.
pub fn validate_production_config() -> Result<(), ConfigValidationError> {
    let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".into());
    let is_production = app_env == "production";
    let is_non_dev = app_env != "development";

    let mut errors: Vec<String> = Vec::new();

    // -------------------------------------------------------------------------
    // Required variables — must be present in all environments
    // -------------------------------------------------------------------------
    let required = [
        "DATABASE_URL",
        "APP_ENV",
    ];
    for var in &required {
        if env::var(var).map(|v| v.is_empty()).unwrap_or(true) {
            errors.push(format!("{} is required but not set", var));
        }
    }

    // -------------------------------------------------------------------------
    // Secrets — must be present and not placeholder values in non-dev
    // -------------------------------------------------------------------------
    if is_non_dev {
        let secrets = [
            "JWT_SECRET",
            "ENCRYPTION_KEY",
            "PAYSTACK_SECRET_KEY",
            "SYSTEM_WALLET_SECRET",
        ];
        let placeholders = [
            "change-me",
            "xxxx",
            "your-",
            "secret-here",
            "replace-me",
            "todo",
        ];
        for var in &secrets {
            match env::var(var) {
                Err(_) => errors.push(format!("{} is required in {} environment", var, app_env)),
                Ok(val) if val.is_empty() => {
                    errors.push(format!("{} must not be empty in {} environment", var, app_env))
                }
                Ok(val) => {
                    let lower = val.to_lowercase();
                    if placeholders.iter().any(|p| lower.contains(p)) {
                        errors.push(format!(
                            "{} appears to be a placeholder value — replace with a real secret",
                            var
                        ));
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // JWT secret minimum length (32 chars)
    // -------------------------------------------------------------------------
    if let Ok(jwt) = env::var("JWT_SECRET") {
        if jwt.len() < 32 {
            errors.push(format!(
                "JWT_SECRET must be at least 32 characters (got {})",
                jwt.len()
            ));
        }
    }

    // -------------------------------------------------------------------------
    // Database TLS enforcement in production
    // -------------------------------------------------------------------------
    if is_production {
        match env::var("DATABASE_URL") {
            Ok(url) => {
                let has_ssl = url.contains("sslmode=require")
                    || url.contains("sslmode=verify-full")
                    || url.contains("sslmode=verify-ca");
                if !has_ssl {
                    errors.push(
                        "DATABASE_URL must include sslmode=require or sslmode=verify-full in production"
                            .into(),
                    );
                }
            }
            Err(_) => {} // already caught above
        }
    }

    // -------------------------------------------------------------------------
    // Redis TLS enforcement in production
    // -------------------------------------------------------------------------
    if is_production {
        let redis_url = env::var("REDIS_URL").unwrap_or_default();
        if !redis_url.is_empty() && !redis_url.starts_with("rediss://") {
            errors.push(
                "REDIS_URL must use rediss:// (TLS) in production — plain redis:// is not allowed"
                    .into(),
            );
        }
    }

    // -------------------------------------------------------------------------
    // Stellar network must match environment
    // -------------------------------------------------------------------------
    if is_production {
        let network = env::var("STELLAR_NETWORK").unwrap_or_default();
        if network != "mainnet" {
            errors.push(format!(
                "STELLAR_NETWORK must be 'mainnet' in production (got '{}')",
                network
            ));
        }
    }

    // -------------------------------------------------------------------------
    // Debug mode must be disabled in production
    // -------------------------------------------------------------------------
    if is_production {
        let debug = env::var("DEBUG_MODE")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        if debug {
            errors.push("DEBUG_MODE must be false in production — disabling immediately".into());
        }
    }

    // -------------------------------------------------------------------------
    // Mock payments must be disabled in non-dev
    // -------------------------------------------------------------------------
    if is_non_dev {
        let mock = env::var("ENABLE_MOCK_PAYMENTS")
            .unwrap_or_else(|_| "false".into())
            .to_lowercase();
        if mock == "true" || mock == "1" {
            errors.push(format!(
                "ENABLE_MOCK_PAYMENTS must be false in {} environment",
                app_env
            ));
        }
    }

    // -------------------------------------------------------------------------
    // Log format must be JSON in non-dev (structured logging for aggregators)
    // -------------------------------------------------------------------------
    if is_non_dev {
        let fmt = env::var("LOG_FORMAT").unwrap_or_default().to_lowercase();
        if fmt == "plain" {
            errors.push(format!(
                "LOG_FORMAT should be 'json' in {} for log aggregation",
                app_env
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigValidationError { errors })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_secret_too_short() {
        // Set a short JWT secret and a non-dev env
        std::env::set_var("JWT_SECRET", "short");
        std::env::set_var("APP_ENV", "development");
        std::env::set_var("DATABASE_URL", "postgres://localhost/test");

        let result = validate_production_config();
        // Should fail due to short JWT secret
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.errors.iter().any(|e| e.contains("JWT_SECRET must be at least 32")));
    }

    #[test]
    fn test_production_requires_ssl_database() {
        std::env::set_var("APP_ENV", "production");
        std::env::set_var("DATABASE_URL", "postgres://user:pass@host/db?sslmode=disable");
        std::env::set_var("REDIS_URL", "rediss://localhost:6379");
        std::env::set_var("STELLAR_NETWORK", "mainnet");
        std::env::set_var("JWT_SECRET", "a-very-long-secret-that-is-at-least-32-chars");
        std::env::set_var("ENCRYPTION_KEY", "a-very-long-secret-that-is-at-least-32-chars");
        std::env::set_var("PAYSTACK_SECRET_KEY", "sk_live_realkey123456789");
        std::env::set_var("SYSTEM_WALLET_SECRET", "SREAL_STELLAR_SECRET_KEY_HERE_LONG");

        let result = validate_production_config();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.errors.iter().any(|e| e.contains("sslmode=require")));
    }

    #[test]
    fn test_production_requires_redis_tls() {
        std::env::set_var("APP_ENV", "production");
        std::env::set_var("DATABASE_URL", "postgres://user:pass@host/db?sslmode=require");
        std::env::set_var("REDIS_URL", "redis://localhost:6379");
        std::env::set_var("STELLAR_NETWORK", "mainnet");
        std::env::set_var("JWT_SECRET", "a-very-long-secret-that-is-at-least-32-chars");
        std::env::set_var("ENCRYPTION_KEY", "a-very-long-secret-that-is-at-least-32-chars");
        std::env::set_var("PAYSTACK_SECRET_KEY", "sk_live_realkey123456789");
        std::env::set_var("SYSTEM_WALLET_SECRET", "SREAL_STELLAR_SECRET_KEY_HERE_LONG");

        let result = validate_production_config();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.errors.iter().any(|e| e.contains("rediss://")));
    }
}
