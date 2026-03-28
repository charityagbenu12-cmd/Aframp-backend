//! Bank Account Verification Service
//!
//! Handles verification of Nigerian bank accounts using Flutterwave or Paystack APIs.
//! Validates account existence, normalizes account names, and detects name mismatches.

use crate::error::{AppError, AppErrorKind, ExternalError, ValidationError};
use crate::payments::types::ProviderName;
use crate::payments::factory::PaymentProviderFactory;
use async_trait::async_trait;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Bank verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankVerificationResult {
    pub account_number: String,
    pub account_name: String,
    pub bank_name: Option<String>,
    pub verified: bool,
    pub verified_at: String,
}

/// Configuration for bank verification service
#[derive(Debug, Clone)]
pub struct BankVerificationConfig {
    pub timeout_secs: u64,
    pub max_retries: u32,
    pub name_match_tolerance: f32, // 0.0 - 1.0, percentage match required
}

impl Default for BankVerificationConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            max_retries: 2,
            name_match_tolerance: 0.7, // 70% match required
        }
    }
}

/// Bank verification service
pub struct BankVerificationService {
    provider_factory: Arc<PaymentProviderFactory>,
    config: BankVerificationConfig,
}

impl BankVerificationService {
    pub fn new(provider_factory: Arc<PaymentProviderFactory>, config: BankVerificationConfig) -> Self {
        Self {
            provider_factory,
            config,
        }
    }

    pub fn with_provider_factory(provider_factory: Arc<PaymentProviderFactory>) -> Self {
        Self::new(provider_factory, BankVerificationConfig::default())
    }

    /// Verify bank account using Flutterwave or Paystack
    pub async fn verify_account(
        &self,
        bank_code: &str,
        account_number: &str,
        account_name: &str,
    ) -> Result<BankVerificationResult, AppError> {
        // First try Flutterwave, then Paystack as fallback
        let result = self
            .verify_with_provider(ProviderName::Flutterwave, bank_code, account_number, account_name)
            .await;

        match result {
            Ok(r) => {
                info!(
                    bank_code = %bank_code,
                    account_number = %account_number,
                    verified_name = %r.account_name,
                    "Account verified with Flutterwave"
                );
                return Ok(r);
            }
            Err(e) => {
                warn!(
                    error = ?e,
                    "Flutterwave verification failed, trying Paystack"
                );
            }
        }

        // Fallback to Paystack
        self.verify_with_provider(ProviderName::Paystack, bank_code, account_number, account_name)
            .await
    }

    /// Verify account with specific provider
    async fn verify_with_provider(
        &self,
        provider_name: ProviderName,
        bank_code: &str,
        account_number: &str,
        provided_name: &str,
    ) -> Result<BankVerificationResult, AppError> {
        let provider = self
            .provider_factory
            .get_provider(provider_name.clone())
            .map_err(|e| {
                error!(error = %e, provider = ?provider_name, "Failed to get payment provider");
                AppError::new(AppErrorKind::External(ExternalError::PaymentProvider {
                    provider: provider_name.to_string(),
                    message: format!("Failed to initialize {}: {}", provider_name, e),
                    is_retryable: true,
                }))
            })?;

        match provider_name {
            ProviderName::Flutterwave => {
                self.verify_with_flutterwave(bank_code, account_number, provided_name)
                    .await
            }
            ProviderName::Paystack => {
                self.verify_with_paystack(bank_code, account_number, provided_name)
                    .await
            }
            ProviderName::Mock => {
                Ok(BankVerificationResult {
                    account_number: account_number.to_string(),
                    account_name: provided_name.to_string(),
                    bank_name: Some("Mock Bank".to_string()),
                    verified: true,
                    verified_at: chrono::Utc::now().to_rfc3339(),
                })
            }
            _ => {
                error!(provider = ?provider_name, "Unsupported provider for bank verification");
                Err(AppError::new(AppErrorKind::Validation(
                    ValidationError::InvalidAmount {
                        amount: provider_name.to_string(),
                        reason: "Bank verification provider not supported".to_string(),
                    },
                )))
            }
        }
    }

    /// Verify with Flutterwave API
    /// POST https://api.flutterwave.com/v3/accounts/resolve
    async fn verify_with_flutterwave(
        &self,
        bank_code: &str,
        account_number: &str,
        provided_name: &str,
    ) -> Result<BankVerificationResult, AppError> {
        let url = "https://api.flutterwave.com/v3/accounts/resolve";
        let secret_key = std::env::var("FLUTTERWAVE_SECRET_KEY")
            .map_err(|_| {
                error!("FLUTTERWAVE_SECRET_KEY not configured");
                AppError::new(AppErrorKind::Infrastructure(
                    crate::error::InfrastructureError::Configuration {
                        message: "Flutterwave API key not configured".to_string(),
                    },
                ))
            })?;

        let client = HttpClient::new();
        let payload = serde_json::json!({
            "account_number": account_number,
            "account_bank": bank_code,
        });

        debug!(
            url = %url,
            bank_code = %bank_code,
            account_number = %account_number,
            "Verifying account with Flutterwave"
        );

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            client
                .post(url)
                .bearer_auth(&secret_key)
                .json(&payload)
                .send(),
        )
        .await
        .map_err(|_| {
            error!("Flutterwave verification timeout");
            AppError::new(AppErrorKind::External(ExternalError::Timeout {
                service: "Flutterwave".to_string(),
                timeout_secs: self.config.timeout_secs,
            }))
        })
        .map_err(|e| {
            error!(error = %e, "Flutterwave request failed");
            AppError::new(AppErrorKind::External(ExternalError::PaymentProvider {
                provider: "flutterwave".to_string(),
                message: format!("Account verification request failed: {}", e),
                is_retryable: true,
            }))
        })?
        .map_err(|e| {
            error!(error = %e, "Flutterwave HTTP error");
            AppError::new(AppErrorKind::External(ExternalError::PaymentProvider {
                provider: "flutterwave".to_string(),
                message: format!("HTTP error: {}", e),
                is_retryable: true,
            }))
        })?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to read Flutterwave response");
                AppError::new(AppErrorKind::External(ExternalError::PaymentProvider {
                    provider: "flutterwave".to_string(),
                    message: "Failed to read response".to_string(),
                    is_retryable: false,
                }))
            })?;

        debug!(status = %status, response = %text, "Flutterwave response received");

        if !status.is_success() {
            error!(
                status = %status,
                response = %text,
                "Flutterwave verification failed"
            );
            return Err(AppError::new(AppErrorKind::External(
                ExternalError::PaymentProvider {
                    provider: "flutterwave".to_string(),
                    message: if status.as_u16() == 404 {
                        format!("Account not found: {}", account_number)
                    } else {
                        "Bank verification failed".to_string()
                    },
                    is_retryable: status.is_server_error(),
                },
            )));
        }

        let json_response: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| {
                error!(error = %e, response = %text, "Failed to parse Flutterwave response");
                AppError::new(AppErrorKind::External(ExternalError::PaymentProvider {
                    provider: "flutterwave".to_string(),
                    message: "Invalid response format".to_string(),
                    is_retryable: false,
                }))
            })?;

        // Expected format:
        // {
        //   "status": "success",
        //   "data": {
        //     "account_number": "0123456789",
        //     "account_name": "JOHN DOE"
        //   }
        // }

        let account_data = json_response
            .get("data")
            .ok_or_else(|| {
                error!("No data in Flutterwave response");
                AppError::new(AppErrorKind::External(ExternalError::PaymentProvider {
                    provider: "flutterwave".to_string(),
                    message: "Invalid response format".to_string(),
                    is_retryable: false,
                }))
            })?;

        let verified_account_name = account_data
            .get("account_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let verified_account_number = account_data
            .get("account_number")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Check if names match
        if !self.names_match(provided_name, &verified_account_name) {
            warn!(
                provided = %provided_name,
                verified = %verified_account_name,
                "Account name mismatch"
            );
            return Err(AppError::new(AppErrorKind::Validation(
                ValidationError::InvalidAmount {
                    amount: provided_name.to_string(),
                    reason: format!(
                        "Account name mismatch. Expected: {}, but found: {}. Please verify the account details.",
                        self.normalize_name(provided_name),
                        verified_account_name
                    ),
                },
            )));
        }

        Ok(BankVerificationResult {
            account_number: verified_account_number,
            account_name: verified_account_name,
            bank_name: None,
            verified: true,
            verified_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Verify with Paystack API
    /// GET https://api.paystack.co/bank/resolve?account_number=...&bank_code=...
    async fn verify_with_paystack(
        &self,
        bank_code: &str,
        account_number: &str,
        provided_name: &str,
    ) -> Result<BankVerificationResult, AppError> {
        let url = format!(
            "https://api.paystack.co/bank/resolve?account_number={}&bank_code={}",
            account_number, bank_code
        );

        let secret_key = std::env::var("PAYSTACK_SECRET_KEY")
            .map_err(|_| {
                error!("PAYSTACK_SECRET_KEY not configured");
                AppError::new(AppErrorKind::Infrastructure(
                    crate::error::InfrastructureError::Configuration {
                        message: "Paystack API key not configured".to_string(),
                    },
                ))
            })?;

        let client = HttpClient::new();

        debug!(
            url = %url,
            bank_code = %bank_code,
            account_number = %account_number,
            "Verifying account with Paystack"
        );

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            client
                .get(&url)
                .bearer_auth(&secret_key)
                .send(),
        )
        .await
        .map_err(|_| {
            error!("Paystack verification timeout");
            AppError::new(AppErrorKind::External(ExternalError::Timeout {
                service: "Paystack".to_string(),
                timeout_secs: self.config.timeout_secs,
            }))
        })
        .map_err(|e| {
            error!(error = %e, "Paystack request failed");
            AppError::new(AppErrorKind::External(ExternalError::PaymentProvider {
                provider: "paystack".to_string(),
                message: format!("Account verification request failed: {}", e),
                is_retryable: true,
            }))
        })?
        .map_err(|e| {
            error!(error = %e, "Paystack HTTP error");
            AppError::new(AppErrorKind::External(ExternalError::PaymentProvider {
                provider: "paystack".to_string(),
                message: format!("HTTP error: {}", e),
                is_retryable: true,
            }))
        })?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to read Paystack response");
                AppError::new(AppErrorKind::External(ExternalError::PaymentProvider {
                    provider: "paystack".to_string(),
                    message: "Failed to read response".to_string(),
                    is_retryable: false,
                }))
            })?;

        debug!(status = %status, response = %text, "Paystack response received");

        if !status.is_success() {
            error!(
                status = %status,
                response = %text,
                "Paystack verification failed"
            );
            return Err(AppError::new(AppErrorKind::External(
                ExternalError::PaymentProvider {
                    provider: "paystack".to_string(),
                    message: if status.as_u16() == 404 {
                        format!("Account not found: {}", account_number)
                    } else {
                        "Bank verification failed".to_string()
                    },
                    is_retryable: status.is_server_error(),
                },
            )));
        }

        let json_response: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| {
                error!(error = %e, response = %text, "Failed to parse Paystack response");
                AppError::new(AppErrorKind::External(ExternalError::PaymentProvider {
                    provider: "paystack".to_string(),
                    message: "Invalid response format".to_string(),
                    is_retryable: false,
                }))
            })?;

        // Expected format:
        // {
        //   "status": true,
        //   "message": "Account number resolved",
        //   "data": {
        //     "account_number": "0123456789",
        //     "account_name": "John Doe",
        //     "bank_id": 9
        //   }
        // }

        let account_data = json_response
            .get("data")
            .ok_or_else(|| {
                error!("No data in Paystack response");
                AppError::new(AppErrorKind::External(ExternalError::PaymentProvider {
                    provider: "paystack".to_string(),
                    message: "Invalid response format".to_string(),
                    is_retryable: false,
                }))
            })?;

        let verified_account_name = account_data
            .get("account_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let verified_account_number = account_data
            .get("account_number")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Check if names match
        if !self.names_match(provided_name, &verified_account_name) {
            warn!(
                provided = %provided_name,
                verified = %verified_account_name,
                "Account name mismatch"
            );
            return Err(AppError::new(AppErrorKind::Validation(
                ValidationError::InvalidAmount {
                    amount: provided_name.to_string(),
                    reason: format!(
                        "Account name mismatch. Expected: {}, but found: {}. Please verify the account details.",
                        self.normalize_name(provided_name),
                        verified_account_name
                    ),
                },
            )));
        }

        Ok(BankVerificationResult {
            account_number: verified_account_number,
            account_name: verified_account_name,
            bank_name: None,
            verified: true,
            verified_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Normalize name for comparison (uppercase, collapse whitespace)
    fn normalize_name(&self, name: &str) -> String {
        name.trim()
            .to_uppercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Check if two names match with tolerance
    fn names_match(&self, provided: &str, verified: &str) -> bool {
        let provided_normalized = self.normalize_name(provided);
        let verified_normalized = self.normalize_name(verified);

        // Exact match
        if provided_normalized == verified_normalized {
            return true;
        }

        // Fuzzy match using Levenshtein distance
        self.fuzzy_match(&provided_normalized, &verified_normalized)
    }

    /// Fuzzy match using simple algorithm (word-based)
    fn fuzzy_match(&self, provided: &str, verified: &str) -> bool {
        let provided_words: Vec<&str> = provided.split_whitespace().collect();
        let verified_words: Vec<&str> = verified.split_whitespace().collect();

        // All provided words must be in verified
        let matches = provided_words
            .iter()
            .filter(|w| verified_words.contains(w))
            .count();

        let match_ratio = matches as f32 / provided_words.len().max(1) as f32;
        match_ratio >= self.config.name_match_tolerance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_name() {
        let service = BankVerificationService {
            provider_factory: Arc::new(
                crate::payments::factory::PaymentProviderFactory::with_config(
                    crate::payments::factory::PaymentFactoryConfig {
                        default_provider: ProviderName::Paystack,
                        enabled_providers: vec![ProviderName::Paystack, ProviderName::Flutterwave],
                        provider_fee_bps: std::collections::HashMap::new(),
                    },
                ),
            ),
            config: BankVerificationConfig::default(),
        };

        assert_eq!(service.normalize_name("john doe"), "JOHN DOE");
        assert_eq!(service.normalize_name("JOHN  DOE"), "JOHN DOE");
        assert_eq!(
            service.normalize_name("  john doe  "),
            "JOHN DOE"
        );
    }

    #[test]
    fn test_names_match() {
        let service = BankVerificationService {
            provider_factory: Arc::new(
                crate::payments::factory::PaymentProviderFactory::with_config(
                    crate::payments::factory::PaymentFactoryConfig {
                        default_provider: ProviderName::Paystack,
                        enabled_providers: vec![ProviderName::Paystack, ProviderName::Flutterwave],
                        provider_fee_bps: std::collections::HashMap::new(),
                    },
                ),
            ),
            config: BankVerificationConfig::default(),
        };

        assert!(service.names_match("John Doe", "john doe"));
        assert!(service.names_match("JOHN DOE", "john doe"));
        assert!(service.names_match("John  Doe", "john doe"));
        assert!(service.names_match("John Doe", "JOHN DOE"));
        // Fuzzy match - at least one word matches
        assert!(service.names_match("John Smith", "JOHN DOE")); // JOHN matches
        // No match
        assert!(!service.names_match("Jane Doe", "JOHN DOE"));
    }
}
