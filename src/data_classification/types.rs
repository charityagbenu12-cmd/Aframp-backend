//! Data classification types — the authoritative taxonomy for every category
//! of sensitive data handled by the Aframp platform.
//!
//! # Classification Tiers (highest → lowest sensitivity)
//!
//! | Tier | Label | Examples |
//! |------|-------|---------|
//! | 1 | `Critical` | Private keys, wallet secrets, raw card data, auth credentials |
//! | 2 | `Restricted` | KYC documents, government IDs, selfies, full account numbers |
//! | 3 | `Confidential` | Email, phone, wallet addresses, transaction amounts, KYC status |
//! | 4 | `Internal` | Exchange rates, fee structures, provider configs, audit metadata |
//! | 5 | `Public` | Supported currencies, health status, API version |

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Classification tier
// ---------------------------------------------------------------------------

/// The sensitivity tier assigned to a data element.
///
/// Tiers are ordered: `Critical > Restricted > Confidential > Internal > Public`.
/// Use `tier >= ClassificationTier::Confidential` to test "needs protection".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationTier {
    /// Tier 5 — freely shareable, no protection required.
    Public = 1,
    /// Tier 4 — internal operational data; not for external exposure.
    Internal = 2,
    /// Tier 3 — personal or financial data; encryption + masking required.
    Confidential = 3,
    /// Tier 2 — identity documents, biometrics; strict access + encryption.
    Restricted = 4,
    /// Tier 1 — cryptographic secrets, raw credentials; never logged or stored in plaintext.
    Critical = 5,
}

impl ClassificationTier {
    /// Returns `true` if this tier requires encryption at rest.
    pub fn requires_encryption_at_rest(&self) -> bool {
        *self >= ClassificationTier::Confidential
    }

    /// Returns `true` if this tier requires encryption in transit (TLS).
    pub fn requires_encryption_in_transit(&self) -> bool {
        *self >= ClassificationTier::Internal
    }

    /// Returns `true` if this tier must be masked in logs and API responses.
    pub fn requires_masking(&self) -> bool {
        *self >= ClassificationTier::Confidential
    }

    /// Returns `true` if this tier must never appear in log output at all.
    pub fn must_never_log(&self) -> bool {
        *self >= ClassificationTier::Critical
    }

    /// Returns `true` if access to this tier requires an audit trail entry.
    pub fn requires_access_audit(&self) -> bool {
        *self >= ClassificationTier::Restricted
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            ClassificationTier::Public => "PUBLIC",
            ClassificationTier::Internal => "INTERNAL",
            ClassificationTier::Confidential => "CONFIDENTIAL",
            ClassificationTier::Restricted => "RESTRICTED",
            ClassificationTier::Critical => "CRITICAL",
        }
    }

    /// Default retention period in days (`None` = retain indefinitely for compliance).
    pub fn default_retention_days(&self) -> Option<u32> {
        match self {
            ClassificationTier::Public => None,
            ClassificationTier::Internal => Some(365),
            ClassificationTier::Confidential => Some(2555), // 7 years — AML/KYC requirement
            ClassificationTier::Restricted => Some(2555),   // 7 years
            ClassificationTier::Critical => Some(90),       // rotate/purge quickly
        }
    }
}

impl fmt::Display for ClassificationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// Data categories
// ---------------------------------------------------------------------------

/// Logical grouping of data elements by domain.
///
/// Each category maps to one or more [`ClassificationTier`]s depending on
/// the specific field. The category is used by the policy engine to apply
/// domain-specific handling rules on top of the tier rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    // ── Identity & PII ──────────────────────────────────────────────────────
    /// Email addresses (login identifier).
    Email,
    /// Phone numbers (login / M-Pesa identifier).
    PhoneNumber,
    /// Full legal name from KYC documents.
    FullName,
    /// Date of birth from identity documents.
    DateOfBirth,
    /// National ID / passport / driver's licence number.
    GovernmentId,
    /// Scanned or photographed identity document.
    IdentityDocument,
    /// Liveness selfie captured during KYC.
    BiometricData,
    /// Physical or postal address.
    PhysicalAddress,
    /// IP address of a request.
    IpAddress,

    // ── Financial ───────────────────────────────────────────────────────────
    /// Transaction monetary amounts.
    TransactionAmount,
    /// Bank account number (full).
    BankAccountNumber,
    /// Bank account number (masked for display).
    BankAccountNumberMasked,
    /// Raw card PAN — must never be stored.
    CardPan,
    /// Tokenised card reference (provider token, not raw PAN).
    CardToken,
    /// M-Pesa / mobile money phone number used as payment identifier.
    MobileMoneyIdentifier,
    /// Blockchain wallet address.
    WalletAddress,
    /// On-chain transaction hash.
    BlockchainTxHash,
    /// AFRI / cNGN balance.
    CryptoBalance,
    /// Fiat balance or quoted amount.
    FiatAmount,
    /// Exchange rate (internal pricing).
    ExchangeRate,
    /// Fee structure details.
    FeeStructure,

    // ── Authentication & Credentials ────────────────────────────────────────
    /// Stellar / blockchain private key or secret seed.
    PrivateKey,
    /// JWT access token (full string).
    JwtToken,
    /// JWT refresh token.
    RefreshToken,
    /// API key plaintext (issued once, never stored).
    ApiKeyPlaintext,
    /// Argon2id hash of an API key or password.
    CredentialHash,
    /// OAuth client secret.
    OAuthClientSecret,
    /// TOTP / 2FA secret seed.
    TotpSecret,
    /// Payment provider webhook secret.
    WebhookSecret,
    /// Payment provider API secret key.
    ProviderSecretKey,

    // ── Compliance & Risk ───────────────────────────────────────────────────
    /// KYC verification tier and status.
    KycStatus,
    /// KYC risk score or EDD trigger reason.
    RiskScore,
    /// AML / compliance flags.
    ComplianceFlag,
    /// Manual review queue entry.
    ManualReviewData,
    /// EDD case details.
    EnhancedDueDiligenceData,

    // ── Operational ─────────────────────────────────────────────────────────
    /// Webhook event payload from a payment provider.
    WebhookPayload,
    /// Provider-specific response data.
    ProviderResponseData,
    /// Internal error messages (may contain stack traces).
    ErrorMessage,
    /// Audit log entry.
    AuditLogEntry,
    /// Request / response hash for integrity audit.
    RequestIntegrityHash,

    // ── Public ──────────────────────────────────────────────────────────────
    /// Supported currency codes.
    CurrencyCode,
    /// Transaction status code (pending / completed / failed).
    TransactionStatus,
    /// API health / version information.
    PublicApiMetadata,
}

impl DataCategory {
    /// The default classification tier for this category.
    ///
    /// Individual fields may override this via [`DataField::tier`].
    pub fn default_tier(&self) -> ClassificationTier {
        match self {
            // Critical — never log, never store plaintext
            DataCategory::PrivateKey
            | DataCategory::ApiKeyPlaintext
            | DataCategory::OAuthClientSecret
            | DataCategory::TotpSecret
            | DataCategory::WebhookSecret
            | DataCategory::ProviderSecretKey
            | DataCategory::CardPan => ClassificationTier::Critical,

            // Restricted — identity documents, biometrics
            DataCategory::IdentityDocument
            | DataCategory::BiometricData
            | DataCategory::GovernmentId
            | DataCategory::DateOfBirth
            | DataCategory::FullName
            | DataCategory::JwtToken
            | DataCategory::RefreshToken
            | DataCategory::BankAccountNumber
            | DataCategory::EnhancedDueDiligenceData
            | DataCategory::ManualReviewData => ClassificationTier::Restricted,

            // Confidential — PII, financial identifiers
            DataCategory::Email
            | DataCategory::PhoneNumber
            | DataCategory::PhysicalAddress
            | DataCategory::IpAddress
            | DataCategory::TransactionAmount
            | DataCategory::CardToken
            | DataCategory::MobileMoneyIdentifier
            | DataCategory::WalletAddress
            | DataCategory::CryptoBalance
            | DataCategory::FiatAmount
            | DataCategory::CredentialHash
            | DataCategory::KycStatus
            | DataCategory::RiskScore
            | DataCategory::ComplianceFlag
            | DataCategory::BlockchainTxHash
            | DataCategory::BankAccountNumberMasked => ClassificationTier::Confidential,

            // Internal — operational / pricing data
            DataCategory::ExchangeRate
            | DataCategory::FeeStructure
            | DataCategory::WebhookPayload
            | DataCategory::ProviderResponseData
            | DataCategory::ErrorMessage
            | DataCategory::AuditLogEntry
            | DataCategory::RequestIntegrityHash => ClassificationTier::Internal,

            // Public
            DataCategory::CurrencyCode
            | DataCategory::TransactionStatus
            | DataCategory::PublicApiMetadata => ClassificationTier::Public,
        }
    }
}

// ---------------------------------------------------------------------------
// Handling requirements
// ---------------------------------------------------------------------------

/// The complete set of handling requirements derived from a classification.
///
/// Produced by [`crate::data_classification::policy::PolicyEngine::requirements_for`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlingRequirements {
    pub tier: ClassificationTier,
    pub category: DataCategory,
    /// Must be encrypted at rest (AES-256-GCM or equivalent).
    pub encrypt_at_rest: bool,
    /// Must only be transmitted over TLS 1.2+.
    pub encrypt_in_transit: bool,
    /// Must be masked / redacted in log output.
    pub mask_in_logs: bool,
    /// Must be masked in API responses returned to clients.
    pub mask_in_responses: bool,
    /// Must never appear in any log output whatsoever.
    pub never_log: bool,
    /// Every read access must produce an audit trail entry.
    pub audit_on_access: bool,
    /// Retention period in days (`None` = indefinite / compliance-driven).
    pub retention_days: Option<u32>,
    /// Masking strategy to apply when `mask_in_logs` or `mask_in_responses` is true.
    pub masking_strategy: MaskingStrategy,
}

/// How a value should be masked when displayed or logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaskingStrategy {
    /// Replace the entire value with `[REDACTED]`.
    FullRedact,
    /// Show first N and last N characters, mask the middle with `*`.
    PartialMask { show_first: usize, show_last: usize },
    /// Replace with a fixed placeholder string.
    Placeholder(&'static str),
    /// No masking required.
    None,
}

impl MaskingStrategy {
    /// Apply this masking strategy to a string value.
    pub fn apply(&self, value: &str) -> String {
        match self {
            MaskingStrategy::FullRedact => "[REDACTED]".to_string(),
            MaskingStrategy::PartialMask {
                show_first,
                show_last,
            } => {
                let len = value.len();
                let first = (*show_first).min(len);
                let last = (*show_last).min(len.saturating_sub(first));
                if first + last >= len {
                    // Value too short to meaningfully mask — redact fully
                    return "[REDACTED]".to_string();
                }
                let masked_len = len - first - last;
                format!(
                    "{}{}{}",
                    &value[..first],
                    "*".repeat(masked_len),
                    &value[len - last..]
                )
            }
            MaskingStrategy::Placeholder(p) => p.to_string(),
            MaskingStrategy::None => value.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering_is_correct() {
        assert!(ClassificationTier::Critical > ClassificationTier::Restricted);
        assert!(ClassificationTier::Restricted > ClassificationTier::Confidential);
        assert!(ClassificationTier::Confidential > ClassificationTier::Internal);
        assert!(ClassificationTier::Internal > ClassificationTier::Public);
    }

    #[test]
    fn critical_tier_never_logs() {
        assert!(ClassificationTier::Critical.must_never_log());
        assert!(!ClassificationTier::Confidential.must_never_log());
    }

    #[test]
    fn masking_partial_mask() {
        let strategy = MaskingStrategy::PartialMask {
            show_first: 4,
            show_last: 4,
        };
        let result = strategy.apply("GABCDEFGHIJKLMNOPQRSTUVWXYZ1234");
        assert!(result.starts_with("GABC"));
        assert!(result.ends_with("1234"));
        assert!(result.contains('*'));
    }

    #[test]
    fn masking_full_redact() {
        let result = MaskingStrategy::FullRedact.apply("super-secret");
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn masking_short_value_redacts_fully() {
        let strategy = MaskingStrategy::PartialMask {
            show_first: 4,
            show_last: 4,
        };
        // Value shorter than show_first + show_last → full redact
        assert_eq!(strategy.apply("abc"), "[REDACTED]");
    }
}
