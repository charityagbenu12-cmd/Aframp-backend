//! Authoritative data field registry.
//!
//! Every field that flows through the Aframp platform is registered here with
//! its classification tier, category, and masking strategy.  This is the
//! single source of truth that the policy engine, log sanitiser, and
//! serialisation guards consult.
//!
//! # Adding a new field
//!
//! 1. Add a variant to [`DataField`].
//! 2. Implement the three methods on the `DataField` impl block.
//! 3. Add a test case in the `tests` module.

use crate::data_classification::types::{ClassificationTier, DataCategory, MaskingStrategy};

/// Every named data field on the platform, mapped to its classification.
///
/// Variants are grouped by domain for readability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataField {
    // ── User / Identity ─────────────────────────────────────────────────────
    UserEmail,
    UserPhone,
    UserFullName,
    UserDateOfBirth,
    UserPhysicalAddress,

    // ── KYC / Identity Documents ────────────────────────────────────────────
    KycDocumentNumber,
    KycDocumentType,
    KycDocumentImageRef,
    KycSelfieImageRef,
    KycIssuingCountry,
    KycExpiryDate,
    KycVerificationStatus,
    KycVerificationTier,
    KycRiskScore,
    KycEddTriggerReason,
    KycEddCaseDetails,
    KycManualReviewReason,
    KycVerificationSessionId,
    KycVerificationProvider,

    // ── Wallet / Blockchain ──────────────────────────────────────────────────
    WalletAddress,
    WalletPrivateKey,
    WalletSecretSeed,
    BlockchainTxHash,
    CryptoBalance,
    CngnBalance,

    // ── Transactions ─────────────────────────────────────────────────────────
    TransactionId,
    TransactionAmount,
    TransactionFromAmount,
    TransactionToAmount,
    TransactionAfriAmount,
    TransactionStatus,
    TransactionPaymentReference,
    TransactionErrorMessage,
    TransactionMetadata,

    // ── Payment Methods ──────────────────────────────────────────────────────
    PaymentMethodEncryptedData,
    PaymentMethodPhoneNumber,
    BankAccountNumber,
    BankAccountName,
    BankCode,
    CardPan,
    CardToken,
    BillAccountNumber,

    // ── Authentication ───────────────────────────────────────────────────────
    JwtAccessToken,
    JwtRefreshToken,
    JwtSessionId,
    JwtJti,
    ApiKeyPlaintext,
    ApiKeyHash,
    ApiKeyPrefix,
    OAuthClientId,
    OAuthClientSecretHash,
    OAuthRedirectUri,
    TotpSecretSeed,

    // ── Provider Credentials ─────────────────────────────────────────────────
    PaystackSecretKey,
    FlutterwaveSecretKey,
    MpesaConsumerKey,
    MpesaConsumerSecret,
    MpesaPasskey,
    WebhookSignatureSecret,
    WebhookPayload,
    WebhookSignature,

    // ── Compliance / Risk ────────────────────────────────────────────────────
    IpAddress,
    IpReputationScore,
    GeoCountryCode,
    ComplianceFlag,
    AmlAlertDetails,

    // ── Operational / Audit ──────────────────────────────────────────────────
    ExchangeRate,
    FeeAmount,
    FeeStructureDetails,
    AuditLogEntry,
    AdminActionDetail,
    RequestIntegrityHash,
    ErrorStackTrace,

    // ── Public ───────────────────────────────────────────────────────────────
    CurrencyCode,
    SupportedChain,
    ApiVersion,
    HealthStatus,
}

impl DataField {
    /// The classification tier for this field.
    pub fn tier(&self) -> ClassificationTier {
        match self {
            // ── Critical ────────────────────────────────────────────────────
            DataField::WalletPrivateKey
            | DataField::WalletSecretSeed
            | DataField::ApiKeyPlaintext
            | DataField::OAuthClientSecretHash
            | DataField::TotpSecretSeed
            | DataField::PaystackSecretKey
            | DataField::FlutterwaveSecretKey
            | DataField::MpesaConsumerKey
            | DataField::MpesaConsumerSecret
            | DataField::MpesaPasskey
            | DataField::WebhookSignatureSecret
            | DataField::CardPan => ClassificationTier::Critical,

            // ── Restricted ──────────────────────────────────────────────────
            DataField::KycDocumentNumber
            | DataField::KycDocumentImageRef
            | DataField::KycSelfieImageRef
            | DataField::KycExpiryDate
            | DataField::KycEddCaseDetails
            | DataField::KycManualReviewReason
            | DataField::UserFullName
            | DataField::UserDateOfBirth
            | DataField::UserPhysicalAddress
            | DataField::JwtAccessToken
            | DataField::JwtRefreshToken
            | DataField::BankAccountNumber
            | DataField::AmlAlertDetails => ClassificationTier::Restricted,

            // ── Confidential ────────────────────────────────────────────────
            DataField::UserEmail
            | DataField::UserPhone
            | DataField::WalletAddress
            | DataField::CryptoBalance
            | DataField::CngnBalance
            | DataField::TransactionAmount
            | DataField::TransactionFromAmount
            | DataField::TransactionToAmount
            | DataField::TransactionAfriAmount
            | DataField::TransactionPaymentReference
            | DataField::PaymentMethodEncryptedData
            | DataField::PaymentMethodPhoneNumber
            | DataField::BankAccountName
            | DataField::CardToken
            | DataField::BillAccountNumber
            | DataField::KycVerificationStatus
            | DataField::KycVerificationTier
            | DataField::KycRiskScore
            | DataField::KycEddTriggerReason
            | DataField::KycVerificationSessionId
            | DataField::IpAddress
            | DataField::ComplianceFlag
            | DataField::BlockchainTxHash
            | DataField::FiatAmount
            | DataField::ApiKeyHash
            | DataField::JwtSessionId
            | DataField::JwtJti
            | DataField::WebhookSignature => ClassificationTier::Confidential,

            // ── Internal ────────────────────────────────────────────────────
            DataField::ExchangeRate
            | DataField::FeeAmount
            | DataField::FeeStructureDetails
            | DataField::AuditLogEntry
            | DataField::AdminActionDetail
            | DataField::RequestIntegrityHash
            | DataField::ErrorStackTrace
            | DataField::TransactionErrorMessage
            | DataField::TransactionMetadata
            | DataField::WebhookPayload
            | DataField::IpReputationScore
            | DataField::GeoCountryCode
            | DataField::KycDocumentType
            | DataField::KycIssuingCountry
            | DataField::KycVerificationProvider
            | DataField::OAuthClientId
            | DataField::OAuthRedirectUri
            | DataField::ApiKeyPrefix
            | DataField::BankCode
            | DataField::TransactionId => ClassificationTier::Internal,

            // ── Public ──────────────────────────────────────────────────────
            DataField::CurrencyCode
            | DataField::SupportedChain
            | DataField::ApiVersion
            | DataField::HealthStatus
            | DataField::TransactionStatus => ClassificationTier::Public,
        }
    }

    /// The data category this field belongs to.
    pub fn category(&self) -> DataCategory {
        match self {
            DataField::UserEmail => DataCategory::Email,
            DataField::UserPhone => DataCategory::PhoneNumber,
            DataField::UserFullName => DataCategory::FullName,
            DataField::UserDateOfBirth => DataCategory::DateOfBirth,
            DataField::UserPhysicalAddress => DataCategory::PhysicalAddress,

            DataField::KycDocumentNumber
            | DataField::KycDocumentType
            | DataField::KycIssuingCountry
            | DataField::KycExpiryDate => DataCategory::GovernmentId,
            DataField::KycDocumentImageRef => DataCategory::IdentityDocument,
            DataField::KycSelfieImageRef => DataCategory::BiometricData,
            DataField::KycVerificationStatus | DataField::KycVerificationTier => {
                DataCategory::KycStatus
            }
            DataField::KycRiskScore | DataField::KycEddTriggerReason => DataCategory::RiskScore,
            DataField::KycEddCaseDetails => DataCategory::EnhancedDueDiligenceData,
            DataField::KycManualReviewReason => DataCategory::ManualReviewData,
            DataField::KycVerificationSessionId | DataField::KycVerificationProvider => {
                DataCategory::KycStatus
            }

            DataField::WalletAddress => DataCategory::WalletAddress,
            DataField::WalletPrivateKey | DataField::WalletSecretSeed => DataCategory::PrivateKey,
            DataField::BlockchainTxHash => DataCategory::BlockchainTxHash,
            DataField::CryptoBalance | DataField::CngnBalance => DataCategory::CryptoBalance,

            DataField::TransactionId
            | DataField::TransactionStatus
            | DataField::TransactionPaymentReference
            | DataField::TransactionErrorMessage
            | DataField::TransactionMetadata => DataCategory::TransactionStatus,
            DataField::TransactionAmount
            | DataField::TransactionFromAmount
            | DataField::TransactionToAmount
            | DataField::TransactionAfriAmount
            | DataField::FiatAmount => DataCategory::TransactionAmount,

            DataField::PaymentMethodEncryptedData | DataField::CardToken => {
                DataCategory::CardToken
            }
            DataField::PaymentMethodPhoneNumber | DataField::BillAccountNumber => {
                DataCategory::MobileMoneyIdentifier
            }
            DataField::BankAccountNumber => DataCategory::BankAccountNumber,
            DataField::BankAccountName | DataField::BankCode => {
                DataCategory::BankAccountNumberMasked
            }
            DataField::CardPan => DataCategory::CardPan,

            DataField::JwtAccessToken => DataCategory::JwtToken,
            DataField::JwtRefreshToken => DataCategory::RefreshToken,
            DataField::JwtSessionId | DataField::JwtJti => DataCategory::JwtToken,
            DataField::ApiKeyPlaintext => DataCategory::ApiKeyPlaintext,
            DataField::ApiKeyHash | DataField::ApiKeyPrefix => DataCategory::CredentialHash,
            DataField::OAuthClientId
            | DataField::OAuthClientSecretHash
            | DataField::OAuthRedirectUri => DataCategory::OAuthClientSecret,
            DataField::TotpSecretSeed => DataCategory::TotpSecret,

            DataField::PaystackSecretKey
            | DataField::FlutterwaveSecretKey
            | DataField::MpesaConsumerKey
            | DataField::MpesaConsumerSecret
            | DataField::MpesaPasskey => DataCategory::ProviderSecretKey,
            DataField::WebhookSignatureSecret => DataCategory::WebhookSecret,
            DataField::WebhookPayload => DataCategory::WebhookPayload,
            DataField::WebhookSignature => DataCategory::WebhookSecret,

            DataField::IpAddress => DataCategory::IpAddress,
            DataField::IpReputationScore => DataCategory::RiskScore,
            DataField::GeoCountryCode => DataCategory::PublicApiMetadata,
            DataField::ComplianceFlag | DataField::AmlAlertDetails => {
                DataCategory::ComplianceFlag
            }

            DataField::ExchangeRate => DataCategory::ExchangeRate,
            DataField::FeeAmount | DataField::FeeStructureDetails => DataCategory::FeeStructure,
            DataField::AuditLogEntry | DataField::AdminActionDetail => DataCategory::AuditLogEntry,
            DataField::RequestIntegrityHash => DataCategory::RequestIntegrityHash,
            DataField::ErrorStackTrace => DataCategory::ErrorMessage,

            DataField::CurrencyCode => DataCategory::CurrencyCode,
            DataField::SupportedChain
            | DataField::ApiVersion
            | DataField::HealthStatus => DataCategory::PublicApiMetadata,
        }
    }

    /// The masking strategy to apply when this field must be masked.
    pub fn masking_strategy(&self) -> MaskingStrategy {
        match self {
            // Never show any part of these
            DataField::WalletPrivateKey
            | DataField::WalletSecretSeed
            | DataField::ApiKeyPlaintext
            | DataField::OAuthClientSecretHash
            | DataField::TotpSecretSeed
            | DataField::PaystackSecretKey
            | DataField::FlutterwaveSecretKey
            | DataField::MpesaConsumerKey
            | DataField::MpesaConsumerSecret
            | DataField::MpesaPasskey
            | DataField::WebhookSignatureSecret
            | DataField::CardPan
            | DataField::JwtAccessToken
            | DataField::JwtRefreshToken
            | DataField::ApiKeyHash
            | DataField::KycDocumentImageRef
            | DataField::KycSelfieImageRef
            | DataField::KycEddCaseDetails
            | DataField::AmlAlertDetails => MaskingStrategy::FullRedact,

            // Email: show domain only → user@***.com → u***@***.com
            DataField::UserEmail => MaskingStrategy::PartialMask {
                show_first: 2,
                show_last: 4,
            },

            // Phone: show last 4 digits
            DataField::UserPhone | DataField::PaymentMethodPhoneNumber => {
                MaskingStrategy::PartialMask {
                    show_first: 0,
                    show_last: 4,
                }
            }

            // Wallet address: show first 4 + last 4 (Stellar convention)
            DataField::WalletAddress => MaskingStrategy::PartialMask {
                show_first: 4,
                show_last: 4,
            },

            // Bank account: show last 4
            DataField::BankAccountNumber | DataField::BillAccountNumber => {
                MaskingStrategy::PartialMask {
                    show_first: 0,
                    show_last: 4,
                }
            }

            // KYC document number: show last 4
            DataField::KycDocumentNumber => MaskingStrategy::PartialMask {
                show_first: 0,
                show_last: 4,
            },

            // Names / DOB: full redact in logs
            DataField::UserFullName
            | DataField::UserDateOfBirth
            | DataField::UserPhysicalAddress
            | DataField::BankAccountName => MaskingStrategy::FullRedact,

            // Transaction amounts: show as-is in responses (needed for UX), redact in logs
            DataField::TransactionAmount
            | DataField::TransactionFromAmount
            | DataField::TransactionToAmount
            | DataField::TransactionAfriAmount
            | DataField::FiatAmount
            | DataField::CryptoBalance
            | DataField::CngnBalance => MaskingStrategy::Placeholder("[AMOUNT]"),

            // IP address: mask last octet
            DataField::IpAddress => MaskingStrategy::PartialMask {
                show_first: 7,
                show_last: 0,
            },

            // Webhook signature: full redact
            DataField::WebhookSignature => MaskingStrategy::FullRedact,

            // Everything else at Confidential/Internal: full redact
            _ => MaskingStrategy::FullRedact,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_is_critical() {
        assert_eq!(DataField::WalletPrivateKey.tier(), ClassificationTier::Critical);
    }

    #[test]
    fn email_is_confidential() {
        assert_eq!(DataField::UserEmail.tier(), ClassificationTier::Confidential);
    }

    #[test]
    fn transaction_status_is_public() {
        assert_eq!(DataField::TransactionStatus.tier(), ClassificationTier::Public);
    }

    #[test]
    fn kyc_document_image_is_restricted() {
        assert_eq!(
            DataField::KycDocumentImageRef.tier(),
            ClassificationTier::Restricted
        );
    }

    #[test]
    fn wallet_address_masking() {
        let strategy = DataField::WalletAddress.masking_strategy();
        let addr = "GABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRS";
        let masked = strategy.apply(addr);
        assert!(masked.starts_with("GABC"));
        assert!(masked.ends_with("PQRS"));
    }

    #[test]
    fn phone_masking_shows_last_four() {
        let strategy = DataField::UserPhone.masking_strategy();
        let masked = strategy.apply("+2348012345678");
        assert!(masked.ends_with("5678"));
    }
}
