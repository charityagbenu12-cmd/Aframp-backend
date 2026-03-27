//! Policy engine — derives and enforces handling requirements for every
//! data field based on its classification tier and category.
//!
//! The engine is the single place where "what tier does this field have?"
//! translates into "what must we do with it?".  All enforcement utilities
//! call through here rather than hard-coding tier logic themselves.

use crate::data_classification::{
    registry::DataField,
    types::{ClassificationTier, DataCategory, HandlingRequirements, MaskingStrategy},
};

// ---------------------------------------------------------------------------
// Policy engine
// ---------------------------------------------------------------------------

/// Stateless policy engine.
///
/// All methods are pure functions — no state, no I/O.  Instantiate once and
/// share via `Arc` or use the module-level convenience functions.
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    /// Derive the full [`HandlingRequirements`] for a known [`DataField`].
    pub fn requirements_for_field(&self, field: DataField) -> HandlingRequirements {
        let tier = field.tier();
        let category = field.category();
        let masking_strategy = field.masking_strategy();
        self.build_requirements(tier, category, masking_strategy)
    }

    /// Derive [`HandlingRequirements`] for an ad-hoc tier + category pair.
    ///
    /// Use this when you have a tier/category but not a specific [`DataField`]
    /// variant (e.g., dynamic JSONB fields from provider responses).
    pub fn requirements_for(
        &self,
        tier: ClassificationTier,
        category: DataCategory,
    ) -> HandlingRequirements {
        let masking_strategy = default_masking_for_tier(tier);
        self.build_requirements(tier, category, masking_strategy)
    }

    fn build_requirements(
        &self,
        tier: ClassificationTier,
        category: DataCategory,
        masking_strategy: MaskingStrategy,
    ) -> HandlingRequirements {
        HandlingRequirements {
            tier,
            category,
            encrypt_at_rest: tier.requires_encryption_at_rest(),
            encrypt_in_transit: tier.requires_encryption_in_transit(),
            mask_in_logs: tier.requires_masking(),
            // Responses: mask Restricted+ but show Confidential amounts to the
            // authenticated owner (the enforcer layer handles ownership checks).
            mask_in_responses: tier >= ClassificationTier::Restricted,
            never_log: tier.must_never_log(),
            audit_on_access: tier.requires_access_audit(),
            retention_days: tier.default_retention_days(),
            masking_strategy,
        }
    }

    /// Returns `true` if the given tier is permitted to be included in a
    /// log line at the given log level.
    ///
    /// Rules:
    /// - `Critical` → never log regardless of level.
    /// - `Restricted` → only at TRACE level in non-production environments.
    /// - `Confidential` → only masked values; raw values never logged.
    /// - `Internal` / `Public` → always permitted.
    pub fn is_loggable(&self, tier: ClassificationTier, is_production: bool) -> bool {
        match tier {
            ClassificationTier::Critical => false,
            ClassificationTier::Restricted => !is_production,
            ClassificationTier::Confidential => true, // masked value is loggable
            ClassificationTier::Internal => true,
            ClassificationTier::Public => true,
        }
    }

    /// Returns `true` if a field at this tier may be included in an API
    /// response body without additional masking.
    ///
    /// Callers must still apply the masking strategy for Confidential fields.
    pub fn is_response_safe(&self, tier: ClassificationTier) -> bool {
        tier <= ClassificationTier::Confidential
    }

    /// Returns `true` if a field at this tier may be stored in a cache
    /// (Redis / in-process L1).
    ///
    /// Critical fields must never be cached.  Restricted fields may only be
    /// cached with encryption.
    pub fn is_cacheable(&self, tier: ClassificationTier) -> bool {
        tier < ClassificationTier::Critical
    }

    /// Returns `true` if a field at this tier may be included in a webhook
    /// payload sent to an external endpoint.
    pub fn is_webhook_safe(&self, tier: ClassificationTier) -> bool {
        tier <= ClassificationTier::Internal
    }
}

// ---------------------------------------------------------------------------
// Transmission policy
// ---------------------------------------------------------------------------

/// Transmission context — where is the data going?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmissionContext {
    /// Outbound HTTP response to an authenticated API client.
    ApiResponse,
    /// Outbound webhook delivery to a developer-registered endpoint.
    WebhookDelivery,
    /// Internal service-to-service call (same trust boundary).
    InternalRpc,
    /// Log line (structured JSON log).
    LogLine,
    /// Cache storage (Redis / in-process).
    Cache,
    /// Database persistence.
    Database,
}

/// Policy decision for a transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransmissionDecision {
    /// Allow as-is.
    Allow,
    /// Allow but apply the specified masking strategy first.
    AllowMasked(MaskingStrategy),
    /// Deny — this field must not be transmitted in this context.
    Deny { reason: &'static str },
}

impl PolicyEngine {
    /// Decide whether and how a field may be transmitted in a given context.
    pub fn transmission_decision(
        &self,
        field: DataField,
        context: TransmissionContext,
    ) -> TransmissionDecision {
        let tier = field.tier();
        let strategy = field.masking_strategy();

        match context {
            TransmissionContext::LogLine => {
                if tier.must_never_log() {
                    TransmissionDecision::Deny {
                        reason: "field tier is CRITICAL — must never appear in logs",
                    }
                } else if tier.requires_masking() {
                    TransmissionDecision::AllowMasked(strategy)
                } else {
                    TransmissionDecision::Allow
                }
            }

            TransmissionContext::ApiResponse => {
                if tier >= ClassificationTier::Critical {
                    TransmissionDecision::Deny {
                        reason: "CRITICAL fields must never be included in API responses",
                    }
                } else if tier >= ClassificationTier::Restricted {
                    TransmissionDecision::AllowMasked(strategy)
                } else {
                    TransmissionDecision::Allow
                }
            }

            TransmissionContext::WebhookDelivery => {
                if tier >= ClassificationTier::Restricted {
                    TransmissionDecision::Deny {
                        reason: "Restricted/Critical fields must not be sent in webhook payloads",
                    }
                } else if tier >= ClassificationTier::Confidential {
                    TransmissionDecision::AllowMasked(strategy)
                } else {
                    TransmissionDecision::Allow
                }
            }

            TransmissionContext::InternalRpc => {
                // Internal calls within the same trust boundary may carry
                // Confidential data but never Critical plaintext.
                if tier >= ClassificationTier::Critical {
                    TransmissionDecision::Deny {
                        reason: "CRITICAL fields must not be passed over RPC — use references",
                    }
                } else {
                    TransmissionDecision::Allow
                }
            }

            TransmissionContext::Cache => {
                if tier >= ClassificationTier::Critical {
                    TransmissionDecision::Deny {
                        reason: "CRITICAL fields must never be cached",
                    }
                } else {
                    // Restricted fields may be cached but must be encrypted;
                    // the cache layer is responsible for that.
                    TransmissionDecision::Allow
                }
            }

            TransmissionContext::Database => {
                // Database always allows storage; encryption-at-rest is
                // enforced at the infrastructure level (column encryption /
                // tablespace encryption).  Critical fields must be hashed
                // before storage — that is enforced at the service layer.
                TransmissionDecision::Allow
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_masking_for_tier(tier: ClassificationTier) -> MaskingStrategy {
    match tier {
        ClassificationTier::Critical | ClassificationTier::Restricted => {
            MaskingStrategy::FullRedact
        }
        ClassificationTier::Confidential => MaskingStrategy::PartialMask {
            show_first: 2,
            show_last: 2,
        },
        ClassificationTier::Internal | ClassificationTier::Public => MaskingStrategy::None,
    }
}

// ---------------------------------------------------------------------------
// Module-level convenience functions
// ---------------------------------------------------------------------------

/// Convenience: get requirements for a field without constructing the engine.
pub fn requirements_for_field(field: DataField) -> HandlingRequirements {
    PolicyEngine::default().requirements_for_field(field)
}

/// Convenience: get the transmission decision for a field in a context.
pub fn transmission_decision(
    field: DataField,
    context: TransmissionContext,
) -> TransmissionDecision {
    PolicyEngine::default().transmission_decision(field, context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_classification::registry::DataField;

    #[test]
    fn private_key_denied_in_logs() {
        let decision =
            transmission_decision(DataField::WalletPrivateKey, TransmissionContext::LogLine);
        assert!(matches!(decision, TransmissionDecision::Deny { .. }));
    }

    #[test]
    fn private_key_denied_in_api_response() {
        let decision =
            transmission_decision(DataField::WalletPrivateKey, TransmissionContext::ApiResponse);
        assert!(matches!(decision, TransmissionDecision::Deny { .. }));
    }

    #[test]
    fn private_key_denied_in_cache() {
        let decision =
            transmission_decision(DataField::WalletPrivateKey, TransmissionContext::Cache);
        assert!(matches!(decision, TransmissionDecision::Deny { .. }));
    }

    #[test]
    fn email_masked_in_logs() {
        let decision = transmission_decision(DataField::UserEmail, TransmissionContext::LogLine);
        assert!(matches!(decision, TransmissionDecision::AllowMasked(_)));
    }

    #[test]
    fn currency_code_allowed_everywhere() {
        for ctx in [
            TransmissionContext::LogLine,
            TransmissionContext::ApiResponse,
            TransmissionContext::WebhookDelivery,
            TransmissionContext::Cache,
            TransmissionContext::Database,
        ] {
            let decision = transmission_decision(DataField::CurrencyCode, ctx);
            assert_eq!(decision, TransmissionDecision::Allow);
        }
    }

    #[test]
    fn kyc_document_image_denied_in_webhook() {
        let decision = transmission_decision(
            DataField::KycDocumentImageRef,
            TransmissionContext::WebhookDelivery,
        );
        assert!(matches!(decision, TransmissionDecision::Deny { .. }));
    }

    #[test]
    fn requirements_for_email_has_correct_flags() {
        let req = requirements_for_field(DataField::UserEmail);
        assert!(req.encrypt_at_rest);
        assert!(req.encrypt_in_transit);
        assert!(req.mask_in_logs);
        assert!(!req.never_log);
        assert!(!req.audit_on_access);
    }

    #[test]
    fn requirements_for_private_key_never_log() {
        let req = requirements_for_field(DataField::WalletPrivateKey);
        assert!(req.never_log);
        assert!(req.encrypt_at_rest);
        assert!(req.audit_on_access);
    }
}
