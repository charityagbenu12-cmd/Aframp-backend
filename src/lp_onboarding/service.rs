use crate::lp_onboarding::{models::*, repository::LpOnboardingRepository};
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct LpOnboardingService {
    repo: Arc<LpOnboardingRepository>,
    http: Client,
    docusign_base_url: String,
    docusign_account_id: String,
    docusign_access_token: String,
}

impl LpOnboardingService {
    pub fn new(
        repo: Arc<LpOnboardingRepository>,
        docusign_base_url: String,
        docusign_account_id: String,
        docusign_access_token: String,
    ) -> Self {
        Self {
            repo,
            http: Client::new(),
            docusign_base_url,
            docusign_account_id,
            docusign_access_token,
        }
    }

    // ── Partner registration ──────────────────────────────────────────────────

    pub async fn register_partner(
        &self,
        req: RegisterPartnerRequest,
    ) -> Result<LpPartner, ServiceError> {
        let partner = self.repo.create_partner(&req).await?;
        info!(partner_id=%partner.partner_id, "LP partner registered");
        Ok(partner)
    }

    // ── Document management ───────────────────────────────────────────────────

    pub async fn upload_document(
        &self,
        partner_id: Uuid,
        req: UploadDocumentRequest,
    ) -> Result<LpDocument, ServiceError> {
        self.require_partner_exists(partner_id).await?;
        let doc = self.repo.add_document(partner_id, &req).await?;
        info!(partner_id=%partner_id, doc_type=?doc.doc_type, "Document uploaded");
        Ok(doc)
    }

    pub async fn review_document(
        &self,
        document_id: Uuid,
        reviewer_id: Uuid,
        req: ReviewDocumentRequest,
    ) -> Result<(), ServiceError> {
        self.repo.review_document(document_id, reviewer_id, &req).await?;
        // If all required docs are approved, advance partner to legal_review
        Ok(())
    }

    // ── Agreement lifecycle ───────────────────────────────────────────────────

    /// Create a draft agreement and dispatch it to DocuSign for e-signature.
    pub async fn send_agreement_for_signature(
        &self,
        partner_id: Uuid,
        req: CreateAgreementRequest,
        signer_email: String,
        signer_name: String,
    ) -> Result<LpAgreement, ServiceError> {
        let partner = self.require_partner_exists(partner_id).await?;

        // Ensure KYB has passed before sending agreement
        if partner.kyb_passed_at.is_none() {
            return Err(ServiceError::KybNotPassed);
        }

        let agreement = self.repo.create_agreement(partner_id, &req).await?;

        // Call DocuSign Envelopes API
        let envelope_id = self
            .create_docusign_envelope(&agreement, &signer_email, &signer_name)
            .await?;

        self.repo
            .mark_agreement_sent(agreement.agreement_id, &envelope_id)
            .await?;

        info!(
            partner_id=%partner_id,
            agreement_id=%agreement.agreement_id,
            envelope_id=%envelope_id,
            "Agreement sent for signature"
        );

        let mut updated = agreement;
        updated.agreement_status = AgreementStatus::SentForSignature;
        updated.docusign_envelope_id = Some(envelope_id);
        Ok(updated)
    }

    /// Handle DocuSign webhook callback when signer completes.
    pub async fn handle_docusign_webhook(
        &self,
        payload: DocuSignWebhookPayload,
    ) -> Result<(), ServiceError> {
        if payload.status != "completed" {
            warn!(envelope_id=%payload.envelope_id, status=%payload.status, "DocuSign non-completion event");
            return Ok(());
        }

        let hash = payload
            .document_hash
            .unwrap_or_else(|| format!("sha256:{}", Uuid::new_v4()));

        let agreement = self
            .repo
            .mark_agreement_signed(&payload.envelope_id, &hash)
            .await?
            .ok_or(ServiceError::AgreementNotFound)?;

        // Advance partner to Trial status and activate API access
        self.repo
            .update_partner_status(agreement.partner_id, LpStatus::Trial, None)
            .await?;

        info!(
            partner_id=%agreement.partner_id,
            agreement_id=%agreement.agreement_id,
            "Agreement signed — partner promoted to Trial"
        );
        Ok(())
    }

    // ── Stellar key management ────────────────────────────────────────────────

    pub async fn add_stellar_key(
        &self,
        partner_id: Uuid,
        added_by: Uuid,
        req: AddStellarKeyRequest,
    ) -> Result<LpStellarKey, ServiceError> {
        let partner = self.require_partner_exists(partner_id).await?;

        // Only active/trial partners may register keys
        if !matches!(partner.status, LpStatus::Trial | LpStatus::Active) {
            return Err(ServiceError::PartnerNotActive);
        }

        // Validate G-address format (56 chars, starts with G)
        if !is_valid_stellar_address(&req.stellar_address) {
            return Err(ServiceError::InvalidStellarAddress);
        }

        // Ensure a signed agreement exists
        self.repo
            .get_active_agreement(partner_id)
            .await?
            .ok_or(ServiceError::NoSignedAgreement)?;

        let key = self.repo.add_stellar_key(partner_id, added_by, &req).await?;
        info!(partner_id=%partner_id, stellar_address=%key.stellar_address, "Stellar key allowlisted");
        Ok(key)
    }

    pub async fn revoke_stellar_key(
        &self,
        key_id: Uuid,
        revoked_by: Uuid,
    ) -> Result<(), ServiceError> {
        self.repo.revoke_stellar_key(key_id, revoked_by).await?;
        info!(key_id=%key_id, "Stellar key revoked");
        Ok(())
    }

    pub async fn is_address_allowed(&self, stellar_address: &str) -> Result<bool, ServiceError> {
        Ok(self.repo.is_stellar_address_allowed(stellar_address).await?)
    }

    // ── Admin actions ─────────────────────────────────────────────────────────

    pub async fn update_tier(
        &self,
        partner_id: Uuid,
        req: UpdatePartnerTierRequest,
    ) -> Result<(), ServiceError> {
        self.require_partner_exists(partner_id).await?;
        self.repo.update_partner_tier(partner_id, &req).await?;
        info!(partner_id=%partner_id, tier=?req.tier, "Partner tier updated");
        Ok(())
    }

    pub async fn revoke_partner(
        &self,
        partner_id: Uuid,
        revoked_by: Uuid,
        req: RevokePartnerRequest,
    ) -> Result<(), ServiceError> {
        self.require_partner_exists(partner_id).await?;
        self.repo.revoke_partner(partner_id, revoked_by, &req.reason).await?;
        // Revoke all active stellar keys immediately
        let keys = self.repo.list_stellar_keys(partner_id).await?;
        for key in keys.into_iter().filter(|k| k.is_active) {
            if let Err(e) = self.repo.revoke_stellar_key(key.key_id, revoked_by).await {
                error!(key_id=%key.key_id, error=%e, "Failed to revoke stellar key during partner revocation");
            }
        }
        info!(partner_id=%partner_id, "Partner revoked — all keys deactivated");
        Ok(())
    }

    pub async fn mark_kyb_passed(
        &self,
        partner_id: Uuid,
        kyb_ref: Uuid,
    ) -> Result<(), ServiceError> {
        self.repo.set_kyb_passed(partner_id, kyb_ref).await?;
        info!(partner_id=%partner_id, kyb_ref=%kyb_ref, "KYB passed for LP partner");
        Ok(())
    }

    pub async fn get_dashboard(
        &self,
        partner_id: Uuid,
    ) -> Result<PartnerDashboard, ServiceError> {
        self.repo
            .get_dashboard(partner_id)
            .await?
            .ok_or(ServiceError::PartnerNotFound)
    }

    pub async fn list_partners(
        &self,
        status: Option<LpStatus>,
    ) -> Result<Vec<LpPartner>, ServiceError> {
        Ok(self.repo.list_partners(status).await?)
    }

    // ── DocuSign integration ──────────────────────────────────────────────────

    async fn create_docusign_envelope(
        &self,
        agreement: &LpAgreement,
        signer_email: &str,
        signer_name: &str,
    ) -> Result<String, ServiceError> {
        let url = format!(
            "{}/v2.1/accounts/{}/envelopes",
            self.docusign_base_url, self.docusign_account_id
        );

        let body = json!({
            "emailSubject": format!("Liquidity Provision Agreement {} — Please Sign", agreement.version),
            "documents": [{
                "documentId": "1",
                "name": format!("LPA_{}.pdf", agreement.version),
                "fileExtension": "pdf",
                "documentBase64": "" // populated by caller with actual PDF bytes
            }],
            "recipients": {
                "signers": [{
                    "email": signer_email,
                    "name": signer_name,
                    "recipientId": "1",
                    "tabs": {
                        "signHereTabs": [{"documentId":"1","pageNumber":"1","xPosition":"100","yPosition":"700"}]
                    }
                }]
            },
            "status": "sent"
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.docusign_access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ServiceError::DocuSignError(e.to_string()))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ServiceError::DocuSignError(text));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ServiceError::DocuSignError(e.to_string()))?;

        json["envelopeId"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ServiceError::DocuSignError("missing envelopeId".into()))
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    async fn require_partner_exists(&self, partner_id: Uuid) -> Result<LpPartner, ServiceError> {
        self.repo
            .get_partner(partner_id)
            .await?
            .ok_or(ServiceError::PartnerNotFound)
    }
}

fn is_valid_stellar_address(addr: &str) -> bool {
    addr.len() == 56 && addr.starts_with('G') && addr.chars().all(|c| c.is_ascii_alphanumeric())
}

pub fn hash_document(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Partner not found")]
    PartnerNotFound,
    #[error("Agreement not found")]
    AgreementNotFound,
    #[error("Partner is not in an active or trial state")]
    PartnerNotActive,
    #[error("KYB screening has not passed")]
    KybNotPassed,
    #[error("No signed agreement on file")]
    NoSignedAgreement,
    #[error("Invalid Stellar G-address format")]
    InvalidStellarAddress,
    #[error("DocuSign error: {0}")]
    DocuSignError(String),
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),
}
