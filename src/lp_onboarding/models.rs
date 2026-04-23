use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sqlx::types::BigDecimal;

// ── Enums ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "lp_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LpStatus {
    DocumentsPending,
    LegalReview,
    KybScreening,
    AgreementPending,
    Trial,
    Active,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "lp_tier", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LpTier {
    Trial,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "lp_doc_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LpDocType {
    CertificateOfIncorporation,
    TaxId,
    ProofOfAddress,
    AmlPolicy,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "lp_doc_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LpDocStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "agreement_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AgreementStatus {
    Draft,
    SentForSignature,
    Signed,
    Expired,
    Superseded,
}

// ── Core models ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LpPartner {
    pub partner_id: Uuid,
    pub legal_name: String,
    pub registration_number: Option<String>,
    pub tax_id: Option<String>,
    pub jurisdiction: String,
    pub contact_email: String,
    pub contact_name: String,
    pub status: LpStatus,
    pub tier: LpTier,
    pub daily_volume_cap: BigDecimal,
    pub monthly_volume_cap: BigDecimal,
    pub kyb_reference_id: Option<Uuid>,
    pub kyb_passed_at: Option<DateTime<Utc>>,
    pub reviewed_by: Option<Uuid>,
    pub revoked_by: Option<Uuid>,
    pub revocation_reason: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LpDocument {
    pub document_id: Uuid,
    pub partner_id: Uuid,
    pub doc_type: LpDocType,
    pub file_name: String,
    pub storage_key: String,
    pub doc_status: LpDocStatus,
    pub reviewed_by: Option<Uuid>,
    pub review_note: Option<String>,
    pub uploaded_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LpAgreement {
    pub agreement_id: Uuid,
    pub partner_id: Uuid,
    pub version: String,
    pub agreement_status: AgreementStatus,
    pub docusign_envelope_id: Option<String>,
    pub signed_at: Option<DateTime<Utc>>,
    pub document_hash: Option<String>,
    pub effective_from: NaiveDate,
    pub expires_on: NaiveDate,
    pub expiry_alert_30d_sent: bool,
    pub expiry_alert_7d_sent: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LpStellarKey {
    pub key_id: Uuid,
    pub partner_id: Uuid,
    pub stellar_address: String,
    pub label: Option<String>,
    pub is_active: bool,
    pub added_by: Uuid,
    pub revoked_by: Option<Uuid>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ── Request / Response DTOs ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterPartnerRequest {
    pub legal_name: String,
    pub registration_number: Option<String>,
    pub tax_id: Option<String>,
    pub jurisdiction: String,
    pub contact_email: String,
    pub contact_name: String,
}

#[derive(Debug, Deserialize)]
pub struct UploadDocumentRequest {
    pub doc_type: LpDocType,
    pub file_name: String,
    pub storage_key: String,
}

#[derive(Debug, Deserialize)]
pub struct ReviewDocumentRequest {
    pub doc_status: LpDocStatus,
    pub review_note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAgreementRequest {
    pub version: String,
    pub effective_from: NaiveDate,
    pub expires_on: NaiveDate,
}

#[derive(Debug, Deserialize)]
pub struct DocuSignWebhookPayload {
    pub envelope_id: String,
    pub status: String,          // "completed" | "declined" | etc.
    pub document_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddStellarKeyRequest {
    pub stellar_address: String,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePartnerTierRequest {
    pub tier: LpTier,
    pub daily_volume_cap: BigDecimal,
    pub monthly_volume_cap: BigDecimal,
}

#[derive(Debug, Deserialize)]
pub struct RevokePartnerRequest {
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct PartnerDashboard {
    pub partner: LpPartner,
    pub documents: Vec<LpDocument>,
    pub active_agreement: Option<LpAgreement>,
    pub stellar_keys: Vec<LpStellarKey>,
}
