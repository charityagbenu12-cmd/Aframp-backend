use crate::lp_onboarding::models::*;
use sqlx::PgPool;
use uuid::Uuid;
use chrono::Utc;

pub struct LpOnboardingRepository {
    pool: PgPool,
}

impl LpOnboardingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ── Partners ──────────────────────────────────────────────────────────────

    pub async fn create_partner(&self, req: &RegisterPartnerRequest) -> sqlx::Result<LpPartner> {
        sqlx::query_as!(
            LpPartner,
            r#"INSERT INTO lp_partners
               (legal_name, registration_number, tax_id, jurisdiction, contact_email, contact_name)
               VALUES ($1,$2,$3,$4,$5,$6)
               RETURNING
                 partner_id, legal_name, registration_number, tax_id, jurisdiction,
                 contact_email, contact_name,
                 status AS "status: LpStatus",
                 tier   AS "tier: LpTier",
                 daily_volume_cap, monthly_volume_cap,
                 kyb_reference_id, kyb_passed_at,
                 reviewed_by, revoked_by, revocation_reason, revoked_at,
                 created_at, updated_at"#,
            req.legal_name,
            req.registration_number,
            req.tax_id,
            req.jurisdiction,
            req.contact_email,
            req.contact_name,
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_partner(&self, partner_id: Uuid) -> sqlx::Result<Option<LpPartner>> {
        sqlx::query_as!(
            LpPartner,
            r#"SELECT partner_id, legal_name, registration_number, tax_id, jurisdiction,
                      contact_email, contact_name,
                      status AS "status: LpStatus",
                      tier   AS "tier: LpTier",
                      daily_volume_cap, monthly_volume_cap,
                      kyb_reference_id, kyb_passed_at,
                      reviewed_by, revoked_by, revocation_reason, revoked_at,
                      created_at, updated_at
               FROM lp_partners WHERE partner_id = $1"#,
            partner_id
        )
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn list_partners(&self, status: Option<LpStatus>) -> sqlx::Result<Vec<LpPartner>> {
        sqlx::query_as!(
            LpPartner,
            r#"SELECT partner_id, legal_name, registration_number, tax_id, jurisdiction,
                      contact_email, contact_name,
                      status AS "status: LpStatus",
                      tier   AS "tier: LpTier",
                      daily_volume_cap, monthly_volume_cap,
                      kyb_reference_id, kyb_passed_at,
                      reviewed_by, revoked_by, revocation_reason, revoked_at,
                      created_at, updated_at
               FROM lp_partners
               WHERE ($1::lp_status IS NULL OR status = $1)
               ORDER BY created_at DESC"#,
            status as Option<LpStatus>
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn update_partner_status(
        &self,
        partner_id: Uuid,
        status: LpStatus,
        reviewed_by: Option<Uuid>,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "UPDATE lp_partners SET status=$1, reviewed_by=$2, updated_at=NOW()
             WHERE partner_id=$3",
            status as LpStatus,
            reviewed_by,
            partner_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_partner_tier(
        &self,
        partner_id: Uuid,
        req: &UpdatePartnerTierRequest,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "UPDATE lp_partners
             SET tier=$1, daily_volume_cap=$2, monthly_volume_cap=$3, updated_at=NOW()
             WHERE partner_id=$4",
            req.tier as LpTier,
            req.daily_volume_cap,
            req.monthly_volume_cap,
            partner_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn revoke_partner(
        &self,
        partner_id: Uuid,
        revoked_by: Uuid,
        reason: &str,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "UPDATE lp_partners
             SET status='revoked', revoked_by=$1, revocation_reason=$2, revoked_at=NOW(), updated_at=NOW()
             WHERE partner_id=$3",
            revoked_by,
            reason,
            partner_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_kyb_passed(&self, partner_id: Uuid, kyb_ref: Uuid) -> sqlx::Result<()> {
        sqlx::query!(
            "UPDATE lp_partners
             SET kyb_reference_id=$1, kyb_passed_at=NOW(), status='agreement_pending', updated_at=NOW()
             WHERE partner_id=$2",
            kyb_ref,
            partner_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Documents ─────────────────────────────────────────────────────────────

    pub async fn add_document(
        &self,
        partner_id: Uuid,
        req: &UploadDocumentRequest,
    ) -> sqlx::Result<LpDocument> {
        sqlx::query_as!(
            LpDocument,
            r#"INSERT INTO lp_documents (partner_id, doc_type, file_name, storage_key)
               VALUES ($1,$2,$3,$4)
               RETURNING
                 document_id, partner_id,
                 doc_type   AS "doc_type: LpDocType",
                 file_name, storage_key,
                 doc_status AS "doc_status: LpDocStatus",
                 reviewed_by, review_note, uploaded_at, reviewed_at"#,
            partner_id,
            req.doc_type as LpDocType,
            req.file_name,
            req.storage_key,
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn list_documents(&self, partner_id: Uuid) -> sqlx::Result<Vec<LpDocument>> {
        sqlx::query_as!(
            LpDocument,
            r#"SELECT document_id, partner_id,
                      doc_type   AS "doc_type: LpDocType",
                      file_name, storage_key,
                      doc_status AS "doc_status: LpDocStatus",
                      reviewed_by, review_note, uploaded_at, reviewed_at
               FROM lp_documents WHERE partner_id=$1 ORDER BY uploaded_at DESC"#,
            partner_id
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn review_document(
        &self,
        document_id: Uuid,
        reviewer_id: Uuid,
        req: &ReviewDocumentRequest,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "UPDATE lp_documents
             SET doc_status=$1, reviewed_by=$2, review_note=$3, reviewed_at=NOW()
             WHERE document_id=$4",
            req.doc_status as LpDocStatus,
            reviewer_id,
            req.review_note,
            document_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Agreements ────────────────────────────────────────────────────────────

    pub async fn create_agreement(
        &self,
        partner_id: Uuid,
        req: &CreateAgreementRequest,
    ) -> sqlx::Result<LpAgreement> {
        sqlx::query_as!(
            LpAgreement,
            r#"INSERT INTO lp_agreements (partner_id, version, effective_from, expires_on)
               VALUES ($1,$2,$3,$4)
               RETURNING
                 agreement_id, partner_id, version,
                 agreement_status AS "agreement_status: AgreementStatus",
                 docusign_envelope_id, signed_at, document_hash,
                 effective_from, expires_on,
                 expiry_alert_30d_sent, expiry_alert_7d_sent,
                 created_at, updated_at"#,
            partner_id,
            req.version,
            req.effective_from,
            req.expires_on,
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_active_agreement(
        &self,
        partner_id: Uuid,
    ) -> sqlx::Result<Option<LpAgreement>> {
        sqlx::query_as!(
            LpAgreement,
            r#"SELECT agreement_id, partner_id, version,
                      agreement_status AS "agreement_status: AgreementStatus",
                      docusign_envelope_id, signed_at, document_hash,
                      effective_from, expires_on,
                      expiry_alert_30d_sent, expiry_alert_7d_sent,
                      created_at, updated_at
               FROM lp_agreements
               WHERE partner_id=$1 AND agreement_status='signed'
               ORDER BY signed_at DESC LIMIT 1"#,
            partner_id
        )
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn mark_agreement_sent(&self, agreement_id: Uuid, envelope_id: &str) -> sqlx::Result<()> {
        sqlx::query!(
            "UPDATE lp_agreements
             SET agreement_status='sent_for_signature', docusign_envelope_id=$1, updated_at=NOW()
             WHERE agreement_id=$2",
            envelope_id,
            agreement_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_agreement_signed(
        &self,
        envelope_id: &str,
        document_hash: &str,
    ) -> sqlx::Result<Option<LpAgreement>> {
        sqlx::query_as!(
            LpAgreement,
            r#"UPDATE lp_agreements
               SET agreement_status='signed', signed_at=NOW(), document_hash=$1, updated_at=NOW()
               WHERE docusign_envelope_id=$2
               RETURNING
                 agreement_id, partner_id, version,
                 agreement_status AS "agreement_status: AgreementStatus",
                 docusign_envelope_id, signed_at, document_hash,
                 effective_from, expires_on,
                 expiry_alert_30d_sent, expiry_alert_7d_sent,
                 created_at, updated_at"#,
            document_hash,
            envelope_id,
        )
        .fetch_optional(&self.pool)
        .await
    }

    /// Returns agreements expiring within `days` that haven't had their alert sent yet.
    pub async fn agreements_expiring_within(
        &self,
        days: i32,
        alert_field: &str,
    ) -> sqlx::Result<Vec<LpAgreement>> {
        // alert_field is either "expiry_alert_30d_sent" or "expiry_alert_7d_sent"
        // We use a raw query to allow dynamic column selection safely.
        let sql = format!(
            r#"SELECT agreement_id, partner_id, version,
                      agreement_status,
                      docusign_envelope_id, signed_at, document_hash,
                      effective_from, expires_on,
                      expiry_alert_30d_sent, expiry_alert_7d_sent,
                      created_at, updated_at
               FROM lp_agreements
               WHERE agreement_status = 'signed'
                 AND expires_on <= (CURRENT_DATE + INTERVAL '{days} days')
                 AND {alert_field} = FALSE"#,
            days = days,
            alert_field = alert_field
        );
        sqlx::query_as(&sql).fetch_all(&self.pool).await
    }

    pub async fn mark_expiry_alert_sent(
        &self,
        agreement_id: Uuid,
        alert_field: &str,
    ) -> sqlx::Result<()> {
        let sql = format!(
            "UPDATE lp_agreements SET {alert_field}=TRUE, updated_at=NOW() WHERE agreement_id=$1",
            alert_field = alert_field
        );
        sqlx::query(&sql)
            .bind(agreement_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Stellar keys ──────────────────────────────────────────────────────────

    pub async fn add_stellar_key(
        &self,
        partner_id: Uuid,
        added_by: Uuid,
        req: &AddStellarKeyRequest,
    ) -> sqlx::Result<LpStellarKey> {
        sqlx::query_as!(
            LpStellarKey,
            r#"INSERT INTO lp_stellar_keys (partner_id, stellar_address, label, added_by)
               VALUES ($1,$2,$3,$4)
               RETURNING key_id, partner_id, stellar_address, label,
                         is_active, added_by, revoked_by, revoked_at, created_at"#,
            partner_id,
            req.stellar_address,
            req.label,
            added_by,
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn list_stellar_keys(&self, partner_id: Uuid) -> sqlx::Result<Vec<LpStellarKey>> {
        sqlx::query_as!(
            LpStellarKey,
            r#"SELECT key_id, partner_id, stellar_address, label,
                      is_active, added_by, revoked_by, revoked_at, created_at
               FROM lp_stellar_keys WHERE partner_id=$1 ORDER BY created_at DESC"#,
            partner_id
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn revoke_stellar_key(&self, key_id: Uuid, revoked_by: Uuid) -> sqlx::Result<()> {
        sqlx::query!(
            "UPDATE lp_stellar_keys SET is_active=FALSE, revoked_by=$1, revoked_at=NOW()
             WHERE key_id=$2",
            revoked_by,
            key_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Check if a Stellar address is on the active allowlist for an active/trial partner.
    pub async fn is_stellar_address_allowed(&self, stellar_address: &str) -> sqlx::Result<bool> {
        let row = sqlx::query!(
            r#"SELECT COUNT(*) as "count!"
               FROM lp_stellar_keys k
               JOIN lp_partners p ON p.partner_id = k.partner_id
               WHERE k.stellar_address = $1
                 AND k.is_active = TRUE
                 AND p.status IN ('trial','active')"#,
            stellar_address
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.count > 0)
    }

    // ── Dashboard ─────────────────────────────────────────────────────────────

    pub async fn get_dashboard(&self, partner_id: Uuid) -> sqlx::Result<Option<PartnerDashboard>> {
        let partner = match self.get_partner(partner_id).await? {
            Some(p) => p,
            None => return Ok(None),
        };
        let documents = self.list_documents(partner_id).await?;
        let active_agreement = self.get_active_agreement(partner_id).await?;
        let stellar_keys = self.list_stellar_keys(partner_id).await?;
        Ok(Some(PartnerDashboard {
            partner,
            documents,
            active_agreement,
            stellar_keys,
        }))
    }
}
