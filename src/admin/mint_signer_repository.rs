use crate::admin::mint_signer_models::*;
use crate::database::error::DatabaseError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub struct MintSignerRepository { pool: PgPool }

impl MintSignerRepository {
    pub fn new(pool: PgPool) -> Self { Self { pool } }

    pub async fn create(
        &self, req: &InitiateOnboardingRequest,
        token: &str, token_exp: DateTime<Utc>, initiated_by: Uuid,
    ) -> Result<MintSigner, DatabaseError> {
        sqlx::query_as!(MintSigner,
            r#"INSERT INTO mint_signers
               (full_legal_name, role, organisation, contact_email,
                onboarding_token, onboarding_token_exp, initiated_by)
               VALUES ($1,$2,$3,$4,$5,$6,$7)
               RETURNING id, full_legal_name,
                 role AS "role: SignerRole", organisation, contact_email,
                 stellar_public_key, key_fingerprint, key_registered_at,
                 key_expires_at, signing_weight,
                 status AS "status: SignerStatus", last_signing_at,
                 identity_verified, initiated_by, created_at, updated_at"#,
            req.full_legal_name, req.role as SignerRole,
            req.organisation, req.contact_email,
            token, token_exp, initiated_by
        ).fetch_one(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<MintSigner>, DatabaseError> {
        sqlx::query_as!(MintSigner,
            r#"SELECT id, full_legal_name,
                 role AS "role: SignerRole", organisation, contact_email,
                 stellar_public_key, key_fingerprint, key_registered_at,
                 key_expires_at, signing_weight,
                 status AS "status: SignerStatus", last_signing_at,
                 identity_verified, initiated_by, created_at, updated_at
               FROM mint_signers WHERE id=$1"#, id
        ).fetch_optional(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_by_token(&self, token: &str) -> Result<Option<MintSigner>, DatabaseError> {
        sqlx::query_as!(MintSigner,
            r#"SELECT id, full_legal_name,
                 role AS "role: SignerRole", organisation, contact_email,
                 stellar_public_key, key_fingerprint, key_registered_at,
                 key_expires_at, signing_weight,
                 status AS "status: SignerStatus", last_signing_at,
                 identity_verified, initiated_by, created_at, updated_at
               FROM mint_signers WHERE onboarding_token=$1"#, token
        ).fetch_optional(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }

    pub async fn find_by_public_key(&self, key: &str) -> Result<Option<MintSigner>, DatabaseError> {
        sqlx::query_as!(MintSigner,
            r#"SELECT id, full_legal_name,
                 role AS "role: SignerRole", organisation, contact_email,
                 stellar_public_key, key_fingerprint, key_registered_at,
                 key_expires_at, signing_weight,
                 status AS "status: SignerStatus", last_signing_at,
                 identity_verified, initiated_by, created_at, updated_at
               FROM mint_signers WHERE stellar_public_key=$1"#, key
        ).fetch_optional(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }

    pub async fn list_all(&self) -> Result<Vec<MintSigner>, DatabaseError> {
        sqlx::query_as!(MintSigner,
            r#"SELECT id, full_legal_name,
                 role AS "role: SignerRole", organisation, contact_email,
                 stellar_public_key, key_fingerprint, key_registered_at,
                 key_expires_at, signing_weight,
                 status AS "status: SignerStatus", last_signing_at,
                 identity_verified, initiated_by, created_at, updated_at
               FROM mint_signers WHERE status != 'removed' ORDER BY created_at"#
        ).fetch_all(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }

    pub async fn set_public_key(
        &self, id: Uuid, key: &str, fingerprint: &str, expires_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE mint_signers SET stellar_public_key=$1, key_fingerprint=$2,
             key_registered_at=NOW(), key_expires_at=$3, status='pending_identity',
             onboarding_token=NULL, onboarding_token_exp=NULL, updated_at=NOW()
             WHERE id=$4",
            key, fingerprint, expires_at, id
        ).execute(&self.pool).await.map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn activate(&self, id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE mint_signers SET status='active', identity_verified=TRUE, updated_at=NOW() WHERE id=$1", id
        ).execute(&self.pool).await.map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn set_status(&self, id: Uuid, status: SignerStatus) -> Result<(), DatabaseError> {
        sqlx::query!(
            r#"UPDATE mint_signers SET status=$1, updated_at=NOW() WHERE id=$2"#,
            status as SignerStatus, id
        ).execute(&self.pool).await.map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn update_public_key(&self, id: Uuid, key: &str, fp: &str) -> Result<(), DatabaseError> {
        sqlx::query!(
            "UPDATE mint_signers SET stellar_public_key=$1, key_fingerprint=$2, key_registered_at=NOW(), updated_at=NOW() WHERE id=$3",
            key, fp, id
        ).execute(&self.pool).await.map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn touch_last_signing(&self, id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!("UPDATE mint_signers SET last_signing_at=NOW(), updated_at=NOW() WHERE id=$1", id)
            .execute(&self.pool).await.map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn count_active(&self) -> Result<i64, DatabaseError> {
        let n = sqlx::query_scalar!("SELECT COUNT(*) FROM mint_signers WHERE status='active'")
            .fetch_one(&self.pool).await.map_err(DatabaseError::from_sqlx)?;
        Ok(n.unwrap_or(0))
    }

    pub async fn total_active_weight(&self) -> Result<i64, DatabaseError> {
        let n = sqlx::query_scalar!(
            "SELECT COALESCE(SUM(signing_weight::bigint),0) FROM mint_signers WHERE status='active'"
        ).fetch_one(&self.pool).await.map_err(DatabaseError::from_sqlx)?;
        Ok(n.unwrap_or(0))
    }

    // ── Challenges ────────────────────────────────────────────────────────────

    pub async fn create_challenge(
        &self, signer_id: Uuid, challenge: &str, hash: &str,
        expires_at: DateTime<Utc>, ip: Option<&str>,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            "INSERT INTO mint_signer_challenges (signer_id,challenge,challenge_hash,expires_at,ip_address) VALUES ($1,$2,$3,$4,$5::inet)",
            signer_id, challenge, hash, expires_at, ip
        ).execute(&self.pool).await.map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn find_challenge(&self, challenge: &str) -> Result<Option<MintSignerChallenge>, DatabaseError> {
        sqlx::query_as!(MintSignerChallenge,
            "SELECT id,signer_id,challenge,challenge_hash,expires_at,used_at,outcome,created_at FROM mint_signer_challenges WHERE challenge=$1",
            challenge
        ).fetch_optional(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }

    pub async fn mark_challenge_used(&self, id: Uuid, outcome: &str) -> Result<(), DatabaseError> {
        sqlx::query!("UPDATE mint_signer_challenges SET used_at=NOW(), outcome=$1 WHERE id=$2", outcome, id)
            .execute(&self.pool).await.map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    // ── Activity ──────────────────────────────────────────────────────────────

    pub async fn record_activity(
        &self, signer_id: Uuid, auth_request_id: Option<Uuid>, status: &str, ip: Option<&str>,
    ) -> Result<(), DatabaseError> {
        sqlx::query!(
            "INSERT INTO mint_signer_activity (signer_id,auth_request_id,sig_status,ip_address) VALUES ($1,$2,$3,$4::inet)",
            signer_id, auth_request_id, status, ip
        ).execute(&self.pool).await.map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn list_activity(&self, signer_id: Uuid, limit: i64, offset: i64) -> Result<Vec<MintSignerActivity>, DatabaseError> {
        sqlx::query_as!(MintSignerActivity,
            "SELECT id,signer_id,auth_request_id,signing_ts,sig_status,ip_address::text FROM mint_signer_activity WHERE signer_id=$1 ORDER BY signing_ts DESC LIMIT $2 OFFSET $3",
            signer_id, limit, offset
        ).fetch_all(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }

    // ── Key rotations ─────────────────────────────────────────────────────────

    pub async fn create_rotation(
        &self, signer_id: Uuid, old_key: &str, new_key: &str,
        grace_ends_at: DateTime<Utc>, initiated_by: Uuid,
    ) -> Result<MintSignerKeyRotation, DatabaseError> {
        sqlx::query_as!(MintSignerKeyRotation,
            "INSERT INTO mint_signer_key_rotations (signer_id,old_public_key,new_public_key,grace_ends_at,initiated_by) VALUES ($1,$2,$3,$4,$5) RETURNING *",
            signer_id, old_key, new_key, grace_ends_at, initiated_by
        ).fetch_one(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }

    pub async fn complete_rotation(&self, rotation_id: Uuid) -> Result<(), DatabaseError> {
        sqlx::query!("UPDATE mint_signer_key_rotations SET old_removed_at=NOW() WHERE id=$1", rotation_id)
            .execute(&self.pool).await.map_err(DatabaseError::from_sqlx)?;
        Ok(())
    }

    pub async fn pending_rotations_past_grace(&self) -> Result<Vec<MintSignerKeyRotation>, DatabaseError> {
        sqlx::query_as!(MintSignerKeyRotation,
            "SELECT * FROM mint_signer_key_rotations WHERE old_removed_at IS NULL AND grace_ends_at < NOW()"
        ).fetch_all(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }

    // ── Quorum ────────────────────────────────────────────────────────────────

    pub async fn get_quorum(&self) -> Result<Option<MintQuorumConfig>, DatabaseError> {
        sqlx::query_as!(MintQuorumConfig,
            "SELECT id,required_threshold,min_role_diversity,updated_by,updated_at FROM mint_quorum_config ORDER BY updated_at DESC LIMIT 1"
        ).fetch_optional(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }

    pub async fn upsert_quorum(
        &self, threshold: i16, diversity: serde_json::Value, updated_by: Uuid,
    ) -> Result<MintQuorumConfig, DatabaseError> {
        sqlx::query_as!(MintQuorumConfig,
            "INSERT INTO mint_quorum_config (required_threshold,min_role_diversity,updated_by) VALUES ($1,$2,$3) RETURNING id,required_threshold,min_role_diversity,updated_by,updated_at",
            threshold, diversity, updated_by
        ).fetch_one(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }

    pub async fn inactive_signers(&self, days: i64) -> Result<Vec<MintSigner>, DatabaseError> {
        sqlx::query_as!(MintSigner,
            r#"SELECT id, full_legal_name,
                 role AS "role: SignerRole", organisation, contact_email,
                 stellar_public_key, key_fingerprint, key_registered_at,
                 key_expires_at, signing_weight,
                 status AS "status: SignerStatus", last_signing_at,
                 identity_verified, initiated_by, created_at, updated_at
               FROM mint_signers
               WHERE status='active'
                 AND (last_signing_at IS NULL OR last_signing_at < NOW() - make_interval(days => $1::int))"#,
            days as i32
        ).fetch_all(&self.pool).await.map_err(DatabaseError::from_sqlx)
    }
}
