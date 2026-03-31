use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "signer_role", rename_all = "snake_case")]
pub enum SignerRole { Cfo, Cto, Cco, TreasuryManager, ExternalAuditor }

impl SignerRole {
    pub fn max_weight(self) -> i16 {
        match self { Self::Cfo | Self::Cco | Self::Cto => 2, _ => 1 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "signer_status", rename_all = "snake_case")]
pub enum SignerStatus {
    PendingOnboarding, PendingIdentity, Active, Suspended, PendingRemoval, Removed,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MintSigner {
    pub id: Uuid,
    pub full_legal_name: String,
    pub role: SignerRole,
    pub organisation: String,
    pub contact_email: String,
    pub stellar_public_key: Option<String>,
    pub key_fingerprint: Option<String>,
    pub key_registered_at: Option<DateTime<Utc>>,
    pub key_expires_at: Option<DateTime<Utc>>,
    pub signing_weight: i16,
    pub status: SignerStatus,
    pub last_signing_at: Option<DateTime<Utc>>,
    pub identity_verified: bool,
    pub initiated_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MintSignerChallenge {
    pub id: Uuid,
    pub signer_id: Uuid,
    pub challenge: String,
    pub challenge_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub outcome: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MintSignerActivity {
    pub id: Uuid,
    pub signer_id: Uuid,
    pub auth_request_id: Option<Uuid>,
    pub signing_ts: DateTime<Utc>,
    pub sig_status: String,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MintSignerKeyRotation {
    pub id: Uuid,
    pub signer_id: Uuid,
    pub old_public_key: String,
    pub new_public_key: String,
    pub grace_ends_at: DateTime<Utc>,
    pub old_removed_at: Option<DateTime<Utc>>,
    pub initiated_by: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MintQuorumConfig {
    pub id: Uuid,
    pub required_threshold: i16,
    pub min_role_diversity: serde_json::Value,
    pub updated_by: Uuid,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct InitiateOnboardingRequest {
    pub full_legal_name: String,
    pub role: SignerRole,
    pub organisation: String,
    pub contact_email: String,
}

#[derive(Debug, Deserialize)]
pub struct CompleteOnboardingRequest {
    pub token: String,
    pub stellar_public_key: String,
    pub challenge_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct RotateKeyRequest {
    pub new_stellar_public_key: String,
    pub challenge_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct SuspendSignerRequest { pub reason: String }

#[derive(Debug, Deserialize)]
pub struct UpdateQuorumRequest {
    pub required_threshold: i16,
    pub min_role_diversity: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct SignerSummary {
    pub id: Uuid,
    pub full_legal_name: String,
    pub role: SignerRole,
    pub organisation: String,
    pub status: SignerStatus,
    pub key_fingerprint: Option<String>,
    pub last_signing_at: Option<DateTime<Utc>>,
    pub key_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct QuorumStatus {
    pub required_threshold: i16,
    pub active_signer_count: i64,
    pub total_weight: i64,
    pub quorum_reachable: bool,
    pub min_role_diversity: serde_json::Value,
}
