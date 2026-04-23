//! Error types for the Multi-Sig Governance module.

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum MultiSigError {
    // ── Proposal lifecycle ────────────────────────────────────────────────────
    #[error("proposal {0} not found")]
    ProposalNotFound(Uuid),

    #[error("proposal {0} is in terminal state '{1}' and cannot be modified")]
    TerminalState(Uuid, String),

    #[error("proposal {0} has expired")]
    Expired(Uuid),

    #[error("proposal {0} is still time-locked until {1}")]
    TimeLocked(Uuid, chrono::DateTime<chrono::Utc>),

    #[error("proposal {0} has not reached the required signature threshold ({1} of {2})")]
    InsufficientSignatures(Uuid, usize, usize),

    // ── Signer / signature ────────────────────────────────────────────────────
    #[error("signer {0} has already signed proposal {1}")]
    DuplicateSignature(String, Uuid),

    #[error("signer {0} is not an active authorised signer")]
    UnauthorisedSigner(String),

    #[error("proposer cannot sign their own proposal")]
    SelfSigningForbidden,

    #[error("invalid signature XDR: {0}")]
    InvalidSignatureXdr(String),

    // ── Quorum configuration ──────────────────────────────────────────────────
    #[error("no quorum configuration found for operation type '{0}'")]
    MissingQuorumConfig(String),

    #[error("quorum configuration is invalid: {0}")]
    InvalidQuorumConfig(String),

    // ── XDR / Stellar ─────────────────────────────────────────────────────────
    #[error("XDR build error: {0}")]
    XdrBuild(String),

    #[error("Stellar submission error: {0}")]
    StellarSubmission(String),

    // ── Infrastructure ────────────────────────────────────────────────────────
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("serialisation error: {0}")]
    Serialisation(String),

    #[error("notification error: {0}")]
    Notification(String),
}

impl MultiSigError {
    /// HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::ProposalNotFound(_) => 404,
            Self::TerminalState(_, _) => 409,
            Self::Expired(_) => 410,
            Self::TimeLocked(_, _) => 425, // Too Early
            Self::InsufficientSignatures(_, _, _) => 422,
            Self::DuplicateSignature(_, _) => 409,
            Self::UnauthorisedSigner(_) => 403,
            Self::SelfSigningForbidden => 403,
            Self::InvalidSignatureXdr(_) => 400,
            Self::MissingQuorumConfig(_) => 500,
            Self::InvalidQuorumConfig(_) => 400,
            Self::XdrBuild(_) => 500,
            Self::StellarSubmission(_) => 502,
            Self::Database(_) => 500,
            Self::Serialisation(_) => 500,
            Self::Notification(_) => 500,
        }
    }
}

impl axum::response::IntoResponse for MultiSigError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::Json;
        use serde_json::json;

        let status = StatusCode::from_u16(self.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = json!({
            "error": self.to_string(),
            "code": format!("{:?}", self).split('(').next().unwrap_or("UnknownError"),
        });
        (status, Json(body)).into_response()
    }
}
