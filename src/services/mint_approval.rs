//! Mint Approval Workflow Service
//!
//! Implements the programmable, multi-step, role-based approval pipeline that
//! governs how mint requests are approved before on-chain execution.
//!
//! # Tier Logic
//! - Tier 1 (< 1,000,000 NGN)  → 1 approval  (mint_operator)
//! - Tier 2 (1M – 10M NGN)     → 2 approvals (mint_operator + compliance_officer)
//! - Tier 3 (> 10,000,000 NGN) → 3 approvals (mint_operator + compliance_officer + finance_director)
//!
//! # State Machine
//! pending_approval → partially_approved → approved → executed
//!                 ↘ rejected (any stage)
//!                 ↘ expired  (system worker)

use crate::database::mint_request_repository::{
    MintApproval, MintAuditLog, MintRequest, MintRequestRepository,
};
use crate::error::{AppError, AppErrorKind, DomainError, ValidationError};
use bigdecimal::BigDecimal;
use chrono::Utc;
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

// ============================================================================
// Constants
// ============================================================================

/// Tier 1 upper bound (exclusive): < 1,000,000 NGN
const TIER_1_MAX_NGN: i64 = 1_000_000;
/// Tier 2 upper bound (exclusive): < 10,000,000 NGN
const TIER_2_MAX_NGN: i64 = 10_000_000;

// ============================================================================
// Role constants (must match DB CHECK constraint)
// ============================================================================
pub const ROLE_MINT_OPERATOR: &str = "mint_operator";
pub const ROLE_COMPLIANCE_OFFICER: &str = "compliance_officer";
pub const ROLE_FINANCE_DIRECTOR: &str = "finance_director";

// ============================================================================
// Tier definition
// ============================================================================

/// Describes the approval requirements for a given tier.
#[derive(Debug, Clone)]
pub struct TierDefinition {
    pub tier: u8,
    pub required_approvals: u8,
    /// Ordered list of roles that must approve (in any order, but all required)
    pub required_roles: Vec<&'static str>,
}

/// Calculate the approval tier and requirements from an NGN amount.
///
/// This is the single source of truth for tier logic — reuse everywhere.
pub fn calculate_tier(amount_ngn: &BigDecimal) -> TierDefinition {
    let amount_i64: i64 = amount_ngn
        .to_string()
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if amount_i64 < TIER_1_MAX_NGN {
        TierDefinition {
            tier: 1,
            required_approvals: 1,
            required_roles: vec![ROLE_MINT_OPERATOR],
        }
    } else if amount_i64 < TIER_2_MAX_NGN {
        TierDefinition {
            tier: 2,
            required_approvals: 2,
            required_roles: vec![ROLE_MINT_OPERATOR, ROLE_COMPLIANCE_OFFICER],
        }
    } else {
        TierDefinition {
            tier: 3,
            required_approvals: 3,
            required_roles: vec![
                ROLE_MINT_OPERATOR,
                ROLE_COMPLIANCE_OFFICER,
                ROLE_FINANCE_DIRECTOR,
            ],
        }
    }
}

// ============================================================================
// State machine helpers
// ============================================================================

/// Valid state transitions for mint requests.
///
/// Returns `true` if the transition from `from` → `to` is permitted.
pub fn is_valid_transition(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("pending_approval", "partially_approved")
            | ("pending_approval", "approved")
            | ("pending_approval", "rejected")
            | ("pending_approval", "expired")
            | ("partially_approved", "approved")
            | ("partially_approved", "rejected")
            | ("partially_approved", "expired")
            | ("approved", "executed")
    )
}

// ============================================================================
// Workflow errors
// ============================================================================

#[derive(Debug)]
pub enum WorkflowError {
    /// Request not found
    NotFound { id: Uuid },
    /// Transition is not allowed from current state
    InvalidTransition { from: String, to: String },
    /// Approver does not have the required role
    UnauthorizedRole { role: String, required: String },
    /// Creator cannot approve their own request
    SelfApprovalForbidden,
    /// Approver already acted on this request
    AlreadyActed { approver_id: String },
    /// Request is in a terminal state
    TerminalState { status: String },
    /// Rejection requires a reason code
    MissingReasonCode,
    /// Execution guard: not all approvals present
    ExecutionNotAllowed { reason: String },
    /// Database error
    Database(String),
}

impl From<WorkflowError> for AppError {
    fn from(e: WorkflowError) -> Self {
        match e {
            WorkflowError::NotFound { id } => AppError::new(AppErrorKind::Domain(
                DomainError::TransactionNotFound {
                    transaction_id: id.to_string(),
                },
            )),
            // InvalidTransition → 409 Conflict
            WorkflowError::InvalidTransition { from, to } => {
                AppError::new(AppErrorKind::Domain(DomainError::DuplicateTransaction {
                    transaction_id: format!("transition:{}→{}", from, to),
                }))
            }
            // UnauthorizedRole → 403 Forbidden (reuse InvalidWalletAddress which maps to 400;
            // handlers.rs maps this directly so this path is only hit if AppError is used elsewhere)
            WorkflowError::UnauthorizedRole { role, required } => {
                AppError::new(AppErrorKind::Validation(ValidationError::InvalidAmount {
                    amount: role,
                    reason: format!("Required role: {}", required),
                }))
            }
            // SelfApprovalForbidden → 403
            WorkflowError::SelfApprovalForbidden => {
                AppError::new(AppErrorKind::Validation(ValidationError::InvalidAmount {
                    amount: "self".to_string(),
                    reason: "Request creator cannot approve their own request".to_string(),
                }))
            }
            // AlreadyActed → 409 Conflict
            WorkflowError::AlreadyActed { approver_id } => {
                AppError::new(AppErrorKind::Domain(DomainError::DuplicateTransaction {
                    transaction_id: approver_id,
                }))
            }
            // TerminalState → 409 Conflict
            WorkflowError::TerminalState { status } => {
                AppError::new(AppErrorKind::Domain(DomainError::DuplicateTransaction {
                    transaction_id: format!("terminal:{}", status),
                }))
            }
            // MissingReasonCode → 400 Bad Request
            WorkflowError::MissingReasonCode => {
                AppError::new(AppErrorKind::Validation(ValidationError::MissingField {
                    field: "reason_code".to_string(),
                }))
            }
            // ExecutionNotAllowed → 422 Unprocessable Entity
            WorkflowError::ExecutionNotAllowed { reason } => {
                AppError::new(AppErrorKind::Domain(DomainError::InvalidAmount {
                    amount: "execution".to_string(),
                    reason,
                }))
            }
            WorkflowError::Database(msg) => {
                AppError::new(AppErrorKind::Infrastructure(
                    crate::error::InfrastructureError::Database {
                        message: msg,
                        is_retryable: false,
                    },
                ))
            }
        }
    }
}

// ============================================================================
// Service
// ============================================================================

pub struct MintApprovalService {
    repo: Arc<MintRequestRepository>,
}

impl MintApprovalService {
    pub fn new(repo: Arc<MintRequestRepository>) -> Self {
        Self { repo }
    }

    // -------------------------------------------------------------------------
    // Submit a new mint request
    // -------------------------------------------------------------------------

    /// Submit a new mint request.
    ///
    /// Calculates the approval tier from the live NGN amount and persists the
    /// request in `pending_approval` state.
    pub async fn submit(
        &self,
        submitted_by: &str,
        destination_wallet: &str,
        amount_ngn: BigDecimal,
        amount_cngn: BigDecimal,
        rate_snapshot: BigDecimal,
        reference: Option<String>,
        metadata: serde_json::Value,
    ) -> Result<MintRequest, WorkflowError> {
        let tier = calculate_tier(&amount_ngn);

        let request = self
            .repo
            .create(
                submitted_by,
                destination_wallet,
                amount_ngn.clone(),
                amount_cngn.clone(),
                rate_snapshot,
                tier.tier,
                tier.required_approvals,
                reference,
                metadata.clone(),
            )
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        // Audit: request submitted
        self.repo
            .append_audit(
                request.id,
                submitted_by,
                None,
                "mint_request_submitted",
                None,
                Some("pending_approval"),
                json!({
                    "amount_ngn": amount_ngn.to_string(),
                    "amount_cngn": amount_cngn.to_string(),
                    "tier": tier.tier,
                    "required_approvals": tier.required_approvals,
                    "required_roles": tier.required_roles,
                }),
            )
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        info!(
            mint_request_id = %request.id,
            submitted_by = %submitted_by,
            tier = tier.tier,
            required_approvals = tier.required_approvals,
            "Mint request submitted"
        );

        Ok(request)
    }

    // -------------------------------------------------------------------------
    // Approve a mint request
    // -------------------------------------------------------------------------

    /// Record an approval from an authorised approver.
    ///
    /// Enforces:
    /// - Role-based access (approver must hold a required role for this tier)
    /// - Self-approval prevention
    /// - Duplicate approval prevention
    /// - State machine validity
    /// - Automatic promotion to `partially_approved` or `approved`
    pub async fn approve(
        &self,
        mint_request_id: Uuid,
        approver_id: &str,
        approver_role: &str,
        comment: Option<String>,
    ) -> Result<MintRequest, WorkflowError> {
        let request = self.load_active_request(mint_request_id).await?;

        // Self-approval prevention
        if request.submitted_by == approver_id {
            return Err(WorkflowError::SelfApprovalForbidden);
        }

        // Role check: approver_role must be in the tier's required_roles
        let tier = calculate_tier(&request.amount_ngn);
        if !tier.required_roles.contains(&approver_role) {
            return Err(WorkflowError::UnauthorizedRole {
                role: approver_role.to_string(),
                required: tier.required_roles.join(" | "),
            });
        }

        // Duplicate check
        let existing = self
            .repo
            .find_approval_by_approver(mint_request_id, approver_id)
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;
        if existing.is_some() {
            return Err(WorkflowError::AlreadyActed {
                approver_id: approver_id.to_string(),
            });
        }

        // Persist the approval signature
        self.repo
            .add_approval(
                mint_request_id,
                approver_id,
                approver_role,
                "approve",
                None,
                comment.as_deref(),
            )
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        // Count approvals so far (only "approve" actions)
        let approvals = self
            .repo
            .list_approvals(mint_request_id)
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;
        let approve_count = approvals.iter().filter(|a| a.action == "approve").count();

        // Determine next state
        let next_status = if approve_count >= tier.required_approvals as usize {
            "approved"
        } else {
            "partially_approved"
        };

        // Validate transition
        if !is_valid_transition(&request.status, next_status) {
            return Err(WorkflowError::InvalidTransition {
                from: request.status.clone(),
                to: next_status.to_string(),
            });
        }

        // Update state
        let updated = self
            .repo
            .update_status(mint_request_id, next_status, None)
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        // Audit
        self.repo
            .append_audit(
                mint_request_id,
                approver_id,
                Some(approver_role),
                "approval_recorded",
                Some(&request.status),
                Some(next_status),
                json!({
                    "approvals_received": approve_count,
                    "approvals_required": tier.required_approvals,
                    "comment": comment,
                }),
            )
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        info!(
            mint_request_id = %mint_request_id,
            approver_id = %approver_id,
            approver_role = %approver_role,
            approvals_received = approve_count,
            approvals_required = tier.required_approvals,
            new_status = %next_status,
            "Approval recorded"
        );

        Ok(updated)
    }

    // -------------------------------------------------------------------------
    // Reject a mint request
    // -------------------------------------------------------------------------

    /// Reject a mint request at any approval stage.
    ///
    /// Immediately transitions to `rejected`. Requires a `reason_code`.
    pub async fn reject(
        &self,
        mint_request_id: Uuid,
        approver_id: &str,
        approver_role: &str,
        reason_code: &str,
        comment: Option<String>,
    ) -> Result<MintRequest, WorkflowError> {
        if reason_code.trim().is_empty() {
            return Err(WorkflowError::MissingReasonCode);
        }

        let request = self.load_active_request(mint_request_id).await?;

        // Role check
        let tier = calculate_tier(&request.amount_ngn);
        if !tier.required_roles.contains(&approver_role) {
            return Err(WorkflowError::UnauthorizedRole {
                role: approver_role.to_string(),
                required: tier.required_roles.join(" | "),
            });
        }

        // Validate transition
        if !is_valid_transition(&request.status, "rejected") {
            return Err(WorkflowError::InvalidTransition {
                from: request.status.clone(),
                to: "rejected".to_string(),
            });
        }

        // Persist rejection signature
        self.repo
            .add_approval(
                mint_request_id,
                approver_id,
                approver_role,
                "reject",
                Some(reason_code),
                comment.as_deref(),
            )
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        // Update state to rejected
        let updated = self
            .repo
            .update_status(mint_request_id, "rejected", None)
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        // Audit
        self.repo
            .append_audit(
                mint_request_id,
                approver_id,
                Some(approver_role),
                "mint_request_rejected",
                Some(&request.status),
                Some("rejected"),
                json!({
                    "reason_code": reason_code,
                    "comment": comment,
                }),
            )
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        warn!(
            mint_request_id = %mint_request_id,
            approver_id = %approver_id,
            reason_code = %reason_code,
            "Mint request rejected"
        );

        Ok(updated)
    }

    // -------------------------------------------------------------------------
    // Execution guard
    // -------------------------------------------------------------------------

    /// Verify that a mint request is safe to execute on-chain.
    ///
    /// Returns `Ok(())` only when:
    /// - status == "approved"
    /// - All required role approvals are present
    /// - Request has not expired
    /// - Internal SLA has not been breached (blocks Stellar submission)
    pub async fn assert_executable(
        &self,
        mint_request_id: Uuid,
    ) -> Result<MintRequest, WorkflowError> {
        let request = self
            .repo
            .find_by_id(mint_request_id)
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?
            .ok_or(WorkflowError::NotFound {
                id: mint_request_id,
            })?;

        if request.status != "approved" {
            return Err(WorkflowError::ExecutionNotAllowed {
                reason: format!(
                    "Request status is '{}', must be 'approved'",
                    request.status
                ),
            });
        }

        if Utc::now() > request.expires_at {
            return Err(WorkflowError::ExecutionNotAllowed {
                reason: "Request has expired".to_string(),
            });
        }

        // ── SLA breach guard: block Stellar submission if SLA is expired ──────
        // This is the critical gate that prevents any transaction hitting the
        // Stellar ledger after the internal SLA deadline has been breached.
        let sla_stage: Option<String> = sqlx::query_scalar!(
            "SELECT stage::text FROM mint_sla_state WHERE mint_request_id = $1",
            mint_request_id,
        )
        .fetch_optional(self.repo.pool())
        .await
        .map_err(|e| WorkflowError::Database(e.to_string()))?
        .flatten();

        if sla_stage.as_deref() == Some("expired") {
            return Err(WorkflowError::ExecutionNotAllowed {
                reason: "SLA expired: this request cannot be submitted to Stellar. \
                         A fresh re-submission is required (#123)."
                    .to_string(),
            });
        }

        // Verify all required roles have approved
        let tier = calculate_tier(&request.amount_ngn);
        let approvals = self
            .repo
            .list_approvals(mint_request_id)
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        let approved_roles: Vec<&str> = approvals
            .iter()
            .filter(|a| a.action == "approve")
            .map(|a| a.approver_role.as_str())
            .collect();

        for required_role in &tier.required_roles {
            if !approved_roles.contains(required_role) {
                return Err(WorkflowError::ExecutionNotAllowed {
                    reason: format!("Missing approval from role: {}", required_role),
                });
            }
        }

        Ok(request)
    }

    /// Mark a mint request as executed after successful Stellar transaction.
    pub async fn mark_executed(
        &self,
        mint_request_id: Uuid,
        stellar_tx_hash: &str,
        actor_id: &str,
    ) -> Result<MintRequest, WorkflowError> {
        let request = self.assert_executable(mint_request_id).await?;

        if !is_valid_transition(&request.status, "executed") {
            return Err(WorkflowError::InvalidTransition {
                from: request.status.clone(),
                to: "executed".to_string(),
            });
        }

        let updated = self
            .repo
            .update_status(mint_request_id, "executed", Some(stellar_tx_hash))
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        self.repo
            .append_audit(
                mint_request_id,
                actor_id,
                None,
                "mint_executed_on_chain",
                Some("approved"),
                Some("executed"),
                json!({ "stellar_tx_hash": stellar_tx_hash }),
            )
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        info!(
            mint_request_id = %mint_request_id,
            stellar_tx_hash = %stellar_tx_hash,
            "Mint request executed on-chain"
        );

        Ok(updated)
    }

    // -------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------

    pub async fn get_request(
        &self,
        id: Uuid,
    ) -> Result<(MintRequest, Vec<MintApproval>), WorkflowError> {
        let request = self
            .repo
            .find_by_id(id)
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?
            .ok_or(WorkflowError::NotFound { id })?;

        let approvals = self
            .repo
            .list_approvals(id)
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        Ok((request, approvals))
    }

    pub async fn list_requests(
        &self,
        status_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<(MintRequest, Vec<MintApproval>)>, i64), WorkflowError> {
        let (requests, total) = self
            .repo
            .list(status_filter, limit, offset)
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?;

        let mut result = Vec::with_capacity(requests.len());
        for req in requests {
            let approvals = self
                .repo
                .list_approvals(req.id)
                .await
                .map_err(|e| WorkflowError::Database(e.to_string()))?;
            result.push((req, approvals));
        }

        Ok((result, total))
    }

    pub async fn get_audit_log(
        &self,
        mint_request_id: Uuid,
    ) -> Result<Vec<MintAuditLog>, WorkflowError> {
        self.repo
            .list_audit(mint_request_id)
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// Load a request and verify it is not in a terminal state.
    async fn load_active_request(&self, id: Uuid) -> Result<MintRequest, WorkflowError> {
        let request = self
            .repo
            .find_by_id(id)
            .await
            .map_err(|e| WorkflowError::Database(e.to_string()))?
            .ok_or(WorkflowError::NotFound { id })?;

        let terminal = ["approved", "rejected", "expired", "executed"];
        if terminal.contains(&request.status.as_str()) {
            return Err(WorkflowError::TerminalState {
                status: request.status.clone(),
            });
        }

        // Auto-expire check
        if Utc::now() > request.expires_at {
            // Transition to expired in DB
            let _ = self.repo.update_status(id, "expired", None).await;
            let _ = self
                .repo
                .append_audit(
                    id,
                    "system",
                    None,
                    "mint_request_expired",
                    Some(&request.status),
                    Some("expired"),
                    json!({}),
                )
                .await;
            return Err(WorkflowError::TerminalState {
                status: "expired".to_string(),
            });
        }

        Ok(request)
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_1_below_1m() {
        let t = calculate_tier(&BigDecimal::from(500_000));
        assert_eq!(t.tier, 1);
        assert_eq!(t.required_approvals, 1);
        assert_eq!(t.required_roles, vec![ROLE_MINT_OPERATOR]);
    }

    #[test]
    fn test_tier_2_between_1m_and_10m() {
        let t = calculate_tier(&BigDecimal::from(5_000_000));
        assert_eq!(t.tier, 2);
        assert_eq!(t.required_approvals, 2);
        assert!(t.required_roles.contains(&ROLE_COMPLIANCE_OFFICER));
    }

    #[test]
    fn test_tier_3_above_10m() {
        let t = calculate_tier(&BigDecimal::from(15_000_000));
        assert_eq!(t.tier, 3);
        assert_eq!(t.required_approvals, 3);
        assert!(t.required_roles.contains(&ROLE_FINANCE_DIRECTOR));
    }

    #[test]
    fn test_valid_transitions() {
        assert!(is_valid_transition("pending_approval", "partially_approved"));
        assert!(is_valid_transition("pending_approval", "approved"));
        assert!(is_valid_transition("pending_approval", "rejected"));
        assert!(is_valid_transition("partially_approved", "approved"));
        assert!(is_valid_transition("partially_approved", "rejected"));
        assert!(is_valid_transition("approved", "executed"));
    }

    #[test]
    fn test_invalid_transitions() {
        assert!(!is_valid_transition("approved", "pending_approval"));
        assert!(!is_valid_transition("rejected", "approved"));
        assert!(!is_valid_transition("executed", "approved"));
        assert!(!is_valid_transition("expired", "approved"));
    }
}
