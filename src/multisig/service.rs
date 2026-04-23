//! Multi-Sig Governance Service — orchestration layer.
//!
//! This is the single entry point for all governance operations. It enforces:
//! - M-of-N signature threshold before any Stellar transaction is submitted
//! - Time-lock for governance changes (add/remove signer, change threshold)
//! - Tamper-evident governance log for every event
//! - Notification dispatch to all authorised signers

use crate::chains::stellar::client::StellarClient;
use crate::multisig::{
    error::MultiSigError,
    governance_log::compute_entry_hash,
    models::{
        GovernanceLogEntry, MultiSigOpType, MultiSigProposal, MultiSigProposalStatus,
        MultiSigSignature, ProposalDetail, ProposalListResponse, ListProposalsQuery,
    },
    notification::{MultiSigNotificationConfig, MultiSigNotifier, NotificationEvent},
    repository::MultiSigRepository,
    xdr_builder::{build_burn_xdr, build_mint_xdr, build_set_options_xdr, SetOptionsParams},
};
use chrono::{Duration, Utc};
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

pub struct MultiSigService {
    repo: Arc<MultiSigRepository>,
    stellar: Arc<StellarClient>,
    notifier: Arc<MultiSigNotifier>,
    /// Issuing account address (cNGN issuer on Stellar).
    issuer_address: String,
    /// Default proposal TTL in hours.
    proposal_ttl_hours: i64,
}

impl MultiSigService {
    pub fn new(
        repo: Arc<MultiSigRepository>,
        stellar: Arc<StellarClient>,
        notifier_config: MultiSigNotificationConfig,
        issuer_address: String,
        proposal_ttl_hours: Option<i64>,
    ) -> Self {
        Self {
            repo,
            stellar,
            notifier: Arc::new(MultiSigNotifier::new(notifier_config)),
            issuer_address,
            proposal_ttl_hours: proposal_ttl_hours.unwrap_or(72),
        }
    }

    pub fn from_env(
        repo: Arc<MultiSigRepository>,
        stellar: Arc<StellarClient>,
    ) -> Self {
        let issuer_address = std::env::var("STELLAR_ISSUER_ADDRESS")
            .unwrap_or_else(|_| String::new());
        let proposal_ttl_hours = std::env::var("MULTISIG_PROPOSAL_TTL_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(72);

        Self::new(
            repo,
            stellar,
            MultiSigNotificationConfig::from_env(),
            issuer_address,
            Some(proposal_ttl_hours),
        )
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Propose
    // ─────────────────────────────────────────────────────────────────────────

    /// Create a new treasury operation proposal.
    ///
    /// The proposer must be an active authorised signer. The unsigned XDR is
    /// either provided by the caller or built from `op_params`.
    ///
    /// Returns the created proposal with the unsigned XDR for review.
    pub async fn propose(
        &self,
        proposer_key: &str,
        op_type: MultiSigOpType,
        description: &str,
        unsigned_xdr: Option<String>,
        op_params: Option<serde_json::Value>,
    ) -> Result<MultiSigProposal, MultiSigError> {
        // Verify proposer is an active signer
        let (proposer_id, _role) = self
            .repo
            .find_active_signer_by_key(proposer_key)
            .await?
            .ok_or_else(|| MultiSigError::UnauthorisedSigner(proposer_key.to_string()))?;

        // Load quorum configuration for this operation type
        let quorum = self.repo.get_quorum_config(op_type).await?;

        // Build or validate the unsigned XDR
        let xdr = match unsigned_xdr {
            Some(xdr) => xdr,
            None => self.build_xdr(op_type, op_params).await?,
        };

        // Calculate time-lock deadline for governance changes
        let time_lock_until = if op_type.requires_time_lock() && quorum.time_lock_seconds > 0 {
            Some(Utc::now() + Duration::seconds(quorum.time_lock_seconds as i64))
        } else {
            None
        };

        let expires_at = Utc::now() + Duration::hours(self.proposal_ttl_hours);

        let proposal = self
            .repo
            .create_proposal(
                op_type,
                description,
                &xdr,
                quorum.required_signatures,
                quorum.total_signers,
                time_lock_until,
                proposer_id,
                proposer_key,
                expires_at,
            )
            .await?;

        // Append governance log
        self.append_log(
            Some(proposal.id),
            "proposal_created",
            Some(proposer_key),
            Some(proposer_id),
            &json!({
                "op_type": op_type.as_str(),
                "description": description,
                "required_signatures": quorum.required_signatures,
                "total_signers": quorum.total_signers,
                "time_lock_until": time_lock_until,
                "expires_at": expires_at,
            }),
        )
        .await?;

        // Notify all signers
        self.notifier
            .notify(&proposal, NotificationEvent::ProposalCreated)
            .await;

        info!(
            proposal_id = %proposal.id,
            op_type = %op_type,
            proposer = %proposer_key,
            required = quorum.required_signatures,
            total = quorum.total_signers,
            "Multi-sig proposal created"
        );

        Ok(proposal)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sign
    // ─────────────────────────────────────────────────────────────────────────

    /// Record a signer's cryptographic signature on a proposal.
    ///
    /// The signer must:
    /// 1. Be an active authorised signer
    /// 2. Not be the proposer (self-signing prevention)
    /// 3. Not have already signed this proposal
    ///
    /// When the M-of-N threshold is met:
    /// - Governance changes → status transitions to `time_locked`
    /// - Mint/Burn/SetOptions → status transitions to `ready`
    pub async fn sign(
        &self,
        proposal_id: Uuid,
        signer_key: &str,
        signature_xdr: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<ProposalDetail, MultiSigError> {
        let proposal = self.repo.get_proposal(proposal_id).await?;

        // Guard: terminal state
        if proposal.status.is_terminal() {
            return Err(MultiSigError::TerminalState(
                proposal_id,
                format!("{:?}", proposal.status),
            ));
        }

        // Guard: expired
        if Utc::now() > proposal.expires_at {
            self.repo
                .update_proposal_status(
                    proposal_id,
                    MultiSigProposalStatus::Expired,
                    None,
                    None,
                    None,
                )
                .await?;
            return Err(MultiSigError::Expired(proposal_id));
        }

        // Verify signer is active
        let (signer_id, signer_role) = self
            .repo
            .find_active_signer_by_key(signer_key)
            .await?
            .ok_or_else(|| MultiSigError::UnauthorisedSigner(signer_key.to_string()))?;

        // Self-signing prevention
        if signer_id == proposal.proposed_by {
            return Err(MultiSigError::SelfSigningForbidden);
        }

        // Duplicate signature check
        if self.repo.signature_exists(proposal_id, signer_id).await? {
            return Err(MultiSigError::DuplicateSignature(
                signer_key.to_string(),
                proposal_id,
            ));
        }

        // Persist the signature
        self.repo
            .add_signature(
                proposal_id,
                signer_id,
                signer_key,
                &signer_role,
                signature_xdr,
                ip_address,
                user_agent,
            )
            .await?;

        // Count total signatures
        let signatures = self.repo.list_signatures(proposal_id).await?;
        let sig_count = signatures.len();
        let required = proposal.required_signatures as usize;

        // Append governance log
        self.append_log(
            Some(proposal_id),
            "signature_added",
            Some(signer_key),
            Some(signer_id),
            &json!({
                "signer_role": signer_role,
                "signatures_collected": sig_count,
                "signatures_required": required,
            }),
        )
        .await?;

        // Notify
        self.notifier
            .notify(
                &proposal,
                NotificationEvent::SignatureAdded {
                    current: sig_count,
                    required,
                },
            )
            .await;

        // Check if threshold is met
        let updated_proposal = if sig_count >= required {
            let new_status = if proposal.op_type.requires_time_lock()
                && proposal.time_lock_until.is_some()
            {
                MultiSigProposalStatus::TimeLocked
            } else {
                MultiSigProposalStatus::Ready
            };

            let updated = self
                .repo
                .update_proposal_status(proposal_id, new_status, None, None, None)
                .await?;

            self.append_log(
                Some(proposal_id),
                "threshold_met",
                None,
                None,
                &json!({
                    "new_status": format!("{:?}", new_status),
                    "time_lock_until": proposal.time_lock_until,
                }),
            )
            .await?;

            let event = if new_status == MultiSigProposalStatus::Ready {
                NotificationEvent::ThresholdMet
            } else {
                NotificationEvent::SignatureAdded {
                    current: sig_count,
                    required,
                }
            };
            self.notifier.notify(&updated, event).await;

            info!(
                proposal_id = %proposal_id,
                status = ?new_status,
                "Multi-sig threshold met"
            );

            updated
        } else {
            proposal
        };

        let time_lock_remaining = updated_proposal.time_lock_until.map(|tl| {
            let remaining = tl - Utc::now();
            remaining.num_seconds().max(0)
        });

        Ok(ProposalDetail {
            signatures_collected: sig_count,
            signatures_required: required,
            time_lock_remaining_secs: time_lock_remaining,
            proposal: updated_proposal,
            signatures,
        })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Submit
    // ─────────────────────────────────────────────────────────────────────────

    /// Submit the fully-signed XDR to Stellar Horizon.
    ///
    /// Pre-conditions:
    /// - Proposal status must be `ready`
    /// - The signed XDR must be present (all signatures collected)
    /// - Time-lock must have elapsed (for governance changes)
    pub async fn submit(
        &self,
        proposal_id: Uuid,
        actor_key: &str,
        signed_xdr: &str,
    ) -> Result<MultiSigProposal, MultiSigError> {
        let proposal = self.repo.get_proposal(proposal_id).await?;

        // Guard: must be in Ready state
        if proposal.status != MultiSigProposalStatus::Ready {
            if proposal.status == MultiSigProposalStatus::TimeLocked {
                let tl = proposal.time_lock_until.unwrap_or(Utc::now());
                if Utc::now() < tl {
                    return Err(MultiSigError::TimeLocked(proposal_id, tl));
                }
                // Time-lock has elapsed — promote to Ready
                self.repo
                    .update_proposal_status(
                        proposal_id,
                        MultiSigProposalStatus::Ready,
                        None,
                        None,
                        None,
                    )
                    .await?;
                self.append_log(
                    Some(proposal_id),
                    "time_lock_elapsed",
                    Some(actor_key),
                    None,
                    &json!({}),
                )
                .await?;
                self.notifier
                    .notify(&proposal, NotificationEvent::TimeLockElapsed)
                    .await;
            } else {
                return Err(MultiSigError::TerminalState(
                    proposal_id,
                    format!("{:?}", proposal.status),
                ));
            }
        }

        // Verify signature count (defence-in-depth — Stellar will also reject)
        let signatures = self.repo.list_signatures(proposal_id).await?;
        let sig_count = signatures.len();
        let required = proposal.required_signatures as usize;
        if sig_count < required {
            return Err(MultiSigError::InsufficientSignatures(
                proposal_id,
                sig_count,
                required,
            ));
        }

        // Mark as submitted
        let submitted = self
            .repo
            .update_proposal_status(
                proposal_id,
                MultiSigProposalStatus::Submitted,
                Some(signed_xdr),
                None,
                None,
            )
            .await?;

        self.append_log(
            Some(proposal_id),
            "transaction_submitted",
            Some(actor_key),
            None,
            &json!({ "signatures_count": sig_count }),
        )
        .await?;

        self.notifier
            .notify(&submitted, NotificationEvent::Submitted)
            .await;

        // Submit to Stellar Horizon
        match self.stellar.submit_transaction_xdr(signed_xdr).await {
            Ok(result) => {
                let tx_hash = result
                    .get("hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let confirmed = self
                    .repo
                    .update_proposal_status(
                        proposal_id,
                        MultiSigProposalStatus::Confirmed,
                        None,
                        Some(&tx_hash),
                        None,
                    )
                    .await?;

                self.append_log(
                    Some(proposal_id),
                    "transaction_confirmed",
                    Some(actor_key),
                    None,
                    &json!({ "stellar_tx_hash": tx_hash }),
                )
                .await?;

                self.notifier
                    .notify(&confirmed, NotificationEvent::Confirmed)
                    .await;

                info!(
                    proposal_id = %proposal_id,
                    tx_hash = %tx_hash,
                    "Multi-sig transaction confirmed on Stellar"
                );

                Ok(confirmed)
            }
            Err(e) => {
                let reason = e.to_string();
                warn!(
                    proposal_id = %proposal_id,
                    error = %reason,
                    "Stellar submission failed"
                );

                self.append_log(
                    Some(proposal_id),
                    "submission_failed",
                    Some(actor_key),
                    None,
                    &json!({ "error": reason }),
                )
                .await?;

                Err(MultiSigError::StellarSubmission(reason))
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Reject
    // ─────────────────────────────────────────────────────────────────────────

    /// Explicitly reject a proposal.
    ///
    /// Any active signer can reject a proposal at any point before submission.
    pub async fn reject(
        &self,
        proposal_id: Uuid,
        signer_key: &str,
        reason: &str,
    ) -> Result<MultiSigProposal, MultiSigError> {
        let proposal = self.repo.get_proposal(proposal_id).await?;

        if proposal.status.is_terminal() {
            return Err(MultiSigError::TerminalState(
                proposal_id,
                format!("{:?}", proposal.status),
            ));
        }

        // Verify signer is active
        let (signer_id, _) = self
            .repo
            .find_active_signer_by_key(signer_key)
            .await?
            .ok_or_else(|| MultiSigError::UnauthorisedSigner(signer_key.to_string()))?;

        let rejected = self
            .repo
            .update_proposal_status(
                proposal_id,
                MultiSigProposalStatus::Rejected,
                None,
                None,
                Some(reason),
            )
            .await?;

        self.append_log(
            Some(proposal_id),
            "proposal_rejected",
            Some(signer_key),
            Some(signer_id),
            &json!({ "reason": reason }),
        )
        .await?;

        self.notifier
            .notify(&rejected, NotificationEvent::Rejected)
            .await;

        warn!(
            proposal_id = %proposal_id,
            signer = %signer_key,
            reason = %reason,
            "Multi-sig proposal rejected"
        );

        Ok(rejected)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Queries
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn get_proposal_detail(
        &self,
        proposal_id: Uuid,
    ) -> Result<ProposalDetail, MultiSigError> {
        let proposal = self.repo.get_proposal(proposal_id).await?;
        let signatures = self.repo.list_signatures(proposal_id).await?;
        let sig_count = signatures.len();
        let required = proposal.required_signatures as usize;

        let time_lock_remaining = proposal.time_lock_until.map(|tl| {
            let remaining = tl - Utc::now();
            remaining.num_seconds().max(0)
        });

        Ok(ProposalDetail {
            signatures_collected: sig_count,
            signatures_required: required,
            time_lock_remaining_secs: time_lock_remaining,
            proposal,
            signatures,
        })
    }

    pub async fn list_proposals(
        &self,
        query: &ListProposalsQuery,
    ) -> Result<ProposalListResponse, MultiSigError> {
        let (proposals, total) = self
            .repo
            .list_proposals(query.status, query.op_type, query.page_size(), query.offset())
            .await?;

        Ok(ProposalListResponse {
            proposals,
            total,
            page: query.page(),
            page_size: query.page_size(),
        })
    }

    pub async fn get_governance_log(
        &self,
        proposal_id: Uuid,
    ) -> Result<Vec<GovernanceLogEntry>, MultiSigError> {
        self.repo.list_governance_log(proposal_id).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// Build unsigned XDR from operation parameters.
    async fn build_xdr(
        &self,
        op_type: MultiSigOpType,
        params: Option<serde_json::Value>,
    ) -> Result<String, MultiSigError> {
        let params = params.unwrap_or(serde_json::Value::Null);

        match op_type {
            MultiSigOpType::Mint => {
                let destination = params["destination"]
                    .as_str()
                    .ok_or_else(|| MultiSigError::XdrBuild("missing 'destination'".to_string()))?;
                let amount_str = params["amount_stroops"]
                    .as_str()
                    .ok_or_else(|| MultiSigError::XdrBuild("missing 'amount_stroops'".to_string()))?;
                let amount: i64 = amount_str
                    .parse()
                    .map_err(|_| MultiSigError::XdrBuild("invalid 'amount_stroops'".to_string()))?;

                let sequence = self
                    .stellar
                    .get_account(&self.issuer_address)
                    .await
                    .map_err(|e| MultiSigError::StellarSubmission(e.to_string()))?
                    .sequence;

                build_mint_xdr(&self.issuer_address, destination, amount, sequence)
            }

            MultiSigOpType::Burn => {
                let source = params["source"]
                    .as_str()
                    .ok_or_else(|| MultiSigError::XdrBuild("missing 'source'".to_string()))?;
                let amount_str = params["amount_stroops"]
                    .as_str()
                    .ok_or_else(|| MultiSigError::XdrBuild("missing 'amount_stroops'".to_string()))?;
                let amount: i64 = amount_str
                    .parse()
                    .map_err(|_| MultiSigError::XdrBuild("invalid 'amount_stroops'".to_string()))?;

                let sequence = self
                    .stellar
                    .get_account(source)
                    .await
                    .map_err(|e| MultiSigError::StellarSubmission(e.to_string()))?
                    .sequence;

                build_burn_xdr(source, &self.issuer_address, amount, sequence)
            }

            MultiSigOpType::SetOptions
            | MultiSigOpType::AddSigner
            | MultiSigOpType::RemoveSigner
            | MultiSigOpType::ChangeThreshold => {
                let sequence = self
                    .stellar
                    .get_account(&self.issuer_address)
                    .await
                    .map_err(|e| MultiSigError::StellarSubmission(e.to_string()))?
                    .sequence;

                let signer = if let (Some(key), Some(weight)) = (
                    params["signer_key"].as_str(),
                    params["signer_weight"].as_u64(),
                ) {
                    Some((key.to_string(), weight as u32))
                } else {
                    None
                };

                let set_params = SetOptionsParams {
                    master_weight: params["master_weight"].as_u64().map(|v| v as u32),
                    low_threshold: params["low_threshold"].as_u64().map(|v| v as u32),
                    med_threshold: params["med_threshold"].as_u64().map(|v| v as u32),
                    high_threshold: params["high_threshold"].as_u64().map(|v| v as u32),
                    signer,
                };

                build_set_options_xdr(&self.issuer_address, sequence, set_params)
            }
        }
    }

    /// Append a tamper-evident entry to the governance log.
    async fn append_log(
        &self,
        proposal_id: Option<Uuid>,
        event_type: &str,
        actor_key: Option<&str>,
        actor_id: Option<Uuid>,
        payload: &serde_json::Value,
    ) -> Result<GovernanceLogEntry, MultiSigError> {
        let previous_hash = self.repo.get_last_log_hash(proposal_id).await?;
        let current_hash = compute_entry_hash(
            previous_hash.as_deref(),
            proposal_id,
            event_type,
            actor_key,
            payload,
        );

        self.repo
            .append_governance_log(
                proposal_id,
                event_type,
                actor_key,
                actor_id,
                payload,
                previous_hash.as_deref(),
                &current_hash,
            )
            .await
    }
}
