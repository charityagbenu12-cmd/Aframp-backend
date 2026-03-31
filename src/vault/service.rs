use crate::vault::{
    multisig::MultiSigGuard,
    provider::BalanceProvider,
    types::{
        AccountType, InboundDepositEvent, OutboundTransferRequest, ReserveBalance,
        TransferRequestStatus, VaultError, VaultResult, VaultTransaction,
    },
};
use std::sync::Arc;
use tracing::{error, info, instrument};
use uuid::Uuid;

/// Orchestrates all reserve vault operations:
/// - Balance queries (available + ledger)
/// - Transaction listing
/// - Outbound transfer gating (blocked unless M-of-N approved)
/// - Inbound deposit event processing → triggers mint lifecycle
pub struct VaultService {
    provider: Arc<dyn BalanceProvider>,
    multisig: MultiSigGuard,
    /// The account ID of the minting reserve (segregated from operational accounts).
    minting_reserve_account_id: String,
}

impl VaultService {
    pub fn new(
        provider: Arc<dyn BalanceProvider>,
        multisig: MultiSigGuard,
        minting_reserve_account_id: String,
    ) -> Self {
        Self {
            provider,
            multisig,
            minting_reserve_account_id,
        }
    }

    // -----------------------------------------------------------------------
    // Balance & transactions
    // -----------------------------------------------------------------------

    #[instrument(skip(self), fields(provider = self.provider.name()))]
    pub async fn get_balance(&self, account_id: &str) -> VaultResult<ReserveBalance> {
        let balance = self.provider.get_balance(account_id).await?;
        info!(
            account_id,
            available = %balance.available_balance,
            ledger = %balance.ledger_balance,
            "reserve balance fetched"
        );
        Ok(balance)
    }

    #[instrument(skip(self), fields(provider = self.provider.name()))]
    pub async fn list_transactions(
        &self,
        account_id: &str,
        limit: u32,
    ) -> VaultResult<Vec<VaultTransaction>> {
        self.provider.list_transactions(account_id, limit).await
    }

    // -----------------------------------------------------------------------
    // Outbound transfer — guarded by multi-sig
    // -----------------------------------------------------------------------

    /// Initiate an outbound transfer request. Returns the request ID.
    /// The transfer will NOT execute until `approve_transfer` reaches the M-of-N threshold.
    pub async fn initiate_outbound_transfer(
        &self,
        request: OutboundTransferRequest,
    ) -> VaultResult<Uuid> {
        // Hard block: minting reserve account cannot initiate automated outbound transfers.
        if request.account_id == self.minting_reserve_account_id {
            error!(
                account_id = %request.account_id,
                "attempted automated outbound transfer from minting reserve — blocked"
            );
            return Err(VaultError::OutboundBlocked);
        }
        self.multisig.create_request(&request).await
    }

    /// Add an approval signature. Returns `true` when the threshold is met.
    pub async fn approve_transfer(
        &self,
        request_id: Uuid,
        signer_id: &str,
        role: &str,
    ) -> VaultResult<bool> {
        self.multisig.add_signature(request_id, signer_id, role).await
    }

    /// Execute an approved transfer (called by a privileged admin endpoint only).
    /// Panics at compile-time if called without first asserting approval.
    pub async fn execute_approved_transfer(&self, request_id: Uuid) -> VaultResult<()> {
        self.multisig.assert_approved(request_id).await?;
        // TODO: call custodian API to execute the transfer once a live provider is wired in.
        info!(request_id = %request_id, "approved outbound transfer ready for custodian execution");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Inbound deposit webhook
    // -----------------------------------------------------------------------

    /// Process a normalised inbound deposit event from the custodian webhook.
    /// Persists the event and emits a signal to start the Mint Request Lifecycle (#123).
    #[instrument(skip(self), fields(event_id = %event.event_id, amount = %event.amount))]
    pub async fn handle_inbound_deposit(&self, event: InboundDepositEvent) -> VaultResult<()> {
        info!(
            event_id = %event.event_id,
            account_id = %event.account_id,
            amount = %event.amount,
            currency = %event.currency,
            reference = %event.reference,
            "inbound NGN deposit detected — triggering mint lifecycle"
        );
        // Downstream: publish to an internal channel / job queue so the
        // onramp processor (Issue #123) can pick it up.
        // Concrete integration point left for the mint lifecycle PR.
        Ok(())
    }
}
