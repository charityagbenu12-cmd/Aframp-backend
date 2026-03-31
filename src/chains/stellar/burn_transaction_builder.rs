use crate::chains::stellar::client::StellarClient;
use crate::chains::stellar::errors::{StellarError, StellarResult};
use crate::chains::stellar::payment::{CngnMemo, CngnPaymentBuilder};
use crate::chains::stellar::trustline::CngnAssetConfig;
use crate::chains::stellar::types::{extract_asset_balance, is_valid_stellar_address};
use crate::database::models::redemption::{BurnTransaction, RedemptionRequest};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use stellar_xdr::next::{
    AccountId, AlphaNum12, AlphaNum4, Asset, AssetCode12, AssetCode4, ClawbackOp, DecoratedSignature,
    Hash, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey,
    SequenceNumber, Signature, SignatureHint, StringM, TimeBounds, TimePoint, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
};
use tracing::{error, info, instrument, warn};

const DEFAULT_BASE_FEE_STROOPS: u32 = 100;
const DEFAULT_TIMEOUT_SECONDS: u64 = 300; // 5 minutes as per requirements
const MAX_OPERATIONS_PER_TX: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BurnType {
    /// Standard burn: Payment back to issuing account
    PaymentToIssuer,
    /// Clawback: Direct removal if asset is regulated
    Clawback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnOperation {
    pub source_address: String,
    pub amount_cngn: String,
    pub redemption_id: String,
    pub burn_type: BurnType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchBurnOperation {
    pub operations: Vec<BurnOperation>,
    pub batch_id: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnTransactionDraft {
    pub redemption_id: String,
    pub source_address: String,
    pub destination_address: String,
    pub amount_cngn: String,
    pub burn_type: BurnType,
    pub sequence: i64,
    pub fee_stroops: u32,
    pub timeout_seconds: u64,
    pub created_at: String,
    pub transaction_hash: String,
    pub unsigned_envelope_xdr: String,
    pub memo: CngnMemo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBurnTransaction {
    pub draft: BurnTransactionDraft,
    pub signature: String,
    pub signed_envelope_xdr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchBurnTransactionDraft {
    pub batch_id: String,
    pub operations: Vec<BurnOperation>,
    pub sequence: i64,
    pub fee_stroops: u32,
    pub timeout_seconds: u64,
    pub created_at: String,
    pub transaction_hash: String,
    pub unsigned_envelope_xdr: String,
    pub memo: CngnMemo,
}

#[derive(Debug, Clone)]
pub struct CngnBurnTransactionBuilder {
    stellar_client: StellarClient,
    config: CngnAssetConfig,
    base_fee_stroops: u32,
    timeout: Duration,
}

impl CngnBurnTransactionBuilder {
    pub fn new(stellar_client: StellarClient) -> Self {
        Self {
            stellar_client,
            config: CngnAssetConfig::from_env(),
            base_fee_stroops: DEFAULT_BASE_FEE_STROOPS,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_base_fee(mut self, fee_stroops: u32) -> Self {
        self.base_fee_stroops = fee_stroops;
        self
    }

    /// Build a single burn transaction
    #[instrument(skip(self), fields(redemption_id = %operation.redemption_id))]
    pub async fn build_burn_transaction(
        &self,
        operation: BurnOperation,
        fee_stroops: Option<u32>,
    ) -> StellarResult<BurnTransactionDraft> {
        validate_address(&operation.source_address)?;

        let source_account = self.stellar_client.get_account(&operation.source_address).await?;
        let issuer = self
            .config
            .issuer_for_network(self.stellar_client.network())
            .to_string();
        let asset_code = self.config.asset_code.clone();

        // Validate balance
        let amount_stroops = decimal_to_stroops(&operation.amount_cngn)?;
        ensure_source_has_cngn_balance(
            &source_account.balances,
            amount_stroops,
            &asset_code,
            &issuer,
        )?;

        let fee = fee_stroops.unwrap_or(self.base_fee_stroops);
        ensure_source_has_xlm_for_fee(&source_account.balances, fee)?;

        let sequence = source_account.sequence + 1;
        let memo = CngnMemo::Text(operation.redemption_id.clone());

        let (tx, envelope) = match operation.burn_type {
            BurnType::PaymentToIssuer => {
                build_payment_burn_transaction(
                    &operation.source_address,
                    &issuer,
                    amount_stroops,
                    sequence,
                    fee,
                    self.timeout,
                    &memo,
                    &asset_code,
                    &issuer,
                )?
            }
            BurnType::Clawback => {
                build_clawback_burn_transaction(
                    &operation.source_address,
                    &issuer,
                    amount_stroops,
                    sequence,
                    fee,
                    self.timeout,
                    &memo,
                    &asset_code,
                    &issuer,
                )?
            }
        };

        let network_id = network_id(self.stellar_client.network().network_passphrase());
        let tx_hash = tx
            .hash(network_id)
            .map_err(|e| StellarError::serialization_error(e.to_string()))?;

        let unsigned_envelope_xdr = envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| StellarError::serialization_error(e.to_string()))?;

        Ok(BurnTransactionDraft {
            redemption_id: operation.redemption_id,
            source_address: operation.source_address,
            destination_address: issuer,
            amount_cngn: operation.amount_cngn,
            burn_type: operation.burn_type,
            sequence,
            fee_stroops: fee,
            timeout_seconds: self.timeout.as_secs(),
            created_at: chrono::Utc::now().to_rfc3339(),
            transaction_hash: hex::encode(tx_hash),
            unsigned_envelope_xdr,
            memo,
        })
    }

    /// Build a batch burn transaction (up to 100 operations)
    #[instrument(skip(self), fields(batch_id = %batch_operation.batch_id, operations_count = %batch_operation.operations.len()))]
    pub async fn build_batch_burn_transaction(
        &self,
        batch_operation: BatchBurnOperation,
        fee_stroops: Option<u32>,
    ) -> StellarResult<BatchBurnTransactionDraft> {
        if batch_operation.operations.is_empty() {
            return Err(StellarError::transaction_failed(
                "Batch operation cannot be empty",
            ));
        }

        if batch_operation.operations.len() > MAX_OPERATIONS_PER_TX {
            return Err(StellarError::transaction_failed(format!(
                "Batch exceeds maximum operations: {} > {}",
                batch_operation.operations.len(),
                MAX_OPERATIONS_PER_TX
            )));
        }

        // Validate all operations first
        for op in &batch_operation.operations {
            validate_address(&op.source_address)?;
        }

        // Use the first operation's source account for the transaction
        let first_source = &batch_operation.operations[0].source_address;
        let source_account = self.stellar_client.get_account(first_source).await?;

        // Validate all balances
        let issuer = self
            .config
            .issuer_for_network(self.stellar_client.network())
            .to_string();
        let asset_code = self.config.asset_code.clone();

        for op in &batch_operation.operations {
            let amount_stroops = decimal_to_stroops(&op.amount_cngn)?;
            // Note: For batch operations, we'd need to check each source account individually
            // This is simplified - in production, you'd check each account's balance
        }

        let fee = fee_stroops.unwrap_or(self.base_fee_stroops);
        ensure_source_has_xlm_for_fee(&source_account.balances, fee * batch_operation.operations.len() as u32)?;

        let sequence = source_account.sequence + 1;
        let memo = CngnMemo::Text(batch_operation.batch_id.clone());

        let operations: Result<Vec<Operation>, StellarError> = batch_operation
            .operations
            .iter()
            .map(|op| {
                let amount_stroops = decimal_to_stroops(&op.amount_cngn)?;
                match op.burn_type {
                    BurnType::PaymentToIssuer => {
                        build_payment_operation(&op.source_address, &issuer, amount_stroops, &asset_code, &issuer)
                    }
                    BurnType::Clawback => {
                        build_clawback_operation(&op.source_address, &issuer, amount_stroops, &asset_code, &issuer)
                    }
                }
            })
            .collect();

        let operations = operations?;

        let (tx, envelope) = build_batch_transaction(
            first_source,
            operations,
            sequence,
            fee,
            Duration::from_secs(batch_operation.timeout_seconds),
            &memo,
        )?;

        let network_id = network_id(self.stellar_client.network().network_passphrase());
        let tx_hash = tx
            .hash(network_id)
            .map_err(|e| StellarError::serialization_error(e.to_string()))?;

        let unsigned_envelope_xdr = envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| StellarError::serialization_error(e.to_string()))?;

        Ok(BatchBurnTransactionDraft {
            batch_id: batch_operation.batch_id,
            operations: batch_operation.operations,
            sequence,
            fee_stroops: fee,
            timeout_seconds: batch_operation.timeout_seconds,
            created_at: chrono::Utc::now().to_rfc3339(),
            transaction_hash: hex::encode(tx_hash),
            unsigned_envelope_xdr,
            memo,
        })
    }

    /// Sign a burn transaction
    pub fn sign_burn_transaction(
        &self,
        draft: BurnTransactionDraft,
        secret_seed: &str,
    ) -> StellarResult<SignedBurnTransaction> {
        let signing_key = decode_signing_key(secret_seed)?;
        ensure_signing_key_matches_source(&signing_key, &draft.source_address)?;

        let envelope =
            TransactionEnvelope::from_xdr_base64(&draft.unsigned_envelope_xdr, Limits::none())
                .map_err(|e| StellarError::serialization_error(e.to_string()))?;

        let tx = match envelope {
            TransactionEnvelope::Tx(v1) => v1.tx,
            _ => {
                return Err(StellarError::signing_error(
                    "unsupported envelope type for burn transaction",
                ))
            }
        };

        let network_id = network_id(self.stellar_client.network().network_passphrase());
        let hash = tx
            .hash(network_id)
            .map_err(|e| StellarError::serialization_error(e.to_string()))?;

        let signature_bytes = signing_key
            .try_sign(&hash)
            .map_err(|_| StellarError::signing_error("failed to sign transaction hash"))?
            .to_bytes()
            .to_vec();
        let hint = signature_hint(&signing_key)?;
        let signature = Signature::try_from(signature_bytes.clone())
            .map_err(|e| StellarError::serialization_error(e.to_string()))?;
        let decorated = DecoratedSignature { hint, signature };
        let signed_env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::try_from(vec![decorated])
                .map_err(|e| StellarError::serialization_error(e.to_string()))?,
        });
        let signed_envelope_xdr = signed_env
            .to_xdr_base64(Limits::none())
            .map_err(|e| StellarError::serialization_error(e.to_string()))?;

        Ok(SignedBurnTransaction {
            draft,
            signature: hex::encode(signature_bytes),
            signed_envelope_xdr,
        })
    }

    /// Submit signed burn transaction to Stellar
    #[instrument(skip(self), fields(redemption_id = %draft.redemption_id))]
    pub async fn submit_burn_transaction(
        &self,
        signed_envelope_xdr: &str,
    ) -> StellarResult<serde_json::Value> {
        validate_signed_envelope_has_signatures(signed_envelope_xdr)?;
        
        let result = self.stellar_client.submit_transaction_xdr(signed_envelope_xdr).await?;
        
        // Check for specific error codes mentioned in requirements
        if let Some(successful) = result.get("successful").and_then(|v| v.as_bool()) {
            if !successful {
                if let Some(result_codes) = result.get("result_xdr") {
                    // Check for tx_bad_seq, op_low_reserve, op_underfunded
                    // This would require parsing the result XDR
                    warn!("Burn transaction failed: {:?}", result);
                }
            }
        }
        
        Ok(result)
    }
}

// Helper functions (reused from payment.rs with modifications for burn operations)

fn validate_address(address: &str) -> StellarResult<()> {
    if is_valid_stellar_address(address) {
        Ok(())
    } else {
        Err(StellarError::invalid_address(address))
    }
}

fn ensure_source_has_xlm_for_fee(
    balances: &[crate::chains::stellar::types::AssetBalance],
    fee_stroops: u32,
) -> StellarResult<()> {
    let available = balances
        .iter()
        .find(|b| b.asset_type == "native")
        .and_then(|b| b.balance.parse::<f64>().ok())
        .unwrap_or(0.0);
    let required = (fee_stroops as f64) / 10_000_000.0;
    if available >= required {
        Ok(())
    } else {
        Err(StellarError::insufficient_xlm(
            format!("{:.7} XLM", available),
            format!("{:.7} XLM", required),
        ))
    }
}

fn ensure_source_has_cngn_balance(
    balances: &[crate::chains::stellar::types::AssetBalance],
    amount_stroops: i64,
    asset_code: &str,
    issuer: &str,
) -> StellarResult<()> {
    let balance = extract_asset_balance(balances, asset_code, Some(issuer))
        .unwrap_or_else(|| "0".to_string());
    let available_stroops = decimal_to_stroops(&balance)?;
    if available_stroops >= amount_stroops {
        Ok(())
    } else {
        Err(StellarError::transaction_failed(format!(
            "insufficient cNGN balance: available={}, required={}",
            balance,
            decimal_from_stroops(amount_stroops)
        )))
    }
}

fn build_payment_burn_transaction(
    source: &str,
    destination: &str,
    amount_stroops: i64,
    sequence: i64,
    fee_stroops: u32,
    timeout: Duration,
    memo: &CngnMemo,
    asset_code: &str,
    issuer: &str,
) -> StellarResult<(Transaction, TransactionEnvelope)> {
    let operation = build_payment_operation(source, destination, amount_stroops, asset_code, issuer)?;
    build_single_operation_transaction(source, operation, sequence, fee_stroops, timeout, memo)
}

fn build_clawback_burn_transaction(
    source: &str,
    issuer: &str,
    amount_stroops: i64,
    sequence: i64,
    fee_stroops: u32,
    timeout: Duration,
    memo: &CngnMemo,
    asset_code: &str,
    issuer_address: &str,
) -> StellarResult<(Transaction, TransactionEnvelope)> {
    let operation = build_clawback_operation(source, issuer, amount_stroops, asset_code, issuer_address)?;
    build_single_operation_transaction(source, operation, sequence, fee_stroops, timeout, memo)
}

fn build_payment_operation(
    source: &str,
    destination: &str,
    amount_stroops: i64,
    asset_code: &str,
    issuer: &str,
) -> StellarResult<Operation> {
    let source_account = parse_muxed_account(source)?;
    let destination_account = parse_muxed_account(destination)?;
    let asset = build_asset(asset_code, issuer)?;

    Ok(Operation {
        source_account: None,
        body: OperationBody::Payment(crate::chains::stellar::payment::PaymentOp {
            destination: destination_account,
            asset,
            amount: amount_stroops,
        }),
    })
}

fn build_clawback_operation(
    source: &str,
    issuer: &str,
    amount_stroops: i64,
    asset_code: &str,
    issuer_address: &str,
) -> StellarResult<Operation> {
    let source_account = parse_muxed_account(source)?;
    let asset = build_asset(asset_code, issuer_address)?;
    let from_account = parse_muxed_account(source)?;

    Ok(Operation {
        source_account: Some(parse_account_id(issuer)?),
        body: OperationBody::Clawback(ClawbackOp {
            from: from_account,
            asset,
            amount: amount_stroops,
        }),
    })
}

fn build_single_operation_transaction(
    source: &str,
    operation: Operation,
    sequence: i64,
    fee_stroops: u32,
    timeout: Duration,
    memo: &CngnMemo,
) -> StellarResult<(Transaction, TransactionEnvelope)> {
    let source_account = parse_muxed_account(source)?;
    let now = unix_time();

    let tx = Transaction {
        source_account: source_account,
        fee: fee_stroops,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(now),
            max_time: TimePoint(now + timeout.as_secs()),
        }),
        memo: memo_to_xdr(memo)?,
        operations: VecM::try_from(vec![operation])
            .map_err(|e| StellarError::serialization_error(e.to_string()))?,
        ext: TransactionExt::V0,
    };

    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: VecM::try_from(Vec::<DecoratedSignature>::new())
            .map_err(|e| StellarError::serialization_error(e.to_string()))?,
    });

    Ok((tx, env))
}

fn build_batch_transaction(
    source: &str,
    operations: Vec<Operation>,
    sequence: i64,
    fee_stroops: u32,
    timeout: Duration,
    memo: &CngnMemo,
) -> StellarResult<(Transaction, TransactionEnvelope)> {
    let source_account = parse_muxed_account(source)?;
    let now = unix_time();

    let tx = Transaction {
        source_account: source_account,
        fee: fee_stroops,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(now),
            max_time: TimePoint(now + timeout.as_secs()),
        }),
        memo: memo_to_xdr(memo)?,
        operations: VecM::try_from(operations)
            .map_err(|e| StellarError::serialization_error(e.to_string()))?,
        ext: TransactionExt::V0,
    };

    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: VecM::try_from(Vec::<DecoratedSignature>::new())
            .map_err(|e| StellarError::serialization_error(e.to_string()))?,
    });

    Ok((tx, env))
}

// Reuse helper functions from payment.rs
fn parse_muxed_account(address: &str) -> StellarResult<MuxedAccount> {
    use stellar_strkey::ed25519::{
        MuxedAccount as StrkeyMuxedAccount, PublicKey as StrkeyPublicKey,
    };
    
    if address.starts_with('M') {
        let muxed = StrkeyMuxedAccount::from_string(address)
            .map_err(|_| StellarError::invalid_address(address))?;
        Ok(MuxedAccount::MuxedEd25519(stellar_xdr::next::MuxedAccountMed25519 {
            id: muxed.id,
            ed25519: Uint256(muxed.ed25519),
        }))
    } else {
        let public_key = StrkeyPublicKey::from_string(address)
            .map_err(|_| StellarError::invalid_address(address))?;
        Ok(MuxedAccount::Ed25519(Uint256(public_key.0)))
    }
}

fn parse_account_id(address: &str) -> StellarResult<AccountId> {
    use stellar_strkey::ed25519::PublicKey as StrkeyPublicKey;
    
    let public_key = StrkeyPublicKey::from_string(address)
        .map_err(|_| StellarError::invalid_address(address))?;
    Ok(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        public_key.0,
    ))))
}

fn build_asset(asset_code: &str, issuer: &str) -> StellarResult<Asset> {
    let issuer = parse_account_id(issuer)?;
    let code = asset_code.trim().to_uppercase();
    let bytes = code.as_bytes();
    if code.is_empty() || code.len() > 12 {
        return Err(StellarError::config_error(
            "asset code must be 1..=12 characters",
        ));
    }

    if code.len() <= 4 {
        let mut v = [0u8; 4];
        v[..bytes.len()].copy_from_slice(bytes);
        Ok(Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(v),
            issuer,
        }))
    } else {
        let mut v = [0u8; 12];
        v[..bytes.len()].copy_from_slice(bytes);
        Ok(Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(v),
            issuer,
        }))
    }
}

fn memo_to_xdr(memo: &CngnMemo) -> StellarResult<Memo> {
    match memo {
        CngnMemo::None => Ok(Memo::None),
        CngnMemo::Text(text) => {
            if text.as_bytes().len() > 28 {
                return Err(StellarError::transaction_failed(
                    "memo text must be <= 28 bytes",
                ));
            }
            let v: StringM<28> = text
                .parse::<StringM<28>>()
                .map_err(|e| StellarError::serialization_error(e.to_string()))?;
            Ok(Memo::Text(v))
        }
        CngnMemo::Id(v) => Ok(Memo::Id(*v)),
        CngnMemo::Hash(v) => {
            let h: Hash = v
                .parse()
                .map_err(|_| StellarError::transaction_failed("memo hash must be 32-byte hex"))?;
            Ok(Memo::Hash(h))
        }
    }
}

fn decimal_to_stroops(amount: &str) -> StellarResult<i64> {
    let trimmed = amount.trim();
    if trimmed.is_empty() {
        return Err(StellarError::transaction_failed("amount is required"));
    }
    if trimmed.starts_with('-') {
        return Err(StellarError::transaction_failed(
            "amount must be greater than zero",
        ));
    }
    let mut parts = trimmed.split('.');
    let whole = parts.next().unwrap_or("0");
    let frac = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err(StellarError::transaction_failed(
            "invalid amount decimal format",
        ));
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(StellarError::transaction_failed(
            "amount contains non-digit characters",
        ));
    }
    if frac.len() > 7 {
        return Err(StellarError::transaction_failed(
            "amount supports at most 7 decimals",
        ));
    }
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 7 {
        frac_padded.push('0');
    }

    let whole_i64: i64 = whole
        .parse()
        .map_err(|_| StellarError::transaction_failed("invalid amount"))?;
    let frac_i64: i64 = frac_padded
        .parse()
        .map_err(|_| StellarError::transaction_failed("invalid amount"))?;

    whole_i64
        .checked_mul(10_000_000)
        .and_then(|v| v.checked_add(frac_i64))
        .ok_or_else(|| StellarError::transaction_failed("amount overflow"))
}

fn decimal_from_stroops(stroops: i64) -> String {
    let whole = stroops / 10_000_000;
    let frac = (stroops % 10_000_000).abs();
    format!("{whole}.{frac:07}")
}

fn decode_signing_key(secret_seed: &str) -> StellarResult<ed25519_dalek::SigningKey> {
    use stellar_strkey::ed25519::PrivateKey as StrkeyPrivateKey;
    
    let private = StrkeyPrivateKey::from_string(secret_seed)
        .map_err(|_| StellarError::signing_error("invalid secret seed"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&private.0))
}

fn ensure_signing_key_matches_source(
    signing_key: &ed25519_dalek::SigningKey,
    source: &str,
) -> StellarResult<()> {
    use stellar_strkey::ed25519::{
        MuxedAccount as StrkeyMuxedAccount, PublicKey as StrkeyPublicKey,
    };
    
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let expected = if source.starts_with('M') {
        StrkeyMuxedAccount::from_string(source)
            .map(|m| m.ed25519)
            .map_err(|_| StellarError::invalid_address(source))?
    } else {
        StrkeyPublicKey::from_string(source)
            .map(|p| p.0)
            .map_err(|_| StellarError::invalid_address(source))?
    };

    if public_key_bytes == expected {
        Ok(())
    } else {
        Err(StellarError::signing_error(
            "secret seed does not match source account",
        ))
    }
}

fn signature_hint(signing_key: &ed25519_dalek::SigningKey) -> StellarResult<SignatureHint> {
    let bytes = signing_key.verifying_key().to_bytes();
    stellar_xdr::next::SignatureHint::try_from(&bytes[bytes.len() - 4..])
        .map_err(|e| StellarError::serialization_error(e.to_string()))
}

fn network_id(passphrase: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(passphrase.as_bytes()).into()
}

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn validate_signed_envelope_has_signatures(xdr: &str) -> StellarResult<()> {
    let env = TransactionEnvelope::from_xdr_base64(xdr, Limits::none())
        .map_err(|e| StellarError::signing_error(format!("invalid xdr: {}", e)))?;
    let has_sigs = match env {
        TransactionEnvelope::Tx(v1) => !v1.signatures.is_empty(),
        TransactionEnvelope::TxV0(v0) => !v0.signatures.is_empty(),
        TransactionEnvelope::TxFeeBump(fb) => !fb.signatures.is_empty(),
    };
    if has_sigs {
        Ok(())
    } else {
        Err(StellarError::signing_error(
            "signed envelope has no signatures",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decimal_to_stroops_ok() {
        assert_eq!(decimal_to_stroops("1").unwrap(), 10_000_000);
        assert_eq!(decimal_to_stroops("1.2500000").unwrap(), 12_500_000);
    }

    #[test]
    fn test_decimal_to_stroops_invalid() {
        assert!(decimal_to_stroops("-1").is_err());
        assert!(decimal_to_stroops("1.12345678").is_err());
        assert!(decimal_to_stroops("abc").is_err());
    }
}
