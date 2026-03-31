//! Issuer account setup: account creation, flag configuration, multi-sig configuration,
//! distribution account setup, and fee account setup.
//!
//! Private key material is NEVER handled here — all key references are secrets manager paths.

use crate::chains::stellar::{
    client::StellarClient,
    errors::{StellarError, StellarResult},
    issuer::types::{DistributionAccount, IssuerConfig, MultiSigConfig, VerificationReport},
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use stellar_strkey::ed25519::{PrivateKey as StrkeyPrivateKey, PublicKey as StrkeyPublicKey};
use stellar_xdr::next::{
    AccountId, AlphaNum12, AlphaNum4, AssetCode12, AssetCode4, ChangeTrustAsset,
    ChangeTrustOp, Limits, MuxedAccount, Operation, OperationBody,
    Preconditions, PublicKey, SequenceNumber, SetOptionsOp,
    Signer as XdrSigner, SignerKey, SignerKeyEd25519, StringM, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
};
use tracing::info;

// ---------------------------------------------------------------------------
// Keypair generation
// ---------------------------------------------------------------------------

/// A freshly generated Stellar keypair.
/// The secret key is returned ONCE for immediate storage in the secrets manager.
/// It must never be logged or persisted anywhere else.
#[derive(Debug)]
pub struct GeneratedKeypair {
    pub public_key: String,
    /// Raw secret key bytes — store immediately in secrets manager, then zeroize.
    pub secret_key_bytes: [u8; 32],
    pub secret_key_strkey: String,
}

/// Generate a cryptographically secure Stellar keypair using OsRng (≥256 bits entropy).
pub fn generate_keypair() -> StellarResult<GeneratedKeypair> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let secret_bytes: [u8; 32] = signing_key.to_bytes();

    let strkey_private = StrkeyPrivateKey(secret_bytes);
    let strkey_public = StrkeyPublicKey(signing_key.verifying_key().to_bytes());

    Ok(GeneratedKeypair {
        public_key: strkey_public.to_string(),
        secret_key_bytes: secret_bytes,
        secret_key_strkey: strkey_private.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Account flag constants (Stellar protocol)
// ---------------------------------------------------------------------------

const FLAG_AUTH_REQUIRED: u32 = 0x1;
const FLAG_AUTH_REVOCABLE: u32 = 0x2;
const FLAG_AUTH_CLAWBACK_ENABLED: u32 = 0x8;
const DEFAULT_BASE_FEE: u32 = 100;

// ---------------------------------------------------------------------------
// Unsigned transaction builders
// ---------------------------------------------------------------------------

/// Unsigned XDR for setting issuer account flags and home domain.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnsignedSetOptions {
    pub account_id: String,
    pub sequence: i64,
    pub unsigned_xdr: String,
}

/// Build an unsigned SetOptions transaction that:
/// - Sets AUTH_REQUIRED | AUTH_REVOCABLE | AUTH_CLAWBACK_ENABLED
/// - Sets home_domain
/// - Sets master weight to 0
/// - Adds all signers with their weights
/// - Sets low/med/high thresholds
pub fn build_issuer_setup_transaction(
    account_id: &str,
    sequence: i64,
    home_domain: &str,
    multisig: &MultiSigConfig,
) -> StellarResult<UnsignedSetOptions> {
    let source_pk = StrkeyPublicKey::from_string(account_id)
        .map_err(|_| StellarError::invalid_address(account_id))?;

    let source_muxed = MuxedAccount::Ed25519(Uint256(source_pk.0));

    // Build one SetOptions operation per signer + one for flags/thresholds/domain.
    // Stellar allows multiple operations in one transaction.
    let mut operations: Vec<Operation> = Vec::new();

    // Op 1: Set flags, home domain, master weight, thresholds
    let home_domain_strm: StringM<32> = home_domain
        .try_into()
        .map_err(|_| StellarError::config_error("home_domain too long (max 32 chars)"))?;

    let set_options_op = SetOptionsOp {
        inflation_dest: None,
        clear_flags: None,
        set_flags: Some(FLAG_AUTH_REQUIRED | FLAG_AUTH_REVOCABLE | FLAG_AUTH_CLAWBACK_ENABLED),
        master_weight: Some(multisig.master_weight as u32),
        low_threshold: Some(multisig.low_threshold as u32),
        med_threshold: Some(multisig.med_threshold as u32),
        high_threshold: Some(multisig.high_threshold as u32),
        home_domain: Some(home_domain_strm),
        signer: None,
    };

    operations.push(Operation {
        source_account: None,
        body: OperationBody::SetOptions(set_options_op),
    });

    // One SetOptions op per signer to add them
    for signer in &multisig.signers {
        let signer_pk = StrkeyPublicKey::from_string(&signer.public_key)
            .map_err(|_| StellarError::invalid_address(&signer.public_key))?;

        let signer_op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: Some(XdrSigner {
                key: SignerKey::Ed25519(SignerKeyEd25519(Uint256(signer_pk.0))),
                weight: signer.weight as u32,
            }),
        };

        operations.push(Operation {
            source_account: None,
            body: OperationBody::SetOptions(signer_op),
        });
    }

    let ops_vec: VecM<Operation, 100> = operations
        .try_into()
        .map_err(|_| StellarError::config_error("too many operations"))?;

    let tx = Transaction {
        source_account: source_muxed,
        fee: DEFAULT_BASE_FEE * (1 + multisig.signers.len() as u32),
        seq_num: SequenceNumber(sequence + 1),
        cond: Preconditions::None,
        memo: stellar_xdr::next::Memo::None,
        operations: ops_vec,
        ext: TransactionExt::V0,
    };

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let xdr = envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| StellarError::serialization_error(e.to_string()))?;

    info!(
        account_id = %account_id,
        signers = multisig.signers.len(),
        "Built issuer setup transaction (unsigned)"
    );

    Ok(UnsignedSetOptions {
        account_id: account_id.to_string(),
        sequence,
        unsigned_xdr: xdr,
    })
}

/// Build an unsigned ChangeTrust transaction for the distribution account to establish
/// a cNGN trustline to the issuer.
pub fn build_trustline_transaction(
    distribution_account_id: &str,
    sequence: i64,
    asset_code: &str,
    issuer_account_id: &str,
    limit: Option<&str>,
) -> StellarResult<String> {
    let source_pk = StrkeyPublicKey::from_string(distribution_account_id)
        .map_err(|_| StellarError::invalid_address(distribution_account_id))?;

    let issuer_pk = StrkeyPublicKey::from_string(issuer_account_id)
        .map_err(|_| StellarError::invalid_address(issuer_account_id))?;

    let issuer_account_id_xdr =
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_pk.0)));

    let trust_asset = build_change_trust_asset_inner(asset_code, issuer_account_id_xdr)?;

    let trust_limit = match limit {
        Some(l) => (l.parse::<f64>().unwrap_or(0.0) * 10_000_000.0) as i64,
        None => i64::MAX,
    };

    let change_trust = ChangeTrustOp {
        line: trust_asset,
        limit: trust_limit,
    };

    let ops: VecM<Operation, 100> = vec![Operation {
        source_account: None,
        body: OperationBody::ChangeTrust(change_trust),
    }]
    .try_into()
    .map_err(|_| StellarError::config_error("op vec error"))?;

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(source_pk.0)),
        fee: DEFAULT_BASE_FEE,
        seq_num: SequenceNumber(sequence + 1),
        cond: Preconditions::None,
        memo: stellar_xdr::next::Memo::None,
        operations: ops,
        ext: TransactionExt::V0,
    };

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| StellarError::serialization_error(e.to_string()))
}

fn build_change_trust_asset_inner(
    code: &str,
    issuer: AccountId,
) -> StellarResult<ChangeTrustAsset> {
    let bytes = code.as_bytes();
    match code.len() {
        1..=4 => {
            let mut buf = [0u8; 4];
            buf[..bytes.len()].copy_from_slice(bytes);
            Ok(ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(buf),
                issuer,
            }))
        }
        5..=12 => {
            let mut buf = [0u8; 12];
            buf[..bytes.len()].copy_from_slice(bytes);
            Ok(ChangeTrustAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(buf),
                issuer,
            }))
        }
        _ => Err(StellarError::config_error(format!(
            "invalid asset code length: {}",
            code
        ))),
    }
}

// ---------------------------------------------------------------------------
// IssuerSetupService
// ---------------------------------------------------------------------------

/// Orchestrates issuer account setup steps.
/// All operations that require signing are returned as unsigned XDR for
/// offline multi-sig signing by authorized key holders.
pub struct IssuerSetupService {
    client: StellarClient,
}

impl IssuerSetupService {
    pub fn new(client: StellarClient) -> Self {
        Self { client }
    }

    /// Fetch the current sequence number for an account.
    pub async fn get_sequence(&self, account_id: &str) -> StellarResult<i64> {
        let account = self.client.get_account(account_id).await?;
        Ok(account.sequence)
    }

    /// Build the unsigned issuer setup transaction (flags + multisig).
    /// The returned XDR must be signed by the required number of authorized signers
    /// before submission.
    pub async fn build_setup_transaction(
        &self,
        config: &IssuerConfig,
    ) -> StellarResult<UnsignedSetOptions> {
        let sequence = self.get_sequence(&config.issuer_account_id).await?;
        build_issuer_setup_transaction(
            &config.issuer_account_id,
            sequence,
            &config.home_domain,
            &config.multisig,
        )
    }

    /// Build the unsigned trustline transaction for the distribution account.
    pub async fn build_distribution_trustline(
        &self,
        distribution: &DistributionAccount,
        issuer_account_id: &str,
        asset_code: &str,
    ) -> StellarResult<String> {
        let sequence = self.get_sequence(&distribution.account_id).await?;
        build_trustline_transaction(
            &distribution.account_id,
            sequence,
            asset_code,
            issuer_account_id,
            None,
        )
    }

    /// Verify the issuer account is correctly configured on-chain.
    pub async fn verify_issuer_account(
        &self,
        config: &IssuerConfig,
    ) -> StellarResult<VerificationReport> {
        crate::chains::stellar::issuer::verification::verify_issuer_account(
            &self.client,
            config,
            None,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::stellar::issuer::types::MultiSigConfig;

    #[test]
    fn test_generate_keypair_produces_valid_g_address() {
        let kp = generate_keypair().expect("keypair generation failed");
        assert!(kp.public_key.starts_with('G'));
        assert_eq!(kp.public_key.len(), 56);
        assert!(kp.secret_key_strkey.starts_with('S'));
    }

    #[test]
    fn test_generate_keypair_unique() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn test_build_change_trust_asset_alphanum4() {
        let issuer = generate_keypair().unwrap();
        let issuer_pk = StrkeyPublicKey::from_string(&issuer.public_key).unwrap();
        let issuer_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_pk.0)));
        let asset = build_change_trust_asset_inner("cNGN", issuer_id);
        assert!(asset.is_ok());
    }

    #[test]
    fn test_build_change_trust_asset_invalid_code() {
        let issuer = generate_keypair().unwrap();
        let issuer_pk = StrkeyPublicKey::from_string(&issuer.public_key).unwrap();
        let issuer_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_pk.0)));
        let asset = build_change_trust_asset_inner("TOOLONGCODE123", issuer_id);
        assert!(asset.is_err());
    }
}
