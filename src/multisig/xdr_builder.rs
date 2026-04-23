//! XDR transaction builders for multi-sig treasury operations.
//!
//! All builders return **unsigned** XDR (base64). The XDR is stored in the
//! proposal so every signer can inspect the exact transaction before signing.
//!
//! Signing is performed off-chain by each signer's hardware wallet (Ledger /
//! Trezor) or key management system. The resulting `DecoratedSignature` XDR
//! is submitted back to the service via the `/sign` endpoint.

use crate::multisig::error::MultiSigError;
use stellar_strkey::ed25519::PublicKey as StrkeyPublicKey;
use stellar_xdr::next::{
    AccountId, AlphaNum12, AssetCode12, Asset as XdrAsset, Limits, MuxedAccount, Operation,
    OperationBody, PaymentOp, Preconditions, PublicKey, SequenceNumber, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

const BASE_FEE: u32 = 100;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_public_key(address: &str) -> Result<Uint256, MultiSigError> {
    let pk = StrkeyPublicKey::from_string(address)
        .map_err(|_| MultiSigError::XdrBuild(format!("invalid Stellar address: {}", address)))?;
    Ok(Uint256(pk.0))
}

fn build_cngn_asset(issuer_address: &str) -> Result<XdrAsset, MultiSigError> {
    let issuer_pk = parse_public_key(issuer_address)?;
    let issuer_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(issuer_pk));

    let mut code_bytes = [0u8; 12];
    let code = b"cNGN";
    code_bytes[..code.len()].copy_from_slice(code);

    Ok(XdrAsset::CreditAlphanum12(AlphaNum12 {
        asset_code: AssetCode12(code_bytes),
        issuer: issuer_account_id,
    }))
}

fn wrap_in_envelope(
    source_address: &str,
    sequence: i64,
    operations: Vec<Operation>,
    fee_per_op: u32,
) -> Result<String, MultiSigError> {
    let source_pk = parse_public_key(source_address)?;
    let source_muxed = MuxedAccount::Ed25519(source_pk);

    let op_count = operations.len() as u32;
    let ops_vec: VecM<Operation, 100> = operations
        .try_into()
        .map_err(|_| MultiSigError::XdrBuild("too many operations (max 100)".to_string()))?;

    let tx = Transaction {
        source_account: source_muxed,
        fee: fee_per_op * op_count,
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

    envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| MultiSigError::XdrBuild(e.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Mint XDR
// ─────────────────────────────────────────────────────────────────────────────

/// Build an unsigned Payment (mint) transaction XDR.
///
/// On Stellar, minting cNGN is a `Payment` from the issuing account to the
/// destination. The issuing account must have AUTH_REQUIRED set and the
/// destination must have an authorised trustline.
///
/// # Parameters
/// - `issuer_address`      — cNGN issuing account (source of the payment)
/// - `destination_address` — recipient wallet
/// - `amount_stroops`      — amount in stroops (1 cNGN = 10_000_000 stroops)
/// - `sequence`            — current sequence number of the issuing account
pub fn build_mint_xdr(
    issuer_address: &str,
    destination_address: &str,
    amount_stroops: i64,
    sequence: i64,
) -> Result<String, MultiSigError> {
    let dest_pk = parse_public_key(destination_address)?;
    let dest_muxed = MuxedAccount::Ed25519(dest_pk);
    let asset = build_cngn_asset(issuer_address)?;

    let payment_op = PaymentOp {
        destination: dest_muxed,
        asset,
        amount: amount_stroops,
    };

    let operations = vec![Operation {
        source_account: None,
        body: OperationBody::Payment(payment_op),
    }];

    wrap_in_envelope(issuer_address, sequence, operations, BASE_FEE)
}

// ─────────────────────────────────────────────────────────────────────────────
// Burn XDR
// ─────────────────────────────────────────────────────────────────────────────

/// Build an unsigned Payment (burn) transaction XDR.
///
/// Burning cNGN is a `Payment` back to the issuing account, which destroys
/// the tokens (Stellar reduces total supply when tokens return to the issuer).
///
/// # Parameters
/// - `source_address`  — account holding the cNGN to burn
/// - `issuer_address`  — cNGN issuing account (destination of the burn)
/// - `amount_stroops`  — amount in stroops
/// - `sequence`        — current sequence number of the source account
pub fn build_burn_xdr(
    source_address: &str,
    issuer_address: &str,
    amount_stroops: i64,
    sequence: i64,
) -> Result<String, MultiSigError> {
    let issuer_pk = parse_public_key(issuer_address)?;
    let issuer_muxed = MuxedAccount::Ed25519(issuer_pk);
    let asset = build_cngn_asset(issuer_address)?;

    let payment_op = PaymentOp {
        destination: issuer_muxed,
        asset,
        amount: amount_stroops,
    };

    let operations = vec![Operation {
        source_account: None,
        body: OperationBody::Payment(payment_op),
    }];

    wrap_in_envelope(source_address, sequence, operations, BASE_FEE)
}

// ─────────────────────────────────────────────────────────────────────────────
// SetOptions XDR (signer management / threshold changes)
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for a SetOptions operation.
#[derive(Debug, Clone)]
pub struct SetOptionsParams {
    pub master_weight: Option<u32>,
    pub low_threshold: Option<u32>,
    pub med_threshold: Option<u32>,
    pub high_threshold: Option<u32>,
    /// Signer to add or update (public_key, weight). weight=0 removes the signer.
    pub signer: Option<(String, u32)>,
}

/// Build an unsigned SetOptions transaction XDR.
///
/// Used for:
/// - Adding a new signer (weight > 0)
/// - Removing a signer (weight = 0)
/// - Changing thresholds
pub fn build_set_options_xdr(
    issuer_address: &str,
    sequence: i64,
    params: SetOptionsParams,
) -> Result<String, MultiSigError> {
    use stellar_xdr::next::{
        SetOptionsOp, Signer as XdrSigner, SignerKey, SignerKeyEd25519,
    };

    let signer_xdr = if let Some((key, weight)) = params.signer {
        let signer_pk = parse_public_key(&key)?;
        Some(XdrSigner {
            key: SignerKey::Ed25519(SignerKeyEd25519(signer_pk)),
            weight,
        })
    } else {
        None
    };

    let set_options_op = SetOptionsOp {
        inflation_dest: None,
        clear_flags: None,
        set_flags: None,
        master_weight: params.master_weight,
        low_threshold: params.low_threshold,
        med_threshold: params.med_threshold,
        high_threshold: params.high_threshold,
        home_domain: None,
        signer: signer_xdr,
    };

    let operations = vec![Operation {
        source_account: None,
        body: OperationBody::SetOptions(set_options_op),
    }];

    wrap_in_envelope(issuer_address, sequence, operations, BASE_FEE)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use a known valid Stellar testnet address for unit tests.
    const TEST_ISSUER: &str = "GCJRI5CIWK5IU67Q6DGA7QW52JDKRO7JEAHQKFNDUJUPEZGURDBX3LDX";
    const TEST_DEST: &str = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";

    #[test]
    fn test_build_mint_xdr_produces_base64() {
        let xdr = build_mint_xdr(TEST_ISSUER, TEST_DEST, 10_000_000_000, 12345);
        assert!(xdr.is_ok(), "mint XDR build failed: {:?}", xdr.err());
        let xdr_str = xdr.unwrap();
        // Base64 XDR always starts with 'A' (TransactionEnvelope tag)
        assert!(!xdr_str.is_empty());
    }

    #[test]
    fn test_build_burn_xdr_produces_base64() {
        let xdr = build_burn_xdr(TEST_DEST, TEST_ISSUER, 5_000_000_000, 99);
        assert!(xdr.is_ok(), "burn XDR build failed: {:?}", xdr.err());
    }

    #[test]
    fn test_build_set_options_add_signer() {
        let params = SetOptionsParams {
            master_weight: None,
            low_threshold: None,
            med_threshold: Some(3),
            high_threshold: Some(3),
            signer: Some((TEST_DEST.to_string(), 1)),
        };
        let xdr = build_set_options_xdr(TEST_ISSUER, 0, params);
        assert!(xdr.is_ok(), "set_options XDR build failed: {:?}", xdr.err());
    }

    #[test]
    fn test_invalid_address_returns_error() {
        let xdr = build_mint_xdr("INVALID_ADDRESS", TEST_DEST, 1_000_000, 0);
        assert!(xdr.is_err());
    }
}
