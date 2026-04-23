use anyhow::Result;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::Rng;
use std::str::FromStr;
use stellar_strkey::Strkey;

/// Verify an Ed25519 signature over a message using a Stellar public key (G... address).
pub fn verify_stellar_signature(pubkey_str: &str, message: &[u8], sig_hex: &str) -> Result<bool> {
    let strkey = Strkey::from_str(pubkey_str)
        .map_err(|e| anyhow::anyhow!("Invalid Stellar public key: {}", e))?;
    let raw = match strkey {
        Strkey::PublicKeyEd25519(k) => k.0,
        _ => return Err(anyhow::anyhow!("Not an Ed25519 public key")),
    };
    let vk = VerifyingKey::from_bytes(&raw)
        .map_err(|e| anyhow::anyhow!("Invalid key bytes: {}", e))?;
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|_| anyhow::anyhow!("Invalid signature hex"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid signature: {}", e))?;
    Ok(vk.verify(message, &sig).is_ok())
}

/// Validate Stellar public key format (56-char G... address).
pub fn is_valid_stellar_pubkey(key: &str) -> bool {
    if key.len() != 56 || !key.starts_with('G') {
        return false;
    }
    Strkey::from_str(key)
        .map(|s| matches!(s, Strkey::PublicKeyEd25519(_)))
        .unwrap_or(false)
}

/// Generate a cryptographically random challenge string.
pub fn generate_challenge() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Generate a mnemonic verification challenge: pick `count` random word indices from a 24-word phrase.
pub fn generate_mnemonic_challenge(word_count: usize, challenge_count: usize) -> Vec<usize> {
    let mut rng = rand::thread_rng();
    let mut indices: Vec<usize> = (0..word_count).collect();
    // Fisher-Yates partial shuffle
    for i in 0..challenge_count.min(word_count) {
        let j = rng.gen_range(i..word_count);
        indices.swap(i, j);
    }
    indices[..challenge_count.min(word_count)].to_vec()
}

/// Shamir's Secret Sharing — split a secret into `n` shares requiring `k` to reconstruct.
/// Uses GF(256) arithmetic for simplicity.
pub fn shamir_split(secret: &[u8], n: u8, k: u8) -> Vec<Vec<u8>> {
    assert!(k <= n && k >= 2);
    let mut rng = rand::thread_rng();
    let mut shares: Vec<Vec<u8>> = (1..=n).map(|i| vec![i]).collect();

    for &byte in secret {
        // Generate k-1 random coefficients
        let coeffs: Vec<u8> = (0..k - 1).map(|_| rng.gen::<u8>()).collect();
        for share in shares.iter_mut() {
            let x = share[0];
            let mut y = byte;
            let mut xpow = x;
            for &c in &coeffs {
                y ^= gf256_mul(c, xpow);
                xpow = gf256_mul(xpow, x);
            }
            share.push(y);
        }
    }
    shares
}

/// Reconstruct secret from k shares using Lagrange interpolation over GF(256).
pub fn shamir_reconstruct(shares: &[Vec<u8>]) -> Vec<u8> {
    let secret_len = shares[0].len() - 1;
    let mut secret = vec![0u8; secret_len];
    for i in 0..secret_len {
        let points: Vec<(u8, u8)> = shares.iter().map(|s| (s[0], s[i + 1])).collect();
        secret[i] = lagrange_interpolate_at_zero(&points);
    }
    secret
}

fn lagrange_interpolate_at_zero(points: &[(u8, u8)]) -> u8 {
    let mut result = 0u8;
    for (j, &(xj, yj)) in points.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (m, &(xm, _)) in points.iter().enumerate() {
            if m != j {
                num = gf256_mul(num, xm);
                den = gf256_mul(den, gf256_add(xj, xm));
            }
        }
        result ^= gf256_mul(yj, gf256_mul(num, gf256_inv(den)));
    }
    result
}

fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    let mut carry;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b; // GF(2^8) irreducible polynomial x^8+x^4+x^3+x+1
        }
        b >>= 1;
    }
    result
}

fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    gf256_mul(result, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_roundtrip() {
        let secret = b"test-recovery-token-32bytes-here";
        let shares = shamir_split(secret, 3, 2);
        assert_eq!(shares.len(), 3);
        // Reconstruct with any 2 shares
        let reconstructed = shamir_reconstruct(&shares[..2]);
        assert_eq!(reconstructed, secret);
        let reconstructed2 = shamir_reconstruct(&[shares[0].clone(), shares[2].clone()]);
        assert_eq!(reconstructed2, secret);
    }

    #[test]
    fn test_mnemonic_challenge_generation() {
        let indices = generate_mnemonic_challenge(24, 4);
        assert_eq!(indices.len(), 4);
        // All indices in range
        for &i in &indices {
            assert!(i < 24);
        }
        // No duplicates
        let mut sorted = indices.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
    }

    #[test]
    fn test_valid_stellar_pubkey() {
        // Valid format check (length and prefix)
        assert!(!is_valid_stellar_pubkey("INVALID"));
        assert!(!is_valid_stellar_pubkey(""));
    }

    #[test]
    fn test_challenge_generation() {
        let c1 = generate_challenge();
        let c2 = generate_challenge();
        assert_eq!(c1.len(), 64); // 32 bytes hex
        assert_ne!(c1, c2);
    }
}
