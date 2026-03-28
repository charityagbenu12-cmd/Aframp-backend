//! Key escrow using Shamir's Secret Sharing (SSS).
//!
//! Splits high-sensitivity key material into N shares where any K shares
//! can reconstruct the secret. Shares are distributed to designated custodians.
//!
//! Uses a simple GF(256) polynomial implementation (no external SSS crate needed).

use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    #[error("Threshold {threshold} must be <= total shares {total}")]
    InvalidThreshold { threshold: u8, total: u8 },
    #[error("Need at least {needed} shares, got {got}")]
    InsufficientShares { needed: u8, got: usize },
    #[error("Secret must not be empty")]
    EmptySecret,
    #[error("Share data is malformed")]
    MalformedShare,
}

// ---------------------------------------------------------------------------
// Share
// ---------------------------------------------------------------------------

/// A single Shamir share: (x, y_bytes).
#[derive(Debug, Clone)]
pub struct Share {
    pub x: u8,
    pub y: Vec<u8>,
}

// ---------------------------------------------------------------------------
// GF(256) arithmetic (irreducible polynomial x^8 + x^4 + x^3 + x + 1 = 0x11b)
// ---------------------------------------------------------------------------

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

fn gf_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut result = 1u8;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

fn gf_inv(a: u8) -> u8 {
    gf_pow(a, 254) // Fermat's little theorem in GF(256)
}

fn gf_div(a: u8, b: u8) -> u8 {
    gf_mul(a, gf_inv(b))
}

// ---------------------------------------------------------------------------
// Split
// ---------------------------------------------------------------------------

/// Split `secret` into `total` shares where any `threshold` shares reconstruct it.
pub fn split(
    secret: &[u8],
    threshold: u8,
    total: u8,
) -> Result<Vec<Share>, EscrowError> {
    if secret.is_empty() {
        return Err(EscrowError::EmptySecret);
    }
    if threshold > total || threshold == 0 {
        return Err(EscrowError::InvalidThreshold { threshold, total });
    }

    let mut rng = rand::thread_rng();
    let mut shares: Vec<Share> = (1..=total).map(|x| Share { x, y: vec![0u8; secret.len()] }).collect();

    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        // Build a random polynomial of degree (threshold-1) with f(0) = secret_byte
        let mut coeffs = Zeroizing::new(vec![secret_byte]);
        for _ in 1..threshold {
            use rand::Rng;
            coeffs.push(rng.gen::<u8>());
        }

        for share in shares.iter_mut() {
            let x = share.x;
            // Evaluate polynomial at x using Horner's method
            let mut y = 0u8;
            for &c in coeffs.iter().rev() {
                y = gf_mul(y, x) ^ c;
            }
            share.y[byte_idx] = y;
        }
    }

    Ok(shares)
}

// ---------------------------------------------------------------------------
// Reconstruct
// ---------------------------------------------------------------------------

/// Reconstruct the secret from at least `threshold` shares using Lagrange interpolation.
pub fn reconstruct(shares: &[Share], threshold: u8) -> Result<Zeroizing<Vec<u8>>, EscrowError> {
    if shares.len() < threshold as usize {
        return Err(EscrowError::InsufficientShares {
            needed: threshold,
            got: shares.len(),
        });
    }
    if shares.is_empty() || shares[0].y.is_empty() {
        return Err(EscrowError::MalformedShare);
    }

    let shares = &shares[..threshold as usize];
    let secret_len = shares[0].y.len();
    let mut secret = Zeroizing::new(vec![0u8; secret_len]);

    for byte_idx in 0..secret_len {
        let mut value = 0u8;
        for (i, share_i) in shares.iter().enumerate() {
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, share_j) in shares.iter().enumerate() {
                if i != j {
                    num = gf_mul(num, share_j.x);
                    den = gf_mul(den, share_i.x ^ share_j.x);
                }
            }
            value ^= gf_mul(share_i.y[byte_idx], gf_div(num, den));
        }
        secret[byte_idx] = value;
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_reconstruct_exact_threshold() {
        let secret = b"super-secret-key-material-32byt";
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let reconstructed = reconstruct(&shares[..3], 3).unwrap();
        assert_eq!(reconstructed.as_slice(), secret);
    }

    #[test]
    fn test_split_reconstruct_all_shares() {
        let secret = b"another-secret-value";
        let shares = split(secret, 2, 3).unwrap();
        let reconstructed = reconstruct(&shares, 2).unwrap();
        assert_eq!(reconstructed.as_slice(), secret);
    }

    #[test]
    fn test_insufficient_shares_returns_error() {
        let secret = b"test-secret";
        let shares = split(secret, 3, 5).unwrap();
        let result = reconstruct(&shares[..2], 3);
        assert!(matches!(result, Err(EscrowError::InsufficientShares { .. })));
    }

    #[test]
    fn test_invalid_threshold_returns_error() {
        let result = split(b"secret", 6, 5);
        assert!(matches!(result, Err(EscrowError::InvalidThreshold { .. })));
    }

    #[test]
    fn test_single_byte_secret() {
        let secret = b"\xAB";
        let shares = split(secret, 2, 3).unwrap();
        let reconstructed = reconstruct(&shares[..2], 2).unwrap();
        assert_eq!(reconstructed.as_slice(), secret);
    }

    #[test]
    fn test_different_share_subsets_reconstruct_same_secret() {
        let secret = b"consistent-reconstruction";
        let shares = split(secret, 3, 5).unwrap();

        let r1 = reconstruct(&[shares[0].clone(), shares[1].clone(), shares[2].clone()], 3).unwrap();
        let r2 = reconstruct(&[shares[1].clone(), shares[3].clone(), shares[4].clone()], 3).unwrap();
        assert_eq!(r1.as_slice(), secret);
        assert_eq!(r2.as_slice(), secret);
    }
}
