use crate::error::AppError;
use crate::pos::models::{PosPaymentIntent, ProofOfPaymentRecord};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{info, instrument};
use uuid::Uuid;

/// Proof of Payment service for offline-to-online validation
/// Generates verifiable proof screens for customers to show cashiers
/// during temporary internet outages
pub struct ProofOfPayment {
    db: PgPool,
    verification_secret: String,
}

impl ProofOfPayment {
    pub fn new(db: PgPool, verification_secret: String) -> Self {
        Self {
            db,
            verification_secret,
        }
    }

    /// Generate proof of payment record for a confirmed transaction
    #[instrument(skip(self))]
    pub async fn generate_proof(
        &self,
        payment_id: Uuid,
    ) -> Result<ProofOfPaymentRecord, AppError> {
        // Fetch payment intent
        let payment = sqlx::query_as::<_, PosPaymentIntent>(
            r#"
            SELECT * FROM pos_payment_intents
            WHERE id = $1
            "#
        )
        .bind(payment_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Payment not found".to_string()))?;

        // Verify payment is confirmed
        if !matches!(
            payment.status,
            crate::pos::models::PosPaymentStatus::Confirmed
        ) {
            return Err(AppError::BadRequest(
                "Payment must be confirmed to generate proof".to_string()
            ));
        }

        let tx_hash = payment.stellar_tx_hash
            .ok_or_else(|| AppError::BadRequest("No transaction hash available".to_string()))?;

        // Fetch merchant name
        let merchant = sqlx::query_as::<_, crate::pos::models::PosMerchant>(
            r#"
            SELECT * FROM pos_merchants
            WHERE id = $1
            "#
        )
        .bind(payment.merchant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Merchant not found".to_string()))?;

        // Generate verification code
        let verification_code = self.generate_verification_code(
            &payment.id.to_string(),
            &tx_hash,
            &payment.amount_cngn.to_string(),
        );

        let proof = ProofOfPaymentRecord {
            payment_id: payment.id,
            order_id: payment.order_id,
            stellar_tx_hash: tx_hash,
            amount_cngn: payment.amount_cngn,
            merchant_name: merchant.business_name,
            timestamp: payment.confirmed_at.unwrap_or_else(Utc::now),
            verification_code,
        };

        info!(
            payment_id = %payment_id,
            verification_code = %proof.verification_code,
            "Proof of payment generated"
        );

        Ok(proof)
    }

    /// Verify a proof of payment code
    #[instrument(skip(self))]
    pub async fn verify_proof(
        &self,
        payment_id: Uuid,
        verification_code: &str,
    ) -> Result<bool, AppError> {
        // Fetch payment
        let payment = sqlx::query_as::<_, PosPaymentIntent>(
            r#"
            SELECT * FROM pos_payment_intents
            WHERE id = $1
            "#
        )
        .bind(payment_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Payment not found".to_string()))?;

        let tx_hash = payment.stellar_tx_hash
            .ok_or_else(|| AppError::BadRequest("No transaction hash available".to_string()))?;

        // Regenerate verification code and compare
        let expected_code = self.generate_verification_code(
            &payment.id.to_string(),
            &tx_hash,
            &payment.amount_cngn.to_string(),
        );

        let is_valid = verification_code == expected_code;

        info!(
            payment_id = %payment_id,
            is_valid = is_valid,
            "Proof of payment verified"
        );

        Ok(is_valid)
    }

    /// Generate a verification code using HMAC-SHA256
    fn generate_verification_code(
        &self,
        payment_id: &str,
        tx_hash: &str,
        amount: &str,
    ) -> String {
        let data = format!("{}:{}:{}", payment_id, tx_hash, amount);
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(self.verification_secret.as_bytes());
        let result = hasher.finalize();
        
        // Take first 8 bytes and encode as hex (16 characters)
        hex::encode(&result[..8]).to_uppercase()
    }

    /// Generate QR code for proof of payment (for customer's phone)
    #[instrument(skip(self))]
    pub fn generate_proof_qr(
        &self,
        proof: &ProofOfPaymentRecord,
    ) -> Result<String, AppError> {
        // Encode proof data as JSON
        let proof_json = serde_json::to_string(proof)
            .map_err(|e| AppError::InternalError(format!("JSON encoding failed: {}", e)))?;

        // Generate QR code
        let qr_code = qrcode::QrCode::new(proof_json.as_bytes())
            .map_err(|e| AppError::InternalError(format!("QR generation failed: {}", e)))?;

        let svg = qr_code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(200, 200)
            .max_dimensions(400, 400)
            .build();

        Ok(svg)
    }
}

/// Proof of payment display format for customer screen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfPaymentDisplay {
    pub payment_id: String,
    pub order_id: String,
    pub merchant_name: String,
    pub amount: String,
    pub currency: String,
    pub transaction_hash: String,
    pub verification_code: String,
    pub timestamp: String,
    pub qr_code_svg: String,
    pub verification_url: String,
}

impl ProofOfPaymentDisplay {
    pub fn from_record(record: ProofOfPaymentRecord, qr_code_svg: String) -> Self {
        Self {
            payment_id: record.payment_id.to_string(),
            order_id: record.order_id,
            merchant_name: record.merchant_name,
            amount: record.amount_cngn.to_string(),
            currency: "cNGN".to_string(),
            transaction_hash: record.stellar_tx_hash.clone(),
            verification_code: record.verification_code.clone(),
            timestamp: record.timestamp.to_rfc3339(),
            qr_code_svg,
            verification_url: format!(
                "https://stellar.expert/explorer/public/tx/{}",
                record.stellar_tx_hash
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_code_generation() {
        let service = ProofOfPayment {
            db: PgPool::connect_lazy("postgres://localhost/test").unwrap(),
            verification_secret: "test-secret".to_string(),
        };

        let code1 = service.generate_verification_code(
            "payment-123",
            "tx-hash-456",
            "1000.00"
        );

        let code2 = service.generate_verification_code(
            "payment-123",
            "tx-hash-456",
            "1000.00"
        );

        // Same inputs should produce same code
        assert_eq!(code1, code2);
        assert_eq!(code1.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_verification_code_uniqueness() {
        let service = ProofOfPayment {
            db: PgPool::connect_lazy("postgres://localhost/test").unwrap(),
            verification_secret: "test-secret".to_string(),
        };

        let code1 = service.generate_verification_code(
            "payment-123",
            "tx-hash-456",
            "1000.00"
        );

        let code2 = service.generate_verification_code(
            "payment-123",
            "tx-hash-456",
            "2000.00" // Different amount
        );

        // Different inputs should produce different codes
        assert_ne!(code1, code2);
    }
}
