use crate::error::AppError;
use crate::pos::models::PosPaymentIntent;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{info, instrument};

/// SEP-7 compliant payment URI for Stellar
/// Format: web+stellar:pay?destination=<address>&amount=<amount>&asset_code=<code>&asset_issuer=<issuer>&memo=<memo>&memo_type=<type>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sep7PaymentUri {
    pub destination: String,
    pub amount: String,
    pub asset_code: String,
    pub asset_issuer: String,
    pub memo: String,
    pub memo_type: String,
}

impl Sep7PaymentUri {
    /// Encode to SEP-7 URI string
    pub fn to_uri(&self) -> String {
        format!(
            "web+stellar:pay?destination={}&amount={}&asset_code={}&asset_issuer={}&memo={}&memo_type={}",
            urlencoding::encode(&self.destination),
            urlencoding::encode(&self.amount),
            urlencoding::encode(&self.asset_code),
            urlencoding::encode(&self.asset_issuer),
            urlencoding::encode(&self.memo),
            urlencoding::encode(&self.memo_type)
        )
    }

    /// Parse from SEP-7 URI string
    pub fn from_uri(uri: &str) -> Result<Self, AppError> {
        let uri = uri.strip_prefix("web+stellar:pay?")
            .ok_or_else(|| AppError::BadRequest("Invalid SEP-7 URI format".to_string()))?;

        let params: std::collections::HashMap<String, String> = uri
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                Some((
                    parts.next()?.to_string(),
                    urlencoding::decode(parts.next()?).ok()?.to_string(),
                ))
            })
            .collect();

        Ok(Self {
            destination: params.get("destination")
                .ok_or_else(|| AppError::BadRequest("Missing destination".to_string()))?
                .clone(),
            amount: params.get("amount")
                .ok_or_else(|| AppError::BadRequest("Missing amount".to_string()))?
                .clone(),
            asset_code: params.get("asset_code")
                .ok_or_else(|| AppError::BadRequest("Missing asset_code".to_string()))?
                .clone(),
            asset_issuer: params.get("asset_issuer")
                .ok_or_else(|| AppError::BadRequest("Missing asset_issuer".to_string()))?
                .clone(),
            memo: params.get("memo")
                .ok_or_else(|| AppError::BadRequest("Missing memo".to_string()))?
                .clone(),
            memo_type: params.get("memo_type")
                .ok_or_else(|| AppError::BadRequest("Missing memo_type".to_string()))?
                .clone(),
        })
    }
}

/// QR code generator for POS payments
pub struct QrGenerator {
    cngn_issuer: String,
}

impl QrGenerator {
    pub fn new(cngn_issuer: String) -> Self {
        Self { cngn_issuer }
    }

    /// Generate SEP-7 compliant QR code data for a payment intent
    /// Target: <300ms generation time
    #[instrument(skip(self), fields(order_id = %payment_intent.order_id))]
    pub fn generate_dynamic_qr(
        &self,
        payment_intent: &PosPaymentIntent,
    ) -> Result<String, AppError> {
        let start = Instant::now();

        let sep7_uri = Sep7PaymentUri {
            destination: payment_intent.destination_address.clone(),
            amount: payment_intent.amount_cngn.to_string(),
            asset_code: "cNGN".to_string(),
            asset_issuer: self.cngn_issuer.clone(),
            memo: payment_intent.memo.clone(),
            memo_type: "text".to_string(),
        };

        let uri_string = sep7_uri.to_uri();
        
        // Generate QR code as SVG (lightweight, scalable)
        let qr_code = qrcode::QrCode::new(uri_string.as_bytes())
            .map_err(|e| AppError::InternalError(format!("QR generation failed: {}", e)))?;

        let svg = qr_code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(200, 200)
            .max_dimensions(400, 400)
            .build();

        let elapsed = start.elapsed();
        info!(
            elapsed_ms = elapsed.as_millis(),
            order_id = %payment_intent.order_id,
            "QR code generated"
        );

        // Ensure we meet the <300ms SLA
        if elapsed.as_millis() > 300 {
            tracing::warn!(
                elapsed_ms = elapsed.as_millis(),
                "QR generation exceeded 300ms target"
            );
        }

        Ok(svg)
    }

    /// Generate static QR code for variable amount checkout
    /// Used by small vendors who want a single QR code
    #[instrument(skip(self))]
    pub fn generate_static_qr(
        &self,
        merchant_address: &str,
        checkout_url: &str,
    ) -> Result<String, AppError> {
        let start = Instant::now();

        // Static QR encodes a deep link to the checkout page
        // Format: https://pay.aframp.com/pos/{merchant_id}
        let qr_code = qrcode::QrCode::new(checkout_url.as_bytes())
            .map_err(|e| AppError::InternalError(format!("QR generation failed: {}", e)))?;

        let svg = qr_code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(200, 200)
            .max_dimensions(400, 400)
            .build();

        let elapsed = start.elapsed();
        info!(
            elapsed_ms = elapsed.as_millis(),
            merchant_address = %merchant_address,
            "Static QR code generated"
        );

        Ok(svg)
    }

    /// Generate QR code as PNG data URL (for legacy systems)
    #[instrument(skip(self))]
    pub fn generate_qr_png_data_url(
        &self,
        payment_intent: &PosPaymentIntent,
    ) -> Result<String, AppError> {
        let sep7_uri = Sep7PaymentUri {
            destination: payment_intent.destination_address.clone(),
            amount: payment_intent.amount_cngn.to_string(),
            asset_code: "cNGN".to_string(),
            asset_issuer: self.cngn_issuer.clone(),
            memo: payment_intent.memo.clone(),
            memo_type: "text".to_string(),
        };

        let uri_string = sep7_uri.to_uri();
        
        let qr_code = qrcode::QrCode::new(uri_string.as_bytes())
            .map_err(|e| AppError::InternalError(format!("QR generation failed: {}", e)))?;

        let image = qr_code.render::<image::Luma<u8>>()
            .min_dimensions(200, 200)
            .max_dimensions(400, 400)
            .build();

        let mut png_data = Vec::new();
        image.write_to(&mut std::io::Cursor::new(&mut png_data), image::ImageFormat::Png)
            .map_err(|e| AppError::InternalError(format!("PNG encoding failed: {}", e)))?;

        let base64_data = BASE64.encode(&png_data);
        Ok(format!("data:image/png;base64,{}", base64_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rust_decimal::Decimal;
    use std::str::FromStr;
    use uuid::Uuid;

    fn create_test_payment_intent() -> PosPaymentIntent {
        PosPaymentIntent {
            id: Uuid::new_v4(),
            merchant_id: Uuid::new_v4(),
            order_id: "ORDER-12345".to_string(),
            amount_cngn: Decimal::from_str("1000.00").unwrap(),
            destination_address: "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            memo: "ORDER-12345".to_string(),
            qr_code_data: String::new(),
            status: crate::pos::models::PosPaymentStatus::Pending,
            stellar_tx_hash: None,
            actual_amount_received: None,
            customer_address: None,
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            confirmed_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_sep7_uri_encoding() {
        let uri = Sep7PaymentUri {
            destination: "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            amount: "100.50".to_string(),
            asset_code: "cNGN".to_string(),
            asset_issuer: "GISSUER".to_string(),
            memo: "TEST-ORDER".to_string(),
            memo_type: "text".to_string(),
        };

        let encoded = uri.to_uri();
        assert!(encoded.starts_with("web+stellar:pay?"));
        assert!(encoded.contains("destination="));
        assert!(encoded.contains("amount=100.50"));
        assert!(encoded.contains("asset_code=cNGN"));
    }

    #[test]
    fn test_sep7_uri_decoding() {
        let uri_str = "web+stellar:pay?destination=GTEST&amount=100&asset_code=cNGN&asset_issuer=GISSUER&memo=ORDER123&memo_type=text";
        let parsed = Sep7PaymentUri::from_uri(uri_str).unwrap();
        
        assert_eq!(parsed.destination, "GTEST");
        assert_eq!(parsed.amount, "100");
        assert_eq!(parsed.asset_code, "cNGN");
        assert_eq!(parsed.memo, "ORDER123");
    }

    #[test]
    fn test_qr_generation_performance() {
        let generator = QrGenerator::new("GISSUER".to_string());
        let payment_intent = create_test_payment_intent();

        let start = Instant::now();
        let result = generator.generate_dynamic_qr(&payment_intent);
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(elapsed.as_millis() < 300, "QR generation took {}ms, expected <300ms", elapsed.as_millis());
    }

    #[test]
    fn test_static_qr_generation() {
        let generator = QrGenerator::new("GISSUER".to_string());
        let result = generator.generate_static_qr(
            "GMERCHANT",
            "https://pay.aframp.com/pos/merchant-123"
        );

        assert!(result.is_ok());
        let svg = result.unwrap();
        assert!(svg.contains("<svg"));
    }
}
