use crate::error::AppError;
use crate::pos::models::PosPaymentIntent;
use chrono::Utc;
use rust_decimal::Decimal;
use tracing::{info, instrument};

/// Payment validation utilities
pub struct PaymentValidator;

impl PaymentValidator {
    /// Validate payment amount is within acceptable range
    #[instrument]
    pub fn validate_amount(amount: Decimal) -> Result<(), AppError> {
        const MIN_AMOUNT: Decimal = Decimal::from_parts_raw(100, 0, 0, false, 2); // 1.00 cNGN
        const MAX_AMOUNT: Decimal = Decimal::from_parts_raw(1000000000, 0, 0, false, 2); // 10,000,000.00 cNGN

        if amount < MIN_AMOUNT {
            return Err(AppError::BadRequest(format!(
                "Amount too small (minimum: {} cNGN)",
                MIN_AMOUNT
            )));
        }

        if amount > MAX_AMOUNT {
            return Err(AppError::BadRequest(format!(
                "Amount too large (maximum: {} cNGN)",
                MAX_AMOUNT
            )));
        }

        Ok(())
    }

    /// Validate order ID format
    #[instrument]
    pub fn validate_order_id(order_id: &str) -> Result<(), AppError> {
        if order_id.is_empty() {
            return Err(AppError::BadRequest("Order ID cannot be empty".to_string()));
        }

        if order_id.len() > 100 {
            return Err(AppError::BadRequest(
                "Order ID too long (maximum 100 characters)".to_string(),
            ));
        }

        // Check for valid characters (alphanumeric, dash, underscore)
        if !order_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(AppError::BadRequest(
                "Order ID contains invalid characters (only alphanumeric, dash, underscore allowed)".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if payment has expired
    #[instrument(skip(payment))]
    pub fn is_expired(payment: &PosPaymentIntent) -> bool {
        payment.expires_at < Utc::now()
    }

    /// Validate Stellar address format
    #[instrument]
    pub fn validate_stellar_address(address: &str) -> Result<(), AppError> {
        // Stellar addresses are 56 characters starting with 'G'
        if address.len() != 56 {
            return Err(AppError::BadRequest(
                "Invalid Stellar address length (must be 56 characters)".to_string(),
            ));
        }

        if !address.starts_with('G') {
            return Err(AppError::BadRequest(
                "Invalid Stellar address (must start with 'G')".to_string(),
            ));
        }

        // Check for valid base32 characters
        if !address.chars().all(|c| {
            c.is_ascii_uppercase() || c.is_ascii_digit()
        }) {
            return Err(AppError::BadRequest(
                "Invalid Stellar address format (must be uppercase alphanumeric)".to_string(),
            ));
        }

        Ok(())
    }

    /// Calculate amount discrepancy
    #[instrument]
    pub fn calculate_discrepancy(
        expected: Decimal,
        received: Decimal,
    ) -> (Decimal, crate::pos::models::DiscrepancyType) {
        let difference = received - expected;
        let discrepancy_type = if difference > Decimal::ZERO {
            crate::pos::models::DiscrepancyType::Overpayment
        } else {
            crate::pos::models::DiscrepancyType::Underpayment
        };

        (difference.abs(), discrepancy_type)
    }

    /// Check if amount discrepancy is within tolerance
    #[instrument]
    pub fn is_within_tolerance(expected: Decimal, received: Decimal) -> bool {
        const TOLERANCE: Decimal = Decimal::from_parts_raw(1, 0, 0, false, 2); // 0.01 cNGN
        (received - expected).abs() <= TOLERANCE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_validate_amount() {
        // Valid amounts
        assert!(PaymentValidator::validate_amount(Decimal::from_str("100.00").unwrap()).is_ok());
        assert!(PaymentValidator::validate_amount(Decimal::from_str("1000.50").unwrap()).is_ok());

        // Too small
        assert!(PaymentValidator::validate_amount(Decimal::from_str("0.50").unwrap()).is_err());

        // Too large
        assert!(PaymentValidator::validate_amount(Decimal::from_str("100000000.00").unwrap()).is_err());
    }

    #[test]
    fn test_validate_order_id() {
        // Valid order IDs
        assert!(PaymentValidator::validate_order_id("ORDER-12345").is_ok());
        assert!(PaymentValidator::validate_order_id("order_abc_123").is_ok());

        // Invalid order IDs
        assert!(PaymentValidator::validate_order_id("").is_err());
        assert!(PaymentValidator::validate_order_id("order with spaces").is_err());
        assert!(PaymentValidator::validate_order_id(&"x".repeat(101)).is_err());
    }

    #[test]
    fn test_validate_stellar_address() {
        // Valid address format (mock)
        let valid_address = "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        assert!(PaymentValidator::validate_stellar_address(valid_address).is_ok());

        // Invalid addresses
        assert!(PaymentValidator::validate_stellar_address("GSHORT").is_err());
        assert!(PaymentValidator::validate_stellar_address("AXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").is_err());
        assert!(PaymentValidator::validate_stellar_address("gxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").is_err());
    }

    #[test]
    fn test_calculate_discrepancy() {
        let expected = Decimal::from_str("100.00").unwrap();
        
        // Overpayment
        let received = Decimal::from_str("105.00").unwrap();
        let (diff, disc_type) = PaymentValidator::calculate_discrepancy(expected, received);
        assert_eq!(diff, Decimal::from_str("5.00").unwrap());
        assert_eq!(disc_type, crate::pos::models::DiscrepancyType::Overpayment);

        // Underpayment
        let received = Decimal::from_str("95.00").unwrap();
        let (diff, disc_type) = PaymentValidator::calculate_discrepancy(expected, received);
        assert_eq!(diff, Decimal::from_str("5.00").unwrap());
        assert_eq!(disc_type, crate::pos::models::DiscrepancyType::Underpayment);
    }

    #[test]
    fn test_is_within_tolerance() {
        let expected = Decimal::from_str("100.00").unwrap();
        
        // Within tolerance
        assert!(PaymentValidator::is_within_tolerance(
            expected,
            Decimal::from_str("100.00").unwrap()
        ));
        assert!(PaymentValidator::is_within_tolerance(
            expected,
            Decimal::from_str("100.01").unwrap()
        ));

        // Outside tolerance
        assert!(!PaymentValidator::is_within_tolerance(
            expected,
            Decimal::from_str("100.02").unwrap()
        ));
        assert!(!PaymentValidator::is_within_tolerance(
            expected,
            Decimal::from_str("99.98").unwrap()
        ));
    }
}
