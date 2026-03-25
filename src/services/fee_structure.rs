//! Fee structure service
//! Provides active fee lookup and fee calculation helper.

use crate::database::error::DatabaseError;
use crate::database::fee_structure_repository::{FeeStructure, FeeStructureRepository};
use bigdecimal::BigDecimal;
use std::str::FromStr;

/// Fee calculation input
#[derive(Debug, Clone)]
pub struct FeeCalculationInput {
    pub fee_type: String,
    pub amount: BigDecimal,
    pub currency: Option<String>,
    pub at_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Fee calculation result
#[derive(Debug, Clone)]
pub struct FeeCalculationResult {
    pub fee: BigDecimal,
    pub rate_bps: i32,
    pub flat_fee: BigDecimal,
    pub min_fee: Option<BigDecimal>,
    pub max_fee: Option<BigDecimal>,
    pub currency: Option<String>,
    pub structure_id: uuid::Uuid,
}

/// Service for fee structures
pub struct FeeStructureService {
    repo: FeeStructureRepository,
}

impl FeeStructureService {
    pub fn new(repo: FeeStructureRepository) -> Self {
        Self { repo }
    }

    /// Get active fee structures for a fee type
    pub async fn get_active(
        &self,
        fee_type: &str,
        at_time: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<FeeStructure>, DatabaseError> {
        self.repo.get_active_by_type(fee_type, at_time).await
    }

    /// Calculate fee based on the most recent active fee structure
    pub async fn calculate_fee(
        &self,
        input: FeeCalculationInput,
    ) -> Result<Option<FeeCalculationResult>, DatabaseError> {
        let structures = self.get_active(&input.fee_type, input.at_time).await?;
        let structure = match structures.first() {
            Some(s) => s.clone(),
            None => return Ok(None),
        };

        let rate_fee = calculate_rate_fee(&input.amount, structure.fee_rate_bps);
        let mut total_fee = rate_fee + structure.fee_flat.clone();

        if let Some(min_fee) = structure.min_fee.clone() {
            if total_fee < min_fee {
                total_fee = min_fee;
            }
        }

        if let Some(max_fee) = structure.max_fee.clone() {
            if total_fee > max_fee {
                total_fee = max_fee;
            }
        }

        Ok(Some(FeeCalculationResult {
            fee: total_fee,
            rate_bps: structure.fee_rate_bps,
            flat_fee: structure.fee_flat,
            min_fee: structure.min_fee,
            max_fee: structure.max_fee,
            currency: input.currency.or(structure.currency),
            structure_id: structure.id,
        }))
    }
}

fn calculate_rate_fee(amount: &BigDecimal, fee_rate_bps: i32) -> BigDecimal {
    if fee_rate_bps == 0 {
        return BigDecimal::from(0);
    }

    let rate = BigDecimal::from(fee_rate_bps) / BigDecimal::from(10_000u32);
    amount * rate
}

/// Helper to parse string amounts into BigDecimal
pub fn parse_amount(amount: &str) -> BigDecimal {
    BigDecimal::from_str(amount).unwrap_or_else(|_| BigDecimal::from(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_rate_fee_for_standard_amount() {
        let fee = calculate_rate_fee(&BigDecimal::from_str("50000").unwrap(), 140);

        assert_eq!(fee, BigDecimal::from_str("700.00").unwrap());
    }

    #[test]
    fn test_calculate_rate_fee_for_zero_bps_returns_zero() {
        let fee = calculate_rate_fee(&BigDecimal::from_str("50000").unwrap(), 0);

        assert_eq!(fee, BigDecimal::from(0));
    }

    #[test]
    fn test_calculate_rate_fee_preserves_fractional_precision() {
        let fee = calculate_rate_fee(&BigDecimal::from_str("1000.125").unwrap(), 10);

        assert_eq!(fee, BigDecimal::from_str("1.000125").unwrap());
    }

    #[test]
    fn test_parse_amount_returns_zero_for_invalid_input() {
        assert_eq!(parse_amount("not-a-number"), BigDecimal::from(0));
    }
}
