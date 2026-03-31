use rust_decimal::Decimal;

use crate::bug_bounty::models::{BugBountyConfig, BugBountyError, Severity};

/// Returns the `(min, max)` reward range in USD for the given severity.
/// Informational always returns `(0, 0)`.
pub fn tier_range(severity: &Severity, config: &BugBountyConfig) -> (u64, u64) {
    match severity {
        Severity::Critical => (config.reward_critical_min, config.reward_critical_max),
        Severity::High => (config.reward_high_min, config.reward_high_max),
        Severity::Medium => (config.reward_medium_min, config.reward_medium_max),
        Severity::Low => (config.reward_low_min, config.reward_low_max),
        Severity::Informational => (0, 0),
    }
}

/// Validates that `amount` falls within the configured tier range for `severity`.
///
/// - If in range: returns `Ok(())`.
/// - If out of range and `escalation_justification` is provided: returns `Ok(())`.
/// - If out of range and no justification: returns `Err(BugBountyError::RewardOutOfTier)`.
pub fn validate_tier(
    amount: Decimal,
    severity: &Severity,
    config: &BugBountyConfig,
    escalation_justification: Option<&str>,
) -> Result<(), BugBountyError> {
    let (min, max) = tier_range(severity, config);
    let min_dec = Decimal::from(min);
    let max_dec = Decimal::from(max);

    if amount >= min_dec && amount <= max_dec {
        return Ok(());
    }

    // Out of range — require escalation justification
    if escalation_justification.map(|s| !s.trim().is_empty()).unwrap_or(false) {
        return Ok(());
    }

    Err(BugBountyError::RewardOutOfTier {
        severity: severity.clone(),
        amount,
        min,
        max,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> BugBountyConfig {
        BugBountyConfig::default()
    }

    // Helper: build a Decimal from a u64 (infallible for these values)
    fn dec(n: u64) -> Decimal {
        Decimal::from(n)
    }

    // -----------------------------------------------------------------------
    // tier_range
    // -----------------------------------------------------------------------

    #[test]
    fn tier_range_returns_correct_bounds() {
        let cfg = default_config();
        assert_eq!(tier_range(&Severity::Critical, &cfg), (5000, 20000));
        assert_eq!(tier_range(&Severity::High, &cfg), (1000, 5000));
        assert_eq!(tier_range(&Severity::Medium, &cfg), (250, 1000));
        assert_eq!(tier_range(&Severity::Low, &cfg), (50, 250));
        assert_eq!(tier_range(&Severity::Informational, &cfg), (0, 0));
    }

    // -----------------------------------------------------------------------
    // validate_tier — boundary acceptance (min and max are inclusive)
    // -----------------------------------------------------------------------

    #[test]
    fn amount_at_min_boundary_is_ok() {
        let cfg = default_config();
        for (severity, min, _max) in [
            (Severity::Critical, 5000u64, 20000u64),
            (Severity::High, 1000, 5000),
            (Severity::Medium, 250, 1000),
            (Severity::Low, 50, 250),
        ] {
            assert!(
                validate_tier(dec(min), &severity, &cfg, None).is_ok(),
                "expected Ok at min boundary for {severity:?}"
            );
        }
    }

    #[test]
    fn amount_at_max_boundary_is_ok() {
        let cfg = default_config();
        for (severity, _min, max) in [
            (Severity::Critical, 5000u64, 20000u64),
            (Severity::High, 1000, 5000),
            (Severity::Medium, 250, 1000),
            (Severity::Low, 50, 250),
        ] {
            assert!(
                validate_tier(dec(max), &severity, &cfg, None).is_ok(),
                "expected Ok at max boundary for {severity:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // validate_tier — out-of-range rejection without escalation
    // -----------------------------------------------------------------------

    #[test]
    fn amount_below_min_without_escalation_is_err() {
        let cfg = default_config();
        for (severity, min, _max) in [
            (Severity::Critical, 5000u64, 20000u64),
            (Severity::High, 1000, 5000),
            (Severity::Medium, 250, 1000),
            (Severity::Low, 50, 250),
        ] {
            if min == 0 {
                continue; // can't go below 0 for informational
            }
            let result = validate_tier(dec(min - 1), &severity, &cfg, None);
            assert!(
                matches!(result, Err(BugBountyError::RewardOutOfTier { .. })),
                "expected RewardOutOfTier for {severity:?} at min-1"
            );
        }
    }

    #[test]
    fn amount_above_max_without_escalation_is_err() {
        let cfg = default_config();
        for (severity, _min, max) in [
            (Severity::Critical, 5000u64, 20000u64),
            (Severity::High, 1000, 5000),
            (Severity::Medium, 250, 1000),
            (Severity::Low, 50, 250),
        ] {
            let result = validate_tier(dec(max + 1), &severity, &cfg, None);
            assert!(
                matches!(result, Err(BugBountyError::RewardOutOfTier { .. })),
                "expected RewardOutOfTier for {severity:?} at max+1"
            );
        }
    }

    // -----------------------------------------------------------------------
    // validate_tier — informational severity
    // -----------------------------------------------------------------------

    #[test]
    fn informational_amount_zero_is_ok() {
        let cfg = default_config();
        assert!(validate_tier(dec(0), &Severity::Informational, &cfg, None).is_ok());
    }

    #[test]
    fn informational_amount_nonzero_without_escalation_is_err() {
        let cfg = default_config();
        let result = validate_tier(dec(1), &Severity::Informational, &cfg, None);
        assert!(
            matches!(result, Err(BugBountyError::RewardOutOfTier { .. })),
            "expected RewardOutOfTier for informational with amount > 0"
        );
    }

    // -----------------------------------------------------------------------
    // validate_tier — escalation justification overrides out-of-range
    // -----------------------------------------------------------------------

    #[test]
    fn out_of_range_with_escalation_justification_is_ok() {
        let cfg = default_config();
        // Critical max is 20_000; submit 25_000 with a justification
        let result = validate_tier(
            dec(25_000),
            &Severity::Critical,
            &cfg,
            Some("Exceptional impact on financial transaction integrity"),
        );
        assert!(result.is_ok(), "expected Ok when escalation justification is provided");
    }

    #[test]
    fn out_of_range_with_empty_escalation_justification_is_err() {
        let cfg = default_config();
        // Empty string is not a valid justification
        let result = validate_tier(dec(25_000), &Severity::Critical, &cfg, Some(""));
        assert!(
            matches!(result, Err(BugBountyError::RewardOutOfTier { .. })),
            "expected RewardOutOfTier when escalation justification is empty string"
        );
    }

    #[test]
    fn out_of_range_with_whitespace_only_escalation_justification_is_err() {
        let cfg = default_config();
        let result = validate_tier(dec(25_000), &Severity::Critical, &cfg, Some("   "));
        assert!(
            matches!(result, Err(BugBountyError::RewardOutOfTier { .. })),
            "expected RewardOutOfTier when escalation justification is whitespace only"
        );
    }
}
