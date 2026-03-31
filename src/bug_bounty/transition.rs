use chrono::Utc;
use serde_json::json;

use crate::bug_bounty::models::{BugBountyConfig, ProgrammePhase, ProgrammeState, TransitionResult, UnmetCriterion};

/// Runtime statistics needed to evaluate transition criteria.
#[derive(Debug, Clone)]
pub struct ProgrammeStats {
    pub researchers_participated: u32,
    pub valid_findings_processed: u32,
    pub remediation_rate_percent: f64,
}

/// Evaluates all four transition criteria and returns a `TransitionResult`.
///
/// Transition succeeds iff ALL of the following hold:
/// 1. `stats.researchers_participated >= config.min_invited_researchers_participated`
/// 2. `stats.valid_findings_processed >= config.min_valid_findings_processed`
/// 3. `stats.remediation_rate_percent >= config.min_remediation_rate_percent`
/// 4. Elapsed time since `state.launched_at >= config.stabilisation_period_days`
pub fn evaluate_criteria(
    state: &ProgrammeState,
    stats: &ProgrammeStats,
    config: &BugBountyConfig,
) -> TransitionResult {
    let mut unmet = Vec::new();

    // Criterion 1: researchers participated
    if stats.researchers_participated < config.min_invited_researchers_participated {
        unmet.push(UnmetCriterion {
            criterion: "min_invited_researchers_participated".to_string(),
            current_value: json!(stats.researchers_participated),
            required_value: json!(config.min_invited_researchers_participated),
        });
    }

    // Criterion 2: valid findings processed
    if stats.valid_findings_processed < config.min_valid_findings_processed {
        unmet.push(UnmetCriterion {
            criterion: "min_valid_findings_processed".to_string(),
            current_value: json!(stats.valid_findings_processed),
            required_value: json!(config.min_valid_findings_processed),
        });
    }

    // Criterion 3: remediation rate
    if stats.remediation_rate_percent < config.min_remediation_rate_percent {
        unmet.push(UnmetCriterion {
            criterion: "min_remediation_rate_percent".to_string(),
            current_value: json!(stats.remediation_rate_percent),
            required_value: json!(config.min_remediation_rate_percent),
        });
    }

    // Criterion 4: stabilisation period elapsed
    let elapsed_days = (Utc::now() - state.launched_at).num_days() as u64;
    if elapsed_days < config.stabilisation_period_days {
        unmet.push(UnmetCriterion {
            criterion: "stabilisation_period_days".to_string(),
            current_value: json!(elapsed_days),
            required_value: json!(config.stabilisation_period_days),
        });
    }

    TransitionResult {
        success: unmet.is_empty(),
        unmet_criteria: unmet,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use uuid::Uuid;

    fn make_state(launched_at: chrono::DateTime<Utc>) -> ProgrammeState {
        ProgrammeState {
            id: Uuid::new_v4(),
            phase: ProgrammePhase::Private,
            launched_at,
            transitioned_to_public_at: None,
            transitioned_by: None,
        }
    }

    fn make_stats(
        researchers_participated: u32,
        valid_findings_processed: u32,
        remediation_rate_percent: f64,
    ) -> ProgrammeStats {
        ProgrammeStats {
            researchers_participated,
            valid_findings_processed,
            remediation_rate_percent,
        }
    }

    fn make_config(
        min_researchers: u32,
        min_findings: u32,
        min_remediation_rate: f64,
        stabilisation_days: u64,
    ) -> BugBountyConfig {
        BugBountyConfig {
            min_invited_researchers_participated: min_researchers,
            min_valid_findings_processed: min_findings,
            min_remediation_rate_percent: min_remediation_rate,
            stabilisation_period_days: stabilisation_days,
            ..BugBountyConfig::default()
        }
    }

    // -----------------------------------------------------------------------
    // All criteria met → success
    // -----------------------------------------------------------------------

    #[test]
    fn all_criteria_met_returns_success() {
        // launched 31 days ago, stabilisation period is 30 days
        let state = make_state(Utc::now() - Duration::days(31));
        let stats = make_stats(5, 3, 80.0);
        let config = make_config(5, 3, 80.0, 30);

        let result = evaluate_criteria(&state, &stats, &config);

        assert!(result.success);
        assert!(result.unmet_criteria.is_empty());
    }

    // -----------------------------------------------------------------------
    // Individual criterion failures
    // -----------------------------------------------------------------------

    #[test]
    fn researchers_below_threshold_returns_failure_with_correct_criterion() {
        let state = make_state(Utc::now() - Duration::days(31));
        let stats = make_stats(2, 3, 80.0); // only 2 researchers, need 5
        let config = make_config(5, 3, 80.0, 30);

        let result = evaluate_criteria(&state, &stats, &config);

        assert!(!result.success);
        assert_eq!(result.unmet_criteria.len(), 1);
        assert_eq!(
            result.unmet_criteria[0].criterion,
            "min_invited_researchers_participated"
        );
        assert_eq!(result.unmet_criteria[0].current_value, json!(2u32));
        assert_eq!(result.unmet_criteria[0].required_value, json!(5u32));
    }

    #[test]
    fn valid_findings_below_threshold_returns_failure_with_correct_criterion() {
        let state = make_state(Utc::now() - Duration::days(31));
        let stats = make_stats(5, 1, 80.0); // only 1 finding, need 3
        let config = make_config(5, 3, 80.0, 30);

        let result = evaluate_criteria(&state, &stats, &config);

        assert!(!result.success);
        assert_eq!(result.unmet_criteria.len(), 1);
        assert_eq!(
            result.unmet_criteria[0].criterion,
            "min_valid_findings_processed"
        );
        assert_eq!(result.unmet_criteria[0].current_value, json!(1u32));
        assert_eq!(result.unmet_criteria[0].required_value, json!(3u32));
    }

    #[test]
    fn remediation_rate_below_threshold_returns_failure_with_correct_criterion() {
        let state = make_state(Utc::now() - Duration::days(31));
        let stats = make_stats(5, 3, 50.0); // 50% rate, need 80%
        let config = make_config(5, 3, 80.0, 30);

        let result = evaluate_criteria(&state, &stats, &config);

        assert!(!result.success);
        assert_eq!(result.unmet_criteria.len(), 1);
        assert_eq!(
            result.unmet_criteria[0].criterion,
            "min_remediation_rate_percent"
        );
        assert_eq!(result.unmet_criteria[0].current_value, json!(50.0f64));
        assert_eq!(result.unmet_criteria[0].required_value, json!(80.0f64));
    }

    #[test]
    fn stabilisation_period_not_elapsed_returns_failure_with_correct_criterion() {
        // Just launched — stabilisation period of 90 days hasn't elapsed
        let state = make_state(Utc::now());
        let stats = make_stats(5, 3, 80.0);
        let config = make_config(5, 3, 80.0, 90);

        let result = evaluate_criteria(&state, &stats, &config);

        assert!(!result.success);
        assert_eq!(result.unmet_criteria.len(), 1);
        assert_eq!(
            result.unmet_criteria[0].criterion,
            "stabilisation_period_days"
        );
        assert_eq!(result.unmet_criteria[0].required_value, json!(90u64));
    }

    // -----------------------------------------------------------------------
    // All four criteria unmet
    // -----------------------------------------------------------------------

    #[test]
    fn all_criteria_unmet_returns_failure_with_four_entries() {
        // Just launched, all stats below threshold
        let state = make_state(Utc::now());
        let stats = make_stats(0, 0, 0.0);
        let config = make_config(5, 3, 80.0, 90);

        let result = evaluate_criteria(&state, &stats, &config);

        assert!(!result.success);
        assert_eq!(result.unmet_criteria.len(), 4);

        let criteria_names: Vec<&str> = result
            .unmet_criteria
            .iter()
            .map(|c| c.criterion.as_str())
            .collect();
        assert!(criteria_names.contains(&"min_invited_researchers_participated"));
        assert!(criteria_names.contains(&"min_valid_findings_processed"));
        assert!(criteria_names.contains(&"min_remediation_rate_percent"));
        assert!(criteria_names.contains(&"stabilisation_period_days"));
    }

    // -----------------------------------------------------------------------
    // Boundary values (thresholds are inclusive)
    // -----------------------------------------------------------------------

    #[test]
    fn exactly_at_threshold_values_returns_success() {
        // launched exactly `stabilisation_period_days` days ago
        let state = make_state(Utc::now() - Duration::days(30));
        let stats = make_stats(5, 3, 80.0); // exactly at thresholds
        let config = make_config(5, 3, 80.0, 30);

        let result = evaluate_criteria(&state, &stats, &config);

        assert!(result.success);
        assert!(result.unmet_criteria.is_empty());
    }
}
