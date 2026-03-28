//! Frequency calculations for recurring payment schedules.

use chrono::{DateTime, Datelike, Duration, Months, Utc};

/// Supported schedule frequencies.
#[derive(Debug, Clone, PartialEq)]
pub enum Frequency {
    Daily,
    Weekly,
    Monthly,
    /// Custom interval expressed in days.
    Custom(u32),
}

impl Frequency {
    /// Parse from a string + optional custom_interval_days.
    pub fn parse(s: &str, custom_days: Option<i32>) -> Result<Self, String> {
        match s {
            "daily" => Ok(Frequency::Daily),
            "weekly" => Ok(Frequency::Weekly),
            "monthly" => Ok(Frequency::Monthly),
            "custom" => match custom_days {
                Some(d) if d > 0 => Ok(Frequency::Custom(d as u32)),
                Some(_) => Err("custom_interval_days must be > 0".to_string()),
                None => Err("custom_interval_days is required for frequency 'custom'".to_string()),
            },
            other => Err(format!(
                "unsupported frequency '{}'; must be daily, weekly, monthly, or custom",
                other
            )),
        }
    }

    /// Advance `from` by one period according to this frequency.
    pub fn advance(&self, from: DateTime<Utc>) -> DateTime<Utc> {
        match self {
            Frequency::Daily => from + Duration::days(1),
            Frequency::Weekly => from + Duration::weeks(1),
            Frequency::Monthly => {
                // Use chrono Months to handle month-end correctly.
                from.checked_add_months(Months::new(1))
                    .unwrap_or_else(|| from + Duration::days(30))
            }
            Frequency::Custom(days) => from + Duration::days(*days as i64),
        }
    }
}

/// Calculate the first next_execution_at from a start timestamp.
/// If start is in the past, advance until it's in the future.
pub fn next_execution_from_now(freq: &Frequency, start: DateTime<Utc>) -> DateTime<Utc> {
    let now = Utc::now();
    let mut next = start;
    // If start is already in the future, use it directly.
    if next > now {
        return next;
    }
    // Advance until we're past now.
    while next <= now {
        next = freq.advance(next);
    }
    next
}

/// Advance a timestamp by one period (used after execution).
pub fn advance_schedule(freq: &Frequency, from: DateTime<Utc>) -> DateTime<Utc> {
    freq.advance(from)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    #[test]
    fn test_daily_advance() {
        let from = ts(2026, 1, 1);
        assert_eq!(Frequency::Daily.advance(from), ts(2026, 1, 2));
    }

    #[test]
    fn test_weekly_advance() {
        let from = ts(2026, 1, 1);
        assert_eq!(Frequency::Weekly.advance(from), ts(2026, 1, 8));
    }

    #[test]
    fn test_monthly_advance() {
        let from = ts(2026, 1, 31);
        let next = Frequency::Monthly.advance(from);
        // chrono Months: Jan 31 + 1 month = Feb 28 (2026 is not a leap year)
        assert_eq!(next.month(), 2);
    }

    #[test]
    fn test_custom_advance() {
        let from = ts(2026, 1, 1);
        assert_eq!(Frequency::Custom(14).advance(from), ts(2026, 1, 15));
    }

    #[test]
    fn test_parse_valid() {
        assert_eq!(Frequency::parse("daily", None).unwrap(), Frequency::Daily);
        assert_eq!(Frequency::parse("weekly", None).unwrap(), Frequency::Weekly);
        assert_eq!(Frequency::parse("monthly", None).unwrap(), Frequency::Monthly);
        assert_eq!(Frequency::parse("custom", Some(7)).unwrap(), Frequency::Custom(7));
    }

    #[test]
    fn test_parse_custom_missing_days() {
        assert!(Frequency::parse("custom", None).is_err());
    }

    #[test]
    fn test_parse_custom_zero_days() {
        assert!(Frequency::parse("custom", Some(0)).is_err());
    }

    #[test]
    fn test_parse_invalid() {
        assert!(Frequency::parse("hourly", None).is_err());
    }

    #[test]
    fn test_next_execution_future_start() {
        let future = Utc::now() + Duration::days(5);
        let next = next_execution_from_now(&Frequency::Daily, future);
        assert_eq!(next, future);
    }

    #[test]
    fn test_next_execution_past_start_advances() {
        let past = Utc::now() - Duration::days(3);
        let next = next_execution_from_now(&Frequency::Daily, past);
        assert!(next > Utc::now());
    }
}
