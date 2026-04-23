//! Weighted-median aggregator with outlier filtering.
//!
//! Algorithm:
//!   1. Collect raw prices from all healthy adapters.
//!   2. Discard any price that deviates more than `outlier_pct` from the
//!      preliminary median of the full set.
//!   3. Return the median of the remaining prices.

use super::types::RawPrice;

/// Maximum allowed deviation from the group median before a price is
/// considered an outlier and excluded (default 2 %).
const DEFAULT_OUTLIER_PCT: f64 = 2.0;

pub struct Aggregator {
    outlier_pct: f64,
}

impl Aggregator {
    pub fn new(outlier_pct: Option<f64>) -> Self {
        Self { outlier_pct: outlier_pct.unwrap_or(DEFAULT_OUTLIER_PCT) }
    }

    /// Returns `(median_price, sources_used, excluded_sources)`.
    pub fn aggregate(&self, prices: &[RawPrice]) -> Option<(f64, usize, Vec<String>)> {
        if prices.is_empty() {
            return None;
        }

        let mut values: Vec<f64> = prices.iter().map(|p| p.price).collect();
        values.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let preliminary_median = median(&values);

        let threshold = preliminary_median * self.outlier_pct / 100.0;

        let mut excluded: Vec<String> = Vec::new();
        let mut accepted: Vec<f64> = Vec::new();

        for p in prices {
            if (p.price - preliminary_median).abs() <= threshold {
                accepted.push(p.price);
            } else {
                excluded.push(p.source.clone());
            }
        }

        if accepted.is_empty() {
            // All prices were outliers — fall back to full set median
            return Some((preliminary_median, prices.len(), vec![]));
        }

        accepted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        Some((median(&accepted), accepted.len(), excluded))
    }
}

fn median(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n % 2 == 0 {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn raw(source: &str, price: f64) -> RawPrice {
        RawPrice { source: source.into(), pair: "XLM/USD".into(), price, fetched_at: Utc::now() }
    }

    #[test]
    fn test_median_odd() {
        let agg = Aggregator::new(None);
        let prices = vec![raw("a", 0.10), raw("b", 0.12), raw("c", 0.11)];
        let (p, used, excl) = agg.aggregate(&prices).unwrap();
        assert_eq!(used, 3);
        assert!(excl.is_empty());
        assert!((p - 0.11).abs() < 1e-9);
    }

    #[test]
    fn test_outlier_excluded() {
        let agg = Aggregator::new(Some(2.0));
        // 0.50 is far from the 0.10–0.12 cluster
        let prices = vec![raw("a", 0.10), raw("b", 0.11), raw("c", 0.12), raw("bad", 0.50)];
        let (_, used, excl) = agg.aggregate(&prices).unwrap();
        assert_eq!(used, 3);
        assert!(excl.contains(&"bad".to_string()));
    }
}
