// ---------------------------------------------------------------------------
// Parsed memo
// ---------------------------------------------------------------------------

/// The result of parsing a Stellar transaction memo for the Mint_Burn_Worker.
///
/// Expected memo formats:
/// - `mint_id:<uuid>`       → `MintId(uuid)`
/// - `redemption_id:<uuid>` → `RedemptionId(uuid)`
/// - `None` or empty string → `Missing`
/// - anything else          → `Unparseable(raw)`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedMemo {
    MintId(String),
    RedemptionId(String),
    Unparseable(String),
    Missing,
}

// ---------------------------------------------------------------------------
// parse_memo
// ---------------------------------------------------------------------------

/// Parse an optional memo string into a [`ParsedMemo`].
///
/// - Returns [`ParsedMemo::Missing`] when `memo` is `None` or empty.
/// - Returns [`ParsedMemo::MintId`] when the memo starts with `"mint_id:"`.
/// - Returns [`ParsedMemo::RedemptionId`] when the memo starts with `"redemption_id:"`.
/// - Returns [`ParsedMemo::Unparseable`] for any other non-empty value.
pub fn parse_memo(memo: Option<&str>) -> ParsedMemo {
    match memo {
        None => ParsedMemo::Missing,
        Some(s) if s.is_empty() => ParsedMemo::Missing,
        Some(s) => {
            if let Some(id) = s.strip_prefix("mint_id:") {
                if uuid::Uuid::parse_str(id).is_ok() {
                    ParsedMemo::MintId(id.to_owned())
                } else {
                    ParsedMemo::Unparseable(s.to_owned())
                }
            } else if let Some(id) = s.strip_prefix("redemption_id:") {
                if uuid::Uuid::parse_str(id).is_ok() {
                    ParsedMemo::RedemptionId(id.to_owned())
                } else {
                    ParsedMemo::Unparseable(s.to_owned())
                }
            } else {
                ParsedMemo::Unparseable(s.to_owned())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// format_memo
// ---------------------------------------------------------------------------

/// Format a [`ParsedMemo`] back into a memo string, enabling round-trip testing.
///
/// - `MintId(id)`       → `Some("mint_id:<id>")`
/// - `RedemptionId(id)` → `Some("redemption_id:<id>")`
/// - `Missing`          → `None`
/// - `Unparseable(_)`   → `None`
pub fn format_memo(parsed: &ParsedMemo) -> Option<String> {
    match parsed {
        ParsedMemo::MintId(id) => Some(format!("mint_id:{}", id)),
        ParsedMemo::RedemptionId(id) => Some(format!("redemption_id:{}", id)),
        ParsedMemo::Missing | ParsedMemo::Unparseable(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- unit tests (task 4.2) ---

    #[test]
    fn valid_mint_id_memo_returns_mint_id_variant() {
        let memo = "mint_id:550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            parse_memo(Some(memo)),
            ParsedMemo::MintId("550e8400-e29b-41d4-a716-446655440000".to_owned())
        );
    }

    #[test]
    fn valid_redemption_id_memo_returns_redemption_id_variant() {
        let memo = "redemption_id:7c9e6679-7425-40de-944b-e07fc1f90ae7";
        assert_eq!(
            parse_memo(Some(memo)),
            ParsedMemo::RedemptionId("7c9e6679-7425-40de-944b-e07fc1f90ae7".to_owned())
        );
    }

    #[test]
    fn none_memo_returns_missing() {
        assert_eq!(parse_memo(None), ParsedMemo::Missing);
    }

    #[test]
    fn empty_string_memo_returns_missing() {
        assert_eq!(parse_memo(Some("")), ParsedMemo::Missing);
    }

    #[test]
    fn malformed_memo_returns_unparseable() {
        let memo = "some-random-garbage";
        assert_eq!(
            parse_memo(Some(memo)),
            ParsedMemo::Unparseable("some-random-garbage".to_owned())
        );
    }

    #[test]
    fn format_memo_mint_id_produces_correct_string() {
        let parsed = ParsedMemo::MintId("abc-123".to_owned());
        assert_eq!(format_memo(&parsed), Some("mint_id:abc-123".to_owned()));
    }

    #[test]
    fn format_memo_redemption_id_produces_correct_string() {
        let parsed = ParsedMemo::RedemptionId("def-456".to_owned());
        assert_eq!(
            format_memo(&parsed),
            Some("redemption_id:def-456".to_owned())
        );
    }

    #[test]
    fn format_memo_missing_returns_none() {
        assert_eq!(format_memo(&ParsedMemo::Missing), None);
    }

    #[test]
    fn format_memo_unparseable_returns_none() {
        assert_eq!(
            format_memo(&ParsedMemo::Unparseable("garbage".to_owned())),
            None
        );
    }

    // --- round-trip sanity checks ---

    #[test]
    fn round_trip_mint_id() {
        let original = "mint_id:550e8400-e29b-41d4-a716-446655440000";
        let parsed = parse_memo(Some(original));
        let formatted = format_memo(&parsed).unwrap();
        assert_eq!(parse_memo(Some(&formatted)), parsed);
    }

    #[test]
    fn round_trip_redemption_id() {
        let original = "redemption_id:7c9e6679-7425-40de-944b-e07fc1f90ae7";
        let parsed = parse_memo(Some(original));
        let formatted = format_memo(&parsed).unwrap();
        assert_eq!(parse_memo(Some(&formatted)), parsed);
    }
}
