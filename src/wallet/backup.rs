use crate::wallet::recovery::generate_mnemonic_challenge;
use anyhow::Result;

/// Generate a mnemonic verification challenge for the given word count.
/// Returns the indices the user must re-enter.
pub fn create_backup_challenge(word_count: usize) -> Vec<usize> {
    generate_mnemonic_challenge(word_count, 4)
}

/// Verify that the user's answers match the expected words at the challenged indices.
pub fn verify_backup_challenge(
    mnemonic_words: &[&str],
    challenged_indices: &[usize],
    user_answers: &[&str],
) -> bool {
    if challenged_indices.len() != user_answers.len() {
        return false;
    }
    challenged_indices
        .iter()
        .zip(user_answers.iter())
        .all(|(&idx, &answer)| {
            mnemonic_words.get(idx).map(|w| *w == answer).unwrap_or(false)
        })
}

/// Compute backup health status for a wallet.
pub fn backup_health(confirmed: bool, confirmed_days_ago: Option<i64>, warning_threshold_days: i64) -> &'static str {
    if !confirmed {
        return "red";
    }
    match confirmed_days_ago {
        Some(days) if days > warning_threshold_days => "amber",
        _ => "green",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_backup_challenge_correct() {
        let words = vec!["apple", "banana", "cherry", "date", "elderberry"];
        let indices = vec![0, 2, 4];
        let answers = vec!["apple", "cherry", "elderberry"];
        assert!(verify_backup_challenge(&words, &indices, &answers));
    }

    #[test]
    fn test_verify_backup_challenge_wrong() {
        let words = vec!["apple", "banana", "cherry"];
        let indices = vec![0, 1];
        let answers = vec!["apple", "wrong"];
        assert!(!verify_backup_challenge(&words, &indices, &answers));
    }

    #[test]
    fn test_backup_health() {
        assert_eq!(backup_health(false, None, 30), "red");
        assert_eq!(backup_health(true, Some(5), 30), "green");
        assert_eq!(backup_health(true, Some(45), 30), "amber");
    }
}
