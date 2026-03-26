//! Type-safe cache key builders

use std::fmt;

pub const VERSION: &str = "v1";

pub mod wallet {
    use super::*;

    pub const NAMESPACE: &str = "wallet";

    #[derive(Debug, Clone)]
    pub struct BalanceKey {
        pub address: String,
    }

    impl BalanceKey {
        pub fn new(address: impl Into<String>) -> Self {
            Self {
                address: address.into(),
            }
        }
    }

    impl fmt::Display for BalanceKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:balance:{}", VERSION, NAMESPACE, self.address)
        }
    }

    #[derive(Debug, Clone)]
    pub struct TrustlineKey {
        pub address: String,
    }

    impl TrustlineKey {
        pub fn new(address: impl Into<String>) -> Self {
            Self {
                address: address.into(),
            }
        }
    }

    impl fmt::Display for TrustlineKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:trustline:{}", VERSION, NAMESPACE, self.address)
        }
    }

    #[derive(Debug, Clone)]
    pub struct TransactionCountKey {
        pub address: String,
    }

    impl TransactionCountKey {
        pub fn new(address: impl Into<String>) -> Self {
            Self {
                address: address.into(),
            }
        }
    }

    impl fmt::Display for TransactionCountKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:tx_count:{}", VERSION, NAMESPACE, self.address)
        }
    }
}

pub mod exchange_rate {
    use super::*;

    pub const NAMESPACE: &str = "rate";

    #[derive(Debug, Clone)]
    pub struct CurrencyPairKey {
        pub from_currency: String,
        pub to_currency: String,
    }

    impl CurrencyPairKey {
        pub fn new(from_currency: impl Into<String>, to_currency: impl Into<String>) -> Self {
            Self {
                from_currency: from_currency.into(),
                to_currency: to_currency.into(),
            }
        }

        pub fn cngn_rate(to_currency: impl Into<String>) -> Self {
            Self::new("CNGN", to_currency)
        }
    }

    impl fmt::Display for CurrencyPairKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{}:{}:{}:{}",
                VERSION, NAMESPACE, self.from_currency, self.to_currency
            )
        }
    }

    #[derive(Debug, Clone)]
    pub struct ConversionKey {
        pub amount: String,
        pub from_currency: String,
        pub to_currency: String,
    }

    impl ConversionKey {
        pub fn new(
            amount: impl Into<String>,
            from_currency: impl Into<String>,
            to_currency: impl Into<String>,
        ) -> Self {
            Self {
                amount: amount.into(),
                from_currency: from_currency.into(),
                to_currency: to_currency.into(),
            }
        }
    }

    impl fmt::Display for ConversionKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{}:{}:convert:{}:{}:{}",
                VERSION, NAMESPACE, self.amount, self.from_currency, self.to_currency
            )
        }
    }
}

pub mod transaction {
    use super::*;

    pub const NAMESPACE: &str = "transaction";

    #[derive(Debug, Clone)]
    pub struct StatusKey {
        pub tx_hash: String,
    }

    impl StatusKey {
        pub fn new(tx_hash: impl Into<String>) -> Self {
            Self {
                tx_hash: tx_hash.into(),
            }
        }
    }

    impl fmt::Display for StatusKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:status:{}", VERSION, NAMESPACE, self.tx_hash)
        }
    }

    #[derive(Debug, Clone)]
    pub struct RecentKey {
        pub address: String,
    }

    impl RecentKey {
        pub fn new(address: impl Into<String>) -> Self {
            Self {
                address: address.into(),
            }
        }
    }

    impl fmt::Display for RecentKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:recent:{}", VERSION, NAMESPACE, self.address)
        }
    }
}

pub mod auth {
    use super::*;

    pub const NAMESPACE: &str = "auth";

    #[derive(Debug, Clone)]
    pub struct SessionKey {
        pub session_id: String,
    }

    impl SessionKey {
        pub fn new(session_id: impl Into<String>) -> Self {
            Self {
                session_id: session_id.into(),
            }
        }
    }

    impl fmt::Display for SessionKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:session:{}", VERSION, NAMESPACE, self.session_id)
        }
    }

    #[derive(Debug, Clone)]
    pub struct JwtKey {
        pub token_hash: String,
    }

    impl JwtKey {
        pub fn new(token_hash: impl Into<String>) -> Self {
            Self {
                token_hash: token_hash.into(),
            }
        }
    }

    impl fmt::Display for JwtKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:jwt:{}", VERSION, NAMESPACE, self.token_hash)
        }
    }

    #[derive(Debug, Clone)]
    pub struct RateLimitKey {
        pub identifier: String,
        pub action: String,
    }

    impl RateLimitKey {
        pub fn new(identifier: impl Into<String>, action: impl Into<String>) -> Self {
            Self {
                identifier: identifier.into(),
                action: action.into(),
            }
        }
    }

    impl fmt::Display for RateLimitKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{}:{}:rate_limit:{}:{}",
                VERSION, NAMESPACE, self.identifier, self.action
            )
        }
    }
}

pub mod bill_payment {
    use super::*;

    pub const NAMESPACE: &str = "bill";

    #[derive(Debug, Clone)]
    pub struct ProviderKey {
        pub provider_id: String,
    }

    impl ProviderKey {
        pub fn new(provider_id: impl Into<String>) -> Self {
            Self {
                provider_id: provider_id.into(),
            }
        }
    }

    impl fmt::Display for ProviderKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:provider:{}", VERSION, NAMESPACE, self.provider_id)
        }
    }

    #[derive(Debug, Clone)]
    pub struct AvailabilityKey {
        pub country_code: String,
    }

    impl AvailabilityKey {
        pub fn new(country_code: impl Into<String>) -> Self {
            Self {
                country_code: country_code.into(),
            }
        }
    }

    impl fmt::Display for AvailabilityKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{}:{}:available:{}",
                VERSION, NAMESPACE, self.country_code
            )
        }
    }
}

pub mod onramp {
    use super::*;

    pub const NAMESPACE: &str = "onramp";

    #[derive(Debug, Clone)]
    pub struct QuoteKey {
        pub quote_id: String,
    }

    impl QuoteKey {
        pub fn new(quote_id: impl Into<String>) -> Self {
            Self {
                quote_id: quote_id.into(),
            }
        }
    }

    impl fmt::Display for QuoteKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:quote:{}", VERSION, NAMESPACE, self.quote_id)
        }
    }

    #[derive(Debug, Clone)]
    pub struct StatusKey {
        pub tx_id: String,
    }

    impl StatusKey {
        pub fn new(tx_id: impl Into<String>) -> Self {
            Self {
                tx_id: tx_id.into(),
            }
        }
    }

    impl fmt::Display for StatusKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "api:{}:status:{}", NAMESPACE, self.tx_id)
        }
    }
}

pub mod fee {
    use super::*;

    pub const NAMESPACE: &str = "fee";

    #[derive(Debug, Clone)]
    pub struct StructureKey {
        pub fee_type: String,
    }

    impl StructureKey {
        pub fn new(fee_type: impl Into<String>) -> Self {
            Self {
                fee_type: fee_type.into(),
            }
        }
    }

    impl fmt::Display for StructureKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:structure:{}", VERSION, NAMESPACE, self.fee_type)
        }
    }

    /// API fees cache keys per spec
    pub const FEES_ALL: &str = "api:fees:all";

    pub fn fees_calculated(tx_type: &str, provider: &str, amount: &str) -> String {
        format!("api:fees:{}:{}:{}", tx_type, provider, amount)
    }

    pub fn fees_comparison(tx_type: &str, amount: &str) -> String {
        format!("api:fees:{}:all:{}", tx_type, amount)
    }
}

pub mod quote {
    use super::*;

    pub const NAMESPACE: &str = "quote";

    #[derive(Debug, Clone)]
    pub struct QuoteKey {
        pub quote_id: String,
    }

    impl QuoteKey {
        pub fn new(quote_id: impl Into<String>) -> Self {
            Self {
                quote_id: quote_id.into(),
            }
        }
    }

    impl fmt::Display for QuoteKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:{}", VERSION, NAMESPACE, self.quote_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_balance_key() {
        let key = wallet::BalanceKey::new("GA123456789");
        assert_eq!(key.to_string(), "v1:wallet:balance:GA123456789");
    }

    #[test]
    fn test_exchange_rate_key() {
        let key = exchange_rate::CurrencyPairKey::cngn_rate("USD");
        assert_eq!(key.to_string(), "v1:rate:CNGN:USD");
    }

    #[test]
    fn test_conversion_key() {
        let key = exchange_rate::ConversionKey::new("100.50", "CNGN", "USD");
        assert_eq!(key.to_string(), "v1:rate:convert:100.50:CNGN:USD");
    }

    #[test]
    fn test_session_key() {
        let key = auth::SessionKey::new("session_123");
        assert_eq!(key.to_string(), "v1:auth:session:session_123");
    }

    #[test]
    fn test_rate_limit_key() {
        let key = auth::RateLimitKey::new("user_123", "login");
        assert_eq!(key.to_string(), "v1:auth:rate_limit:user_123:login");
    }
}

pub mod signing {
    use super::*;

    pub const NAMESPACE: &str = "sigkey";

    /// Cached derived signing key: `v1:sigkey:<key_id>`
    ///
    /// Stored in Redis with a short TTL to avoid re-deriving HKDF on every request.
    #[derive(Debug, Clone)]
    pub struct DerivedKeyCache {
        pub key_id: String,
    }

    impl DerivedKeyCache {
        pub fn new(key_id: impl Into<String>) -> Self {
            Self { key_id: key_id.into() }
        }
    }

    impl fmt::Display for DerivedKeyCache {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}:{}", VERSION, NAMESPACE, self.key_id)
        }
    }
}

pub mod replay {
    use super::*;

    pub const NAMESPACE: &str = "nonce";

    /// Namespaced nonce key: `v1:nonce:<consumer_id>:<nonce>`
    ///
    /// Stored in Redis with TTL = timestamp_window + safety_buffer.
    /// Presence of this key means the nonce has already been consumed.
    #[derive(Debug, Clone)]
    pub struct NonceKey {
        pub consumer_id: String,
        pub nonce: String,
    }

    impl NonceKey {
        pub fn new(consumer_id: impl Into<String>, nonce: impl Into<String>) -> Self {
            Self {
                consumer_id: consumer_id.into(),
                nonce: nonce.into(),
            }
        }
    }

    impl fmt::Display for NonceKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{}:{}:{}:{}",
                VERSION, NAMESPACE, self.consumer_id, self.nonce
            )
        }
    }
}
