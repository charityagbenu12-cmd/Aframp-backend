# OAuth 2.0 Scope System - Quick Reference

## 🚀 Quick Start

### Initialize Scope Catalogue

```rust
use aframp_backend::auth::ScopeCatalog;

let catalog = ScopeCatalog::with_defaults();
let all_scopes = catalog.all();
```

### Resolve Scope Hierarchy

```rust
use aframp_backend::auth::ScopeHierarchy;

let hierarchy = ScopeHierarchy::new();

// Single scope
assert!(hierarchy.satisfies(&["admin:*"], "admin:transactions"));

// All scopes required
assert!(hierarchy.satisfies_all(&["wallet:*", "onramp:quote"], &["wallet:read", "onramp:quote"]));

// Any scope required
assert!(hierarchy.satisfies_any(&["wallet:read"], &["wallet:read", "offramp:quote"]));
```

### Enforce Scopes in Middleware

```rust
use aframp_backend::middleware::scope_middleware::enforce_single_scope;

// Protect endpoint
app.route(
    "/api/wallet/read",
    get(handler).layer(
        axum::middleware::from_fn(|req, next| {
            enforce_single_scope("wallet:read".to_string(), req, next)
        })
    )
);
```

## 📋 Scope Categories

| Category | Scopes | Sensitive |
|---|---|---|
| Onramp | quote, initiate, read | initiate |
| Offramp | quote, initiate, read | initiate |
| Bills | read, pay | pay |
| Wallet | read, trustline, switch | trustline, switch |
| Rates | read | - |
| Transactions | read | - |
| Webhooks | read, manage | manage |
| Batch | cngn-transfer, fiat-payout | both |
| Recurring | read, manage | manage |
| Analytics | read | - |
| Admin | transactions, consumers, config | all |
| Microservice | internal | - |

## 🌳 Scope Hierarchy

```
admin:*          → admin:transactions, admin:consumers, admin:config
wallet:*         → wallet:read, wallet:trustline, wallet:switch
onramp:*         → onramp:quote, onramp:initiate, onramp:read
offramp:*        → offramp:quote, offramp:initiate, offramp:read
bills:*          → bills:read, bills:pay
webhooks:*       → webhooks:read, webhooks:manage
batch:*          → batch:cngn-transfer, batch:fiat-payout
recurring:*      → recurring:read, recurring:manage
transactions:write → onramp:initiate, offramp:initiate
```

## 🔐 Scope Enforcement

### Single Scope

```rust
enforce_single_scope("wallet:read", req, next).await
```

### Multiple Scopes (ALL)

```rust
enforce_all_scopes(vec!["wallet:read", "onramp:quote"], req, next).await
```

### Any Scope

```rust
enforce_any_scope(vec!["wallet:read", "onramp:quote"], req, next).await
```

## ❌ Error Response

```json
HTTP 403 Forbidden

{
  "error": "insufficient_scope",
  "error_description": "The request requires scopes that were not granted",
  "required_scope": "wallet:trustline",
  "granted_scopes": "wallet:read onramp:quote"
}
```

## 🧾 Partial Consent Example

```
Requested: wallet:*, onramp:*, bills:*
Approved:  wallet:read, onramp:quote
Token:     wallet:read onramp:quote
```

## 🔒 Sensitive Scopes

Require admin approval:
- `admin:*` (all admin scopes)
- `wallet:trustline`, `wallet:switch`
- `onramp:initiate`, `offramp:initiate`, `bills:pay`
- `batch:cngn-transfer`, `batch:fiat-payout`
- `webhooks:manage`
- `recurring:manage`

## 📊 Scope Validation

```rust
// Validate format
ScopeDefinition::validate_format("wallet:read")?; // OK
ScopeDefinition::validate_format("invalid")?;     // Error
```

## 🗄️ Database Operations

```rust
use aframp_backend::database::oauth_scope_repository::OAuthScopeRepository;

let repo = OAuthScopeRepository::new(db);

// Upsert scope
repo.upsert_scope("wallet:read", "Read wallet", "wallet", false).await?;

// Get scope
let scope = repo.get_scope("wallet:read").await?;

// Get by category
let wallet_scopes = repo.get_scopes_by_category("wallet").await?;

// Get sensitive
let sensitive = repo.get_sensitive_scopes().await?;

// Approval workflow
let approval = repo.create_approval("client_123", "wallet:trustline").await?;
repo.approve_scope(&approval.id, "admin_user").await?;
```

## 🧪 Testing

```bash
# Run all scope tests
cargo test --lib auth::scope_tests

# Run specific test
cargo test --lib auth::scope_tests::tests::test_scope_hierarchy_wildcard_admin

# Run with output
cargo test --lib auth::scope_tests -- --nocapture
```

## 📝 Logging

Scope denials logged with context:

```json
{
  "level": "WARN",
  "message": "scope enforcement denied",
  "jti": "jti_...",
  "consumer_id": "consumer_123",
  "client_id": "client_123",
  "required_scope": "wallet:trustline",
  "granted_scopes": "wallet:read onramp:quote"
}
```

## 🔄 Integration Points

### With Token Issuance
- Tokens include only approved scopes
- Partial consent respected
- Sensitive scopes checked

### With Token Validation
- Existing validator reused
- Scope claim extracted
- Hierarchy applied

### With Middleware
- Protects endpoints
- Enforces requirements
- Returns 403 on denial

## 🎯 Common Patterns

### Protect Admin Endpoint

```rust
app.route(
    "/api/admin/config",
    post(handler).layer(
        axum::middleware::from_fn(|req, next| {
            enforce_single_scope("admin:config".to_string(), req, next)
        })
    )
);
```

### Protect with Wildcard

```rust
// Token with admin:* satisfies admin:transactions
enforce_single_scope("admin:transactions", req, next).await
```

### Protect with Multiple Scopes

```rust
// Both scopes required
enforce_all_scopes(
    vec!["wallet:read", "transactions:read"],
    req,
    next
).await
```

### Protect with Any Scope

```rust
// At least one scope required
enforce_any_scope(
    vec!["wallet:read", "onramp:quote"],
    req,
    next
).await
```

## 📚 Files

| File | Purpose |
|---|---|
| `src/auth/scope_catalog.rs` | Scope definitions |
| `src/auth/scope_hierarchy.rs` | Hierarchy logic |
| `src/middleware/scope_middleware.rs` | Enforcement |
| `src/database/oauth_scope_repository.rs` | Persistence |
| `src/auth/scope_tests.rs` | Tests |
| `OAUTH_SCOPE_SYSTEM.md` | Complete guide |

## 🔗 References

- [OAuth 2.0 RFC 6749 - Scope](https://tools.ietf.org/html/rfc6749#section-3.3)
- [OpenID Connect Scopes](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)

---

**Quick Reference v1.0**
