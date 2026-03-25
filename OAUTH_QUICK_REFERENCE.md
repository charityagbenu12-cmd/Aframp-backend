# OAuth 2.0 Token System - Quick Reference

## 🚀 Quick Start

### Issue a Token

```bash
curl -X POST http://localhost:8000/api/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "consumer_id": "consumer_123",
    "client_id": "client_123",
    "consumer_type": "mobile_client",
    "scope": "read write",
    "environment": "mainnet",
    "requested_ttl_secs": 1800
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleV8xMjMifQ...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "scope": "read write"
}
```

### Use Token in Request

```bash
curl -X GET http://localhost:8000/api/payments \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleV8xMjMifQ..."
```

### Revoke Token

```bash
curl -X POST http://localhost:8000/api/oauth/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "jti": "jti_550e8400e29b41d4a716446655440000"
  }'
```

## 📋 Consumer Types & TTLs

| Type | TTL | Use Case |
|---|---|---|
| `mobile_client` | 1h | Mobile apps, web clients |
| `partner` | 30m | Third-party integrations |
| `microservice` | 15m | Service-to-service |
| `admin` | 15m | Admin operations |

## 🔐 Token Claims

```json
{
  "iss": "https://api.aframp.com",
  "sub": "consumer_123",
  "aud": "api",
  "exp": 1711270800,
  "iat": 1711267200,
  "jti": "jti_550e8400e29b41d4a716446655440000",
  "scope": "read write",
  "client_id": "client_123",
  "consumer_type": "mobile_client",
  "environment": "mainnet",
  "kid": "key_id_123",
  "binding": "192.168.1.1"
}
```

## ⚙️ Configuration

```bash
# .env
OAUTH_ISSUER_URL=https://api.aframp.com
OAUTH_API_AUDIENCE=api
OAUTH_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
OAUTH_KEY_ID=key_id_123
OAUTH_JWKS_URL=https://auth.aframp.com/.well-known/jwks.json
OAUTH_JWKS_REFRESH_INTERVAL_SECS=3600
OAUTH_MAX_ACTIVE_TOKENS_PER_CONSUMER=10
OAUTH_MAX_ISSUANCE_PER_CLIENT_PER_WINDOW=100
OAUTH_RATE_LIMIT_WINDOW_SECS=60
```

## 🔑 Generate RS256 Keys

```bash
# Private key
openssl genrsa -out private_key.pem 2048

# Public key
openssl rsa -in private_key.pem -pubout -out public_key.pem

# View private key
cat private_key.pem

# View public key
cat public_key.pem
```

## 📊 Metrics

```
# Token issuance
aframp_tokens_issued_total{consumer_type="mobile_client"} 1234

# Token validation
aframp_tokens_validated_total{consumer_type="mobile_client"} 5678

# Validation failures
aframp_token_validation_failures_total{reason="expired"} 12

# Token revocation
aframp_tokens_revoked_total 45
```

View metrics:
```bash
curl http://localhost:8000/metrics | grep aframp_tokens
```

## 🧪 Test Token Issuance

```rust
#[tokio::test]
async fn test_token_issuance() {
    let service = OAuthTokenService::new(
        "https://api.aframp.com".to_string(),
        "api".to_string(),
        private_key_pem,
        "key_id_123".to_string(),
        db,
        Some(redis_cache),
    );

    let request = TokenIssuanceRequest {
        consumer_id: "consumer_123".to_string(),
        client_id: "client_123".to_string(),
        consumer_type: ConsumerType::MobileClient,
        scope: "read write".to_string(),
        environment: Environment::Mainnet,
        requested_ttl_secs: Some(1800),
        binding: Some("192.168.1.1".to_string()),
    };

    let response = service.issue_token(request).await.unwrap();
    assert!(!response.access_token.is_empty());
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 1800);
}
```

## 🔍 Decode Token (for debugging)

```bash
# Extract header and payload
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleV8xMjMifQ.eyJpc3MiOiJodHRwczovL2FwaS5hZnJhbXAuY29tIiwic3ViIjoiY29uc3VtZXJfMTIzIiwiYXVkIjoiYXBpIiwiZXhwIjoxNzExMjcwODAwLCJpYXQiOjE3MTEyNjcyMDAsImp0aSI6Imp0aV81NTBlODQwMGUyOWI0MWQ0YTcxNjQ0NjY1NTQ0MDAwMCIsInNjb3BlIjoicmVhZCB3cml0ZSIsImNsaWVudF9pZCI6ImNsaWVudF8xMjMiLCJjb25zdW1lcl90eXBlIjoibW9iaWxlX2NsaWVudCIsImVudmlyb25tZW50IjoibWFpbm5ldCIsImtpZCI6ImtleV8xMjMiLCJiaW5kaW5nIjoiMTkyLjE2OC4xLjEifQ.signature"

# Decode header
echo $TOKEN | cut -d. -f1 | base64 -d | jq .

# Decode payload
echo $TOKEN | cut -d. -f2 | base64 -d | jq .
```

## 🚨 Error Codes

| Code | Status | Description |
|---|---|---|
| `invalid_token` | 401 | Token signature invalid |
| `token_expired` | 401 | Token has expired |
| `token_revoked` | 401 | Token has been revoked |
| `token_binding_failed` | 401 | IP/nonce binding mismatch |
| `token_environment_mismatch` | 401 | Environment mismatch |
| `token_issuer_mismatch` | 401 | Issuer mismatch |
| `token_audience_mismatch` | 401 | Audience mismatch |
| `rate_limit_exceeded` | 429 | Rate limit exceeded |
| `missing_token` | 401 | No token provided |

## 📝 Logging

Tokens are logged by JTI only (never full token):

```json
{
  "timestamp": "2024-03-24T10:30:00Z",
  "level": "INFO",
  "message": "access token issued",
  "jti": "jti_550e8400e29b41d4a716446655440000",
  "consumer_id": "consumer_123",
  "client_id": "client_123",
  "scope": "read write",
  "expires_at": 1711270800
}
```

## 🔒 Security Checklist

- [ ] Private key stored in secure vault
- [ ] Public key distributed via JWKS endpoint
- [ ] RS256 signature verification enabled
- [ ] Token binding enforced (IP or nonce)
- [ ] Revocation checking enabled
- [ ] Rate limiting configured
- [ ] Metrics monitoring enabled
- [ ] Logs reviewed for token leaks
- [ ] Keys rotated regularly
- [ ] Redis cache monitored

## 🐛 Common Issues

### "token_binding_failed"
- Client IP doesn't match token binding
- Check if behind proxy (use X-Forwarded-For)

### "token_expired"
- Token TTL exceeded
- Issue new token

### "rate_limit_exceeded"
- Too many tokens issued
- Wait for rate limit window to reset
- Check Redis connectivity

### "invalid_token"
- Token signature invalid
- Token corrupted
- Wrong public key

## 📚 Files

| File | Purpose |
|---|---|
| `src/auth/oauth_token_service.rs` | Token issuance |
| `src/auth/oauth_token_validator.rs` | Token validation |
| `src/auth/jwks_service.rs` | JWKS key management |
| `src/auth/token_limiter.rs` | Rate limiting |
| `src/database/token_registry_repository.rs` | Token persistence |
| `migrations/20240324_create_token_registry.sql` | Database schema |
| `OAUTH_TOKEN_SYSTEM.md` | System documentation |
| `OAUTH_IMPLEMENTATION_GUIDE.md` | Implementation steps |

## 🔗 References

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)
- [JWK RFC 7517](https://tools.ietf.org/html/rfc7517)
- [Bearer Token RFC 6750](https://tools.ietf.org/html/rfc6750)

## 💡 Tips

1. **Always validate all claims** - Never trust token payload without verification
2. **Never log full tokens** - Only log JTI for debugging
3. **Use short TTLs** - Shorter TTLs reduce impact of token compromise
4. **Rotate keys regularly** - JWKS supports key rotation
5. **Monitor metrics** - Watch for unusual validation failures
6. **Test binding** - Ensure IP/nonce binding works correctly
7. **Cache revocation** - Use Redis for fast revocation checks
8. **Rate limit aggressively** - Prevent token exhaustion attacks
