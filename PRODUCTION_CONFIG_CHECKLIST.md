# Production Configuration Checklist

Complete every item before deploying to production. Items marked **[BLOCKER]**
will cause the application to refuse to start.

---

## 1. Secrets Manager

All secrets below must be stored in your secrets manager (AWS Secrets Manager,
HashiCorp Vault, etc.) and injected as environment variables at deploy time.
**Never commit secrets to the repository or bake them into container images.**

| Variable | Format | Notes |
|----------|--------|-------|
| `DATABASE_URL` | `postgres://user:pass@host:5432/db?sslmode=verify-full` | **[BLOCKER]** Must include SSL |
| `DATABASE_READ_REPLICA_URL` | Same format | Optional — enables read replica routing |
| `REDIS_URL` | `rediss://:password@host:6379` | **[BLOCKER]** Must use `rediss://` (TLS) |
| `JWT_SECRET` | Random string ≥ 32 chars | **[BLOCKER]** Generate: `openssl rand -hex 32` |
| `ENCRYPTION_KEY` | 32-byte hex string | **[BLOCKER]** Generate: `openssl rand -hex 32` |
| `PAYSTACK_SECRET_KEY` | `sk_live_...` | **[BLOCKER]** |
| `PAYSTACK_PUBLIC_KEY` | `pk_live_...` | |
| `PAYSTACK_WEBHOOK_SECRET` | Paystack dashboard value | |
| `FLUTTERWAVE_SECRET_KEY` | `FLWSECK-...` | |
| `FLUTTERWAVE_PUBLIC_KEY` | `FLWPUBK-...` | |
| `FLUTTERWAVE_WEBHOOK_SECRET` | Flutterwave dashboard value | |
| `MPESA_CONSUMER_KEY` | Daraja portal value | |
| `MPESA_CONSUMER_SECRET` | Daraja portal value | |
| `MPESA_PASSKEY` | Daraja portal value | |
| `SYSTEM_WALLET_ADDRESS` | Stellar G... address | **[BLOCKER]** |
| `SYSTEM_WALLET_SECRET` | Stellar S... secret key | **[BLOCKER]** Never log this |
| `HOT_WALLET_SECRET_KEY` | Stellar S... secret key | |
| `CNGN_ISSUER_MAINNET` | Stellar G... address | **[BLOCKER]** |

---

## 2. Non-Secret Environment Variables

Set these in your deployment configuration (ECS task definition, K8s ConfigMap, etc.):

| Variable | Production Value | Notes |
|----------|-----------------|-------|
| `APP_ENV` | `production` | **[BLOCKER]** |
| `SERVER_HOST` | `0.0.0.0` | |
| `SERVER_PORT` | `8000` | |
| `STELLAR_NETWORK` | `mainnet` | **[BLOCKER]** |
| `STELLAR_HORIZON_URL` | `https://horizon.stellar.org` | |
| `LOG_LEVEL` | `WARN` | |
| `LOG_FORMAT` | `json` | Required for log aggregation |
| `ENABLE_TRACING` | `true` | |
| `OTEL_SERVICE_NAME` | `aframp-backend` | |
| `OTEL_SAMPLING_RATE` | `0.1` | Tune based on volume |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4317` | |
| `DB_MAX_CONNECTIONS` | `50` | Tune per instance count |
| `DB_MIN_CONNECTIONS` | `10` | |
| `CACHE_MAX_CONNECTIONS` | `30` | |
| `ENABLE_MOCK_PAYMENTS` | `false` | **[BLOCKER]** |
| `CORS_ALLOWED_ORIGINS` | `https://aframp.io,https://app.aframp.io` | |

---

## 3. Database

- [ ] PostgreSQL 15+ with SSL enabled (`ssl = on` in `postgresql.conf`)
- [ ] `sslmode=verify-full` in `DATABASE_URL` with CA cert available
- [ ] `pg_stat_statements` extension enabled
- [ ] Slow query logging: `log_min_duration_statement = 200`
- [ ] Connection pooler (PgBouncer) in front of RDS/Aurora if using serverless
- [ ] Read replica provisioned and `DATABASE_READ_REPLICA_URL` set
- [ ] Automated backups enabled (daily snapshots + WAL archiving)
- [ ] Migration run: `sqlx migrate run` before deploying new binary

## 4. Redis

- [ ] Redis 7+ with TLS enabled
- [ ] `REDIS_URL` uses `rediss://` scheme
- [ ] `maxmemory-policy allkeys-lru` configured
- [ ] `appendonly yes` (AOF persistence) enabled
- [ ] Auth password set and included in `REDIS_URL`
- [ ] Cluster mode or Sentinel for HA

## 5. TLS / Networking

- [ ] Load balancer / reverse proxy terminates TLS
- [ ] Minimum TLS version: 1.2 (prefer 1.3)
- [ ] HSTS header configured: `max-age=31536000; includeSubDomains; preload`
- [ ] Certificate auto-renewal configured (Let's Encrypt / ACM)
- [ ] Certificate expiry monitoring alert set (≤ 30 days)
- [ ] HTTP → HTTPS redirect enforced
- [ ] Security headers set (X-Frame-Options, X-Content-Type-Options, CSP)

## 6. Startup Validation

The application runs `validate_production_config()` at startup and will exit
with a non-zero code and clear error messages if any **[BLOCKER]** item above
is missing or invalid. Check application logs if the container fails to start.

## 7. Pre-Deploy Verification

```bash
# 1. Confirm correct environment
echo $APP_ENV   # must print: production

# 2. Test database connectivity with SSL
psql "$DATABASE_URL" -c "SELECT version();"

# 3. Test Redis connectivity with TLS
redis-cli -u "$REDIS_URL" ping

# 4. Confirm no placeholder secrets
env | grep -E "(SECRET|KEY|PASSWORD)" | grep -iE "(change-me|xxxx|replace)"
# must return nothing

# 5. Health check after deploy
curl -f https://aframp.io/health
```
