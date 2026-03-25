# Runbooks — Aframp Backend

Step-by-step guides for provisioning and operating the Aframp backend.
Follow these in order when setting up a new environment.

---

## 1. Prerequisites

Install these tools before starting:

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable

# sqlx-cli (database migrations)
cargo install sqlx-cli --no-default-features --features postgres

# Docker + Docker Compose
# https://docs.docker.com/get-docker/

# PostgreSQL client
# Ubuntu: apt install postgresql-client
# macOS:  brew install libpq

# Redis client
# Ubuntu: apt install redis-tools
# macOS:  brew install redis
```

---

## 2. Local Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/Petah1/Aframp-backend.git
cd Aframp-backend

# 2. Copy environment template
cp .env.example .env
# Edit .env — fill in dev credentials (see .env.example comments)

# 3. Start the full local stack
docker compose up -d

# 4. Verify services are healthy
docker compose ps
# All services should show "healthy"

# 5. Run database migrations
DATABASE_URL="postgres://aframp:aframp_dev@localhost:5432/aframp_dev?sslmode=disable" \
  sqlx migrate run

# 6. Build and run the application
cargo run --features database

# 7. Confirm health
curl http://localhost:8000/health
```

---

## 3. Staging Environment Setup

### 3.1 Provision infrastructure

Provision:
- PostgreSQL 15+ instance with SSL enabled
- Redis 7+ instance with TLS enabled
- Container runtime (ECS, K8s, or VM with Docker)
- Load balancer with TLS termination (ALB or nginx)

### 3.2 Store secrets

Store every **[SECRET]** from `PRODUCTION_CONFIG_CHECKLIST.md` in your secrets
manager. Example using AWS Secrets Manager:

```bash
aws secretsmanager create-secret \
  --name "aframp/staging/DATABASE_URL" \
  --secret-string "postgres://user:pass@host:5432/aframp_staging?sslmode=require"

aws secretsmanager create-secret \
  --name "aframp/staging/JWT_SECRET" \
  --secret-string "$(openssl rand -hex 32)"
```

### 3.3 Configure non-secret variables

Set in your deployment config (ECS task definition / K8s ConfigMap):

```
APP_ENV=staging
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
STELLAR_NETWORK=testnet
LOG_LEVEL=INFO
LOG_FORMAT=json
ENABLE_TRACING=true
DB_MAX_CONNECTIONS=30
CACHE_MAX_CONNECTIONS=15
ENABLE_MOCK_PAYMENTS=false
```

### 3.4 Run migrations

```bash
DATABASE_URL="<staging-url>" sqlx migrate run
```

### 3.5 Deploy and verify

```bash
# Build production image
docker build -t aframp-backend:staging .

# Push to registry
docker tag aframp-backend:staging <registry>/aframp-backend:staging
docker push <registry>/aframp-backend:staging

# After deploy, verify health
curl -f https://staging.aframp.io/health
```

---

## 4. Production Environment Setup

Follow all steps in Section 3, replacing `staging` with `production`, plus:

### 4.1 Generate production secrets

```bash
# JWT secret (minimum 32 chars)
openssl rand -hex 32

# Encryption key (32 bytes = 64 hex chars)
openssl rand -hex 32
```

### 4.2 Database SSL

Ensure `DATABASE_URL` includes `sslmode=verify-full` and the CA certificate
is available in the container at the path referenced by `PGSSLROOTCERT`.

```bash
# Test SSL connection
psql "postgres://user:pass@host/db?sslmode=verify-full" -c "SELECT 1;"
```

### 4.3 Redis TLS

```bash
# Test TLS connection
redis-cli -u "rediss://:password@host:6379" ping
# Expected: PONG
```

### 4.4 TLS certificate setup (Let's Encrypt)

```bash
# Install Certbot
apt install certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d aframp.io -d app.aframp.io

# Verify auto-renewal
certbot renew --dry-run

# Confirm renewal timer is active
systemctl status certbot.timer
```

### 4.5 Configure nginx

```bash
# Copy nginx config
cp config/nginx/nginx.conf /etc/nginx/nginx.conf

# Test config
nginx -t

# Reload
nginx -s reload
```

### 4.6 Pre-deploy checklist

Work through every item in `PRODUCTION_CONFIG_CHECKLIST.md` before deploying.

### 4.7 Deploy

```bash
# Build
docker build -t aframp-backend:production .

# Run migrations (before starting new containers)
docker run --rm \
  -e DATABASE_URL="$DATABASE_URL" \
  aframp-backend:production \
  sqlx migrate run

# Start application
docker run -d \
  --name aframp-backend \
  -p 8000:8000 \
  --env-file /run/secrets/aframp-env \
  aframp-backend:production

# Verify
curl -f https://aframp.io/health
```

---

## 5. Running Integration Tests

```bash
# Start ephemeral test stack
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d

# Wait for services to be healthy
docker compose ps

# Run tests
DATABASE_URL="postgres://aframp:aframp_test@localhost:5432/aframp_test?sslmode=disable" \
REDIS_URL="redis://localhost:6379" \
cargo test --features database,integration -- --nocapture

# Tear down
docker compose -f docker-compose.yml -f docker-compose.test.yml down -v
```

---

## 6. Certificate Renewal Monitoring

Set up an alert to fire when the TLS certificate expires within 30 days:

```bash
# Check expiry manually
echo | openssl s_client -connect aframp.io:443 2>/dev/null \
  | openssl x509 -noout -dates

# Certbot auto-renewal log
journalctl -u certbot
```

Configure your monitoring tool (Datadog, CloudWatch, Grafana) to alert on
the `ssl_certificate_expiry_days` metric with threshold ≤ 30.

---

## 7. Rollback

```bash
# Roll back to previous image tag
docker stop aframp-backend
docker run -d \
  --name aframp-backend \
  -p 8000:8000 \
  --env-file /run/secrets/aframp-env \
  aframp-backend:<previous-tag>

# If migration rollback is needed
DATABASE_URL="$DATABASE_URL" sqlx migrate revert
```

---

## 8. Troubleshooting

### Application fails to start

Check logs for configuration validation errors:

```bash
docker logs aframp-backend 2>&1 | head -50
```

Common causes:
- Missing required env var → add it to secrets manager
- `DATABASE_URL` missing `sslmode=require` in production → update the secret
- `REDIS_URL` using `redis://` instead of `rediss://` in production → update
- `JWT_SECRET` shorter than 32 chars → regenerate with `openssl rand -hex 32`
- `STELLAR_NETWORK=testnet` in production → set to `mainnet`

### Database connection refused

```bash
# Test connectivity
psql "$DATABASE_URL" -c "SELECT 1;"

# Check SSL
psql "$DATABASE_URL" -c "SHOW ssl;"
```

### Redis connection refused

```bash
redis-cli -u "$REDIS_URL" ping
```

### High query latency

```sql
-- Top slow queries
SELECT round(mean_exec_time::numeric, 2) AS mean_ms,
       calls, left(query, 100) AS query
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 20;

-- Refresh materialised views manually
SELECT refresh_analytics_views();
```
