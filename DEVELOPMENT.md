# Local Development with Docker

This document covers building, running, and testing the Aframp backend using Docker and Docker Compose.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) 24+
- [Docker Compose](https://docs.docker.com/compose/install/) v2 (bundled with Docker Desktop)
- `curl` (for manual health checks)

---

## Quick Start

### 1. Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and set the required values (marked `REQUIRED` in the file). At minimum:

```
POSTGRES_PASSWORD=<choose a strong password>
REDIS_PASSWORD=<choose a strong password>
JWT_SECRET=<at least 64 random characters — openssl rand -hex 64>
```

### 2. Build and start the full stack

```bash
docker compose up --build
```

This starts PostgreSQL, Redis, and the application in dependency order. The application container waits for both services to pass their health checks before starting.

On first run the Rust build takes several minutes. Subsequent builds are fast because the dependency compilation layer is cached by `cargo-chef`.

### 3. Verify the stack is healthy

```bash
curl http://localhost:8000/health
```

Expected response (HTTP 200):

```json
{
  "status": "Healthy",
  "checks": {
    "database": { "status": "Up", "response_time_ms": 2 },
    "cache":    { "status": "Up", "response_time_ms": 1 },
    "stellar":  { "status": "Up", "response_time_ms": 120 }
  },
  "timestamp": "..."
}
```

Additional probes:

```bash
curl http://localhost:8000/health/ready   # readiness probe
curl http://localhost:8000/health/live    # liveness probe
```

---

## Service Ports

| Service    | Host port | Container port |
|------------|-----------|----------------|
| App        | 8000      | 8000           |
| PostgreSQL | 5432      | 5432           |
| Redis      | 6379      | 6379           |

Override any port in `.env` (e.g. `SERVER_PORT=9000`).

---

## Database Migrations

Migrations live in `migrations/` and are applied automatically by the application on startup via `sqlx::migrate!`. The `docker-entrypoint.sh` script waits for PostgreSQL to accept TCP connections before launching the binary, ensuring migrations always run against a live database.

To inspect or manually run migrations outside Docker:

```bash
# Install sqlx-cli
cargo install sqlx-cli --no-default-features --features postgres

# Run migrations
sqlx migrate run --database-url "$DATABASE_URL"

# Revert the last migration
sqlx migrate revert --database-url "$DATABASE_URL"
```

---

## Stopping the Stack

```bash
# Stop containers, keep volumes (data persists)
docker compose down

# Stop containers and remove all volumes (full reset)
docker compose down -v
```

---

## Rebuilding After Code Changes

```bash
docker compose up --build app
```

Only the `app` service is rebuilt. The `cargo-chef` caching strategy means only changed source files are recompiled — dependencies are not redownloaded.

---

## Running Integration Tests

The `docker-compose.test.yml` override spins up ephemeral (no persistent storage) versions of all services and runs the integration test suite:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.test.yml \
  up --build --abort-on-container-exit
```

`--abort-on-container-exit` stops the entire stack as soon as the `test-runner` service exits, and the compose command exits with the test runner's exit code (0 = pass, non-zero = fail).

Clean up after the test run:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.test.yml \
  down -v
```

All test data is ephemeral — no volumes are created, so `down -v` is equivalent to `down` for the test stack.

---

## Running Unit Tests Locally (without Docker)

```bash
cargo test --features database,cache
```

---

## Image Size

The production image is built on `debian:bookworm-slim` and contains only:

- The stripped `Aframp-Backend` binary
- The `migrations/` directory
- `ca-certificates`, `libssl3`, `curl` (runtime deps + health check)
- `docker-entrypoint.sh`

Approximate final image size: **~120–140 MB** (varies with binary size).

To inspect the actual size after building:

```bash
docker compose build app
docker images | grep aframp
```

---

## Security Notes

- No secrets or credentials are baked into any image layer. All sensitive values are injected at runtime via environment variables.
- The application process runs as a non-root user (`uid 10001`).
- The `.dockerignore` file excludes `.env*` files, `target/`, and all other non-essential files from the build context.
- Passwords for PostgreSQL and Redis are required at startup — the compose file will refuse to start if `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, or `JWT_SECRET` are unset.

---

## Troubleshooting

**App fails to start with "DATABASE_URL not set"**
Ensure your `.env` file exists and `DATABASE_URL` is set, or that the `POSTGRES_PASSWORD` variable is exported so the compose interpolation can build the URL.

**Migrations fail with "relation already exists"**
The database already has a partial schema. Run `docker compose down -v` to reset, then `docker compose up --build`.

**Health check returns 503**
Check `docker compose logs app` for startup errors. Common causes: database unreachable, Redis unreachable, or Stellar Horizon timeout. The `/health` endpoint returns a JSON body describing which component is unhealthy.

**Build is slow on first run**
Expected — Rust compiles all dependencies from scratch. Subsequent builds use the `cargo-chef` cache and complete in seconds for source-only changes.
