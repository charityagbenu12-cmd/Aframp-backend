# =============================================================================
# Stage 1 — cargo-chef planner
# Computes the dependency recipe from Cargo.toml / Cargo.lock so that the
# dependency compilation layer is cached independently of application source.
# =============================================================================
FROM rust:1.85-slim AS chef
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install cargo-chef --locked
WORKDIR /app

# =============================================================================
# Stage 2 — dependency recipe
# =============================================================================
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

# =============================================================================
# Stage 3 — dependency compilation (cached layer)
# Only re-runs when Cargo.toml / Cargo.lock change.
# =============================================================================
FROM chef AS builder-deps
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --features database,cache --recipe-path recipe.json

# =============================================================================
# Stage 4 — application build + sqlx-cli for migrations
# Only re-runs when application source changes.
# =============================================================================
FROM builder-deps AS builder
# Install sqlx-cli (postgres only, no default features keeps it lean)
RUN cargo install sqlx-cli \
        --no-default-features \
        --features native-tls,postgres \
        --locked

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --features database,cache \
    && strip target/release/Aframp-Backend

# =============================================================================
# Stage 5 — runtime image
# debian:bookworm-slim provides glibc, OpenSSL, CA certs, and curl for the
# Docker HEALTHCHECK, while remaining minimal (~120 MB compressed).
# No Rust toolchain, no build tools, no source code.
# =============================================================================
FROM debian:bookworm-slim AS runtime

# Install only the runtime libraries required by the binary:
#   - ca-certificates  : TLS root CAs for outbound HTTPS (Stellar, payment providers)
#   - libssl3          : OpenSSL runtime (linked by reqwest / sqlx)
#   - curl             : used exclusively by the Docker HEALTHCHECK instruction
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create a non-root user for the process
RUN groupadd --gid 10001 appgroup \
    && useradd --uid 10001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

# Copy the stripped application binary
COPY --from=builder /app/target/release/Aframp-Backend /app/aframp-backend

# Copy sqlx-cli for running migrations at startup
COPY --from=builder /usr/local/cargo/bin/sqlx /usr/local/bin/sqlx

# Copy database migrations
COPY --from=builder /app/migrations /app/migrations

# Copy the entrypoint script
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# Ensure the app directory is owned by the non-root user
RUN chown -R appuser:appgroup /app

# Expose the application port (overridable via SERVER_PORT env var)
EXPOSE 8000

# Docker health check — validates the /health endpoint.
# start-period gives the app time to run migrations and warm caches before
# the first check fires.
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -fsS "http://localhost:${SERVER_PORT:-8000}/health" || exit 1

USER appuser

ENTRYPOINT ["/app/docker-entrypoint.sh"]
