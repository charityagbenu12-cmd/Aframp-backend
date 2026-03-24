#!/bin/sh
# =============================================================================
# docker-entrypoint.sh
# 1. Waits for PostgreSQL to accept TCP connections.
# 2. Runs sqlx database migrations.
# 3. Starts the application.
#
# Exits non-zero on any failure so Docker restarts the container.
#
# Environment variables consumed:
#   DB_HOST          - postgres hostname (default: postgres)
#   DB_PORT          - postgres port     (default: 5432)
#   DATABASE_URL     - full postgres connection URL (required for migrations)
#   RUN_MIGRATIONS   - set to "false" to skip migration step (default: true)
# =============================================================================
set -e

DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"

# ---------------------------------------------------------------------------
# Wait for PostgreSQL to accept TCP connections.
# curl with the telnet:// scheme performs a raw TCP connect without sending
# any HTTP data, making it a lightweight port-open check.
# ---------------------------------------------------------------------------
wait_for_postgres() {
    retries=30
    echo "==> Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT}..."
    while ! curl -sf --connect-timeout 2 "telnet://${DB_HOST}:${DB_PORT}" >/dev/null 2>&1; do
        retries=$((retries - 1))
        if [ "$retries" -eq 0 ]; then
            echo "ERROR: PostgreSQL at ${DB_HOST}:${DB_PORT} did not become reachable." >&2
            exit 1
        fi
        echo "    Still waiting... (${retries} retries left)"
        sleep 2
    done
    echo "==> PostgreSQL is reachable."
}

# ---------------------------------------------------------------------------
# Run sqlx migrations.
# ---------------------------------------------------------------------------
run_migrations() {
    if [ -z "$DATABASE_URL" ]; then
        echo "ERROR: DATABASE_URL is not set — cannot run migrations." >&2
        exit 1
    fi

    echo "==> Running database migrations..."
    sqlx migrate run --source /app/migrations --database-url "$DATABASE_URL"
    echo "==> Migrations complete."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
    wait_for_postgres
    run_migrations
fi

echo "==> Starting Aframp backend..."
exec /app/aframp-backend "$@"
