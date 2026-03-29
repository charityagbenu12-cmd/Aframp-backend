#!/bin/bash
# Service Authentication Test Runner
# This script sets up the test environment and runs all tests

set -e  # Exit on error

echo "=== Service Authentication Test Runner ==="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Rust/Cargo not found${NC}"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

echo -e "${GREEN}✓ Rust found: $(rustc --version)${NC}"

# Check if PostgreSQL is available
if ! command -v psql &> /dev/null; then
    echo -e "${YELLOW}Warning: PostgreSQL client not found${NC}"
    echo "Tests requiring database will be skipped"
    SKIP_DB_TESTS=true
else
    echo -e "${GREEN}✓ PostgreSQL client found${NC}"
    SKIP_DB_TESTS=false
fi

# Check if Redis is available
if ! command -v redis-cli &> /dev/null; then
    echo -e "${YELLOW}Warning: Redis client not found${NC}"
    echo "Tests requiring Redis will be skipped"
    SKIP_REDIS_TESTS=true
else
    # Check if Redis is running
    if redis-cli ping &> /dev/null; then
        echo -e "${GREEN}✓ Redis is running${NC}"
        SKIP_REDIS_TESTS=false
    else
        echo -e "${YELLOW}Warning: Redis is not running${NC}"
        SKIP_REDIS_TESTS=true
    fi
fi

echo ""
echo "=== Running Tests ==="
echo ""

# Run compilation check
echo "1. Checking compilation..."
if cargo check --features database 2>&1 | tee /tmp/cargo_check.log; then
    echo -e "${GREEN}✓ Compilation successful${NC}"
else
    echo -e "${RED}✗ Compilation failed${NC}"
    echo "See /tmp/cargo_check.log for details"
    exit 1
fi

echo ""

# Run unit tests
echo "2. Running unit tests..."
if cargo test service_auth::tests --features database -- --nocapture; then
    echo -e "${GREEN}✓ Unit tests passed${NC}"
else
    echo -e "${RED}✗ Unit tests failed${NC}"
    exit 1
fi

echo ""

# Run integration tests (if database and Redis are available)
if [ "$SKIP_DB_TESTS" = false ] && [ "$SKIP_REDIS_TESTS" = false ]; then
    echo "3. Running integration tests..."
    
    # Set up test database if needed
    if [ -z "$DATABASE_URL" ]; then
        export DATABASE_URL="postgres://localhost/aframp_test"
        echo "Using default DATABASE_URL: $DATABASE_URL"
    fi
    
    if [ -z "$REDIS_URL" ]; then
        export REDIS_URL="redis://127.0.0.1:6379"
        echo "Using default REDIS_URL: $REDIS_URL"
    fi
    
    # Check if test database exists
    if psql -lqt | cut -d \| -f 1 | grep -qw aframp_test; then
        echo "Test database exists"
    else
        echo "Creating test database..."
        createdb aframp_test || true
    fi
    
    # Run migrations
    echo "Running migrations..."
    if sqlx migrate run --database-url "$DATABASE_URL" 2>&1; then
        echo -e "${GREEN}✓ Migrations applied${NC}"
    else
        echo -e "${YELLOW}Warning: Migration failed, continuing anyway${NC}"
    fi
    
    # Run integration tests
    if cargo test --test service_auth_test --features database -- --ignored --nocapture; then
        echo -e "${GREEN}✓ Integration tests passed${NC}"
    else
        echo -e "${RED}✗ Integration tests failed${NC}"
        exit 1
    fi
else
    echo "3. Skipping integration tests (database or Redis not available)"
fi

echo ""
echo "=== Test Summary ==="
echo ""

# Count test results
UNIT_TESTS=$(cargo test service_auth::tests --features database 2>&1 | grep "test result:" | head -1)
echo "Unit tests: $UNIT_TESTS"

if [ "$SKIP_DB_TESTS" = false ] && [ "$SKIP_REDIS_TESTS" = false ]; then
    INTEGRATION_TESTS=$(cargo test --test service_auth_test --features database -- --ignored 2>&1 | grep "test result:" | head -1)
    echo "Integration tests: $INTEGRATION_TESTS"
fi

echo ""
echo -e "${GREEN}=== All Tests Completed Successfully ===${NC}"
echo ""

# Optional: Run clippy for linting
if command -v cargo-clippy &> /dev/null; then
    echo "Running clippy linter..."
    cargo clippy --features database -- -D warnings
    echo -e "${GREEN}✓ Clippy checks passed${NC}"
fi

# Optional: Check formatting
echo "Checking code formatting..."
if cargo fmt -- --check; then
    echo -e "${GREEN}✓ Code formatting is correct${NC}"
else
    echo -e "${YELLOW}Warning: Code formatting issues found${NC}"
    echo "Run 'cargo fmt' to fix"
fi

echo ""
echo "Test run complete!"
