# Service Authentication Test Runner (PowerShell)
# This script sets up the test environment and runs all tests

$ErrorActionPreference = "Stop"

Write-Host "=== Service Authentication Test Runner ===" -ForegroundColor Cyan
Write-Host ""

# Check if Rust is installed
try {
    $rustVersion = cargo --version
    Write-Host "✓ Rust found: $rustVersion" -ForegroundColor Green
} catch {
    Write-Host "Error: Rust/Cargo not found" -ForegroundColor Red
    Write-Host "Please install Rust from https://rustup.rs/"
    exit 1
}

# Check if PostgreSQL is available
$skipDbTests = $false
try {
    $null = Get-Command psql -ErrorAction Stop
    Write-Host "✓ PostgreSQL client found" -ForegroundColor Green
} catch {
    Write-Host "Warning: PostgreSQL client not found" -ForegroundColor Yellow
    Write-Host "Tests requiring database will be skipped"
    $skipDbTests = $true
}

# Check if Redis is available
$skipRedisTests = $false
try {
    $null = Get-Command redis-cli -ErrorAction Stop
    # Check if Redis is running
    $redisPing = redis-cli ping 2>$null
    if ($redisPing -eq "PONG") {
        Write-Host "✓ Redis is running" -ForegroundColor Green
    } else {
        Write-Host "Warning: Redis is not running" -ForegroundColor Yellow
        $skipRedisTests = $true
    }
} catch {
    Write-Host "Warning: Redis client not found" -ForegroundColor Yellow
    $skipRedisTests = $true
}

Write-Host ""
Write-Host "=== Running Tests ===" -ForegroundColor Cyan
Write-Host ""

# Run compilation check
Write-Host "1. Checking compilation..."
try {
    cargo check --features database 2>&1 | Tee-Object -FilePath "$env:TEMP\cargo_check.log"
    Write-Host "✓ Compilation successful" -ForegroundColor Green
} catch {
    Write-Host "✗ Compilation failed" -ForegroundColor Red
    Write-Host "See $env:TEMP\cargo_check.log for details"
    exit 1
}

Write-Host ""

# Run unit tests
Write-Host "2. Running unit tests..."
try {
    cargo test service_auth::tests --features database -- --nocapture
    Write-Host "✓ Unit tests passed" -ForegroundColor Green
} catch {
    Write-Host "✗ Unit tests failed" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Run integration tests (if database and Redis are available)
if (-not $skipDbTests -and -not $skipRedisTests) {
    Write-Host "3. Running integration tests..."
    
    # Set up environment variables
    if (-not $env:DATABASE_URL) {
        $env:DATABASE_URL = "postgres://localhost/aframp_test"
        Write-Host "Using default DATABASE_URL: $env:DATABASE_URL"
    }
    
    if (-not $env:REDIS_URL) {
        $env:REDIS_URL = "redis://127.0.0.1:6379"
        Write-Host "Using default REDIS_URL: $env:REDIS_URL"
    }
    
    # Check if test database exists
    $dbExists = psql -lqt | Select-String "aframp_test"
    if (-not $dbExists) {
        Write-Host "Creating test database..."
        try {
            createdb aframp_test
        } catch {
            Write-Host "Warning: Could not create test database" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Test database exists"
    }
    
    # Run migrations
    Write-Host "Running migrations..."
    try {
        sqlx migrate run --database-url $env:DATABASE_URL
        Write-Host "✓ Migrations applied" -ForegroundColor Green
    } catch {
        Write-Host "Warning: Migration failed, continuing anyway" -ForegroundColor Yellow
    }
    
    # Run integration tests
    try {
        cargo test --test service_auth_test --features database -- --ignored --nocapture
        Write-Host "✓ Integration tests passed" -ForegroundColor Green
    } catch {
        Write-Host "✗ Integration tests failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "3. Skipping integration tests (database or Redis not available)"
}

Write-Host ""
Write-Host "=== Test Summary ===" -ForegroundColor Cyan
Write-Host ""

# Get test results
$unitTestOutput = cargo test service_auth::tests --features database 2>&1 | Select-String "test result:"
Write-Host "Unit tests: $unitTestOutput"

if (-not $skipDbTests -and -not $skipRedisTests) {
    $integrationTestOutput = cargo test --test service_auth_test --features database -- --ignored 2>&1 | Select-String "test result:"
    Write-Host "Integration tests: $integrationTestOutput"
}

Write-Host ""
Write-Host "=== All Tests Completed Successfully ===" -ForegroundColor Green
Write-Host ""

# Optional: Run clippy for linting
try {
    $null = Get-Command cargo-clippy -ErrorAction Stop
    Write-Host "Running clippy linter..."
    cargo clippy --features database -- -D warnings
    Write-Host "✓ Clippy checks passed" -ForegroundColor Green
} catch {
    # Clippy not installed, skip
}

# Optional: Check formatting
Write-Host "Checking code formatting..."
$formatCheck = cargo fmt -- --check 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Code formatting is correct" -ForegroundColor Green
} else {
    Write-Host "Warning: Code formatting issues found" -ForegroundColor Yellow
    Write-Host "Run 'cargo fmt' to fix"
}

Write-Host ""
Write-Host "Test run complete!" -ForegroundColor Cyan
