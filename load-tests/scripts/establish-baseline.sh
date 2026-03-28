#!/bin/bash

# Load Testing Baseline Establishment Script
# This script runs all load test scenarios and establishes performance baselines

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULTS_DIR="${ROOT_DIR}/results/baseline"
TIMESTAMP="$(date +"%Y%m%d-%H%M%S")"
BASELINE_NAME="baseline-${TIMESTAMP}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if k6 is installed
    if ! command -v k6 &> /dev/null; then
        error "k6 is not installed. Please install k6 first."
        echo "Installation instructions: https://k6.io/docs/getting-started/installation/"
        exit 1
    fi
    
    # Check if environment is configured
    if [ ! -f "${ROOT_DIR}/environments/load.env" ]; then
        warning "Load testing environment file not found. Using example file."
        if [ -f "${ROOT_DIR}/environments/load.env.example" ]; then
            cp "${ROOT_DIR}/environments/load.env.example" "${ROOT_DIR}/environments/load.env"
            warning "Please configure ${ROOT_DIR}/environments/load.env with your load testing environment details."
        else
            error "No environment configuration found."
            exit 1
        fi
    fi
    
    success "Prerequisites check passed"
}

# Load environment variables
load_environment() {
    log "Loading environment configuration..."
    
    if [ -f "${ROOT_DIR}/environments/load.env" ]; then
        set -a
        source "${ROOT_DIR}/environments/load.env"
        set +a
        success "Environment loaded from ${ROOT_DIR}/environments/load.env"
    else
        warning "No environment file found, using defaults"
    fi
}

# Create baseline directory
create_baseline_dir() {
    log "Creating baseline directory: ${RESULTS_DIR}/${BASELINE_NAME}"
    
    mkdir -p "${RESULTS_DIR}/${BASELINE_NAME}"
    
    # Create metadata file
    cat > "${RESULTS_DIR}/${BASELINE_NAME}/metadata.json" << EOF
{
  "baseline_name": "${BASELINE_NAME}",
  "timestamp": "${TIMESTAMP}",
  "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "environment": "${BASE_URL:-localhost}",
  "k6_version": "$(k6 version | grep -o 'v[0-9.]*' | head -1)",
  "scenarios": [],
  "summary": {}
}
EOF
    
    success "Baseline directory created"
}

# Run individual scenario
run_scenario() {
    local scenario=$1
    local description=$2
    
    log "Running ${description}..."
    
    # Run the scenario
    if "${ROOT_DIR}/run.sh" "${scenario}"; then
        success "${description} completed successfully"
        
        # Find the latest results
        local latest_run=$(find "${ROOT_DIR}/results/runs" -type d -name "*-${scenario}" | sort -r | head -n 1)
        
        if [ -n "${latest_run}" ]; then
            # Copy results to baseline
            cp -r "${latest_run}" "${RESULTS_DIR}/${BASELINE_NAME}/${scenario}"
            
            # Extract key metrics
            if [ -f "${latest_run}/summary.json" ]; then
                jq -r '
                {
                  scenario: "'${scenario}'",
                  total_requests: .metrics.http_reqs.values.count,
                  error_rate: (.metrics.http_req_failed.values.rate * 100),
                  p95_response_time: .metrics.http_req_duration.values["p(95)"],
                  p99_response_time: .metrics.http_req_duration.values["p(99)"],
                  throughput: .metrics.http_reqs.values.rate,
                  duration: .state.testRunDuration
                }
                ' "${latest_run}/summary.json" > "${RESULTS_DIR}/${BASELINE_NAME}/${scenario}/metrics.json"
                
                success "Metrics extracted for ${scenario}"
            fi
        else
            error "No results found for ${scenario}"
            return 1
        fi
    else
        error "${description} failed"
        return 1
    fi
}

# Run all scenarios
run_all_scenarios() {
    log "Starting baseline establishment with all scenarios..."
    
    local scenarios=(
        "sustained:Sustained Load Test (30 minutes)"
        "spike:Spike Load Test (14 minutes)"
        "stress:Stress Test (25 minutes)"
        "soak:Soak Test (2 hours)"
    )
    
    local failed_scenarios=()
    local successful_scenarios=()
    
    for scenario_desc in "${scenarios[@]}"; do
        IFS=':' read -r scenario description <<< "${scenario_desc}"
        
        if run_scenario "${scenario}" "${description}"; then
            successful_scenarios+=("${scenario}")
        else
            failed_scenarios+=("${scenario}")
        fi
        
        # Add delay between scenarios
        log "Waiting 2 minutes before next scenario..."
        sleep 120
    done
    
    # Update metadata
    local metadata_file="${RESULTS_DIR}/${BASELINE_NAME}/metadata.json"
    
    # Add successful scenarios to metadata
    for scenario in "${successful_scenarios[@]}"; do
        jq --arg scenario "$scenario" '.scenarios += [$scenario]' "${metadata_file}" > temp.json && mv temp.json "${metadata_file}"
    done
    
    # Generate summary
    generate_baseline_summary
    
    # Report results
    log "Baseline establishment completed"
    
    if [ ${#failed_scenarios[@]} -eq 0 ]; then
        success "All scenarios completed successfully"
        success "Baseline created: ${RESULTS_DIR}/${BASELINE_NAME}"
    else
        warning "Some scenarios failed: ${failed_scenarios[*]}"
        warning "Baseline created with partial data: ${RESULTS_DIR}/${BASELINE_NAME}"
    fi
    
    return ${#failed_scenarios[@]}
}

# Generate baseline summary
generate_baseline_summary() {
    log "Generating baseline summary..."
    
    local summary_file="${RESULTS_DIR}/${BASELINE_NAME}/baseline-summary.md"
    
    cat > "${summary_file}" << EOF
# Performance Baseline: ${BASELINE_NAME}

**Created**: $(date)
**Environment**: ${BASE_URL:-localhost}
**k6 Version**: $(k6 version | grep -o 'v[0-9.]*' | head -1)

## Test Scenarios

EOF
    
    # Add scenario results
    for scenario in sustained spike stress soak; do
        if [ -f "${RESULTS_DIR}/${BASELINE_NAME}/${scenario}/metrics.json" ]; then
            local total_requests=$(jq -r '.total_requests' "${RESULTS_DIR}/${BASELINE_NAME}/${scenario}/metrics.json")
            local error_rate=$(jq -r '.error_rate' "${RESULTS_DIR}/${BASELINE_NAME}/${scenario}/metrics.json")
            local p95=$(jq -r '.p95_response_time' "${RESULTS_DIR}/${BASELINE_NAME}/${scenario}/metrics.json")
            local p99=$(jq -r '.p99_response_time' "${RESULTS_DIR}/${BASELINE_NAME}/${scenario}/metrics.json")
            local throughput=$(jq -r '.throughput' "${RESULTS_DIR}/${BASELINE_NAME}/${scenario}/metrics.json")
            
            cat >> "${summary_file}" << EOF
### ${scenario^} Test

- **Total Requests**: ${total_requests}
- **Error Rate**: ${error_rate}%
- **P95 Response Time**: ${p95}ms
- **P99 Response Time**: ${p99}ms
- **Throughput**: ${throughput} RPS

EOF
        fi
    done
    
    # Add performance assessment
    cat >> "${summary_file}" << EOF
## Performance Assessment

This baseline represents the current performance characteristics of the system under test. Use this as a reference point for:

- Performance regression detection
- Capacity planning
- SLA validation
- System optimization efforts

## Comparison Guidelines

When comparing future test results with this baseline:

1. **Response Time**: P95 should not increase by more than 20%
2. **Error Rate**: Should remain below 2%
3. **Throughput**: Should not decrease by more than 10%
4. **Resource Usage**: Memory and CPU should remain stable

## Notes

- This baseline was established on $(date)
- All tests were run against ${BASE_URL:-localhost}
- Ensure consistent test conditions when comparing results

EOF
    
    success "Baseline summary generated: ${summary_file}"
}

# Cleanup old baselines
cleanup_old_baselines() {
    log "Cleaning up old baselines (keeping last 5)..."
    
    local baseline_count=$(find "${RESULTS_DIR}" -maxdepth 1 -type d -name "baseline-*" | wc -l)
    
    if [ "${baseline_count}" -gt 5 ]; then
        find "${RESULTS_DIR}" -maxdepth 1 -type d -name "baseline-*" | sort -r | tail -n +6 | xargs rm -rf
        success "Old baselines cleaned up"
    else
        log "No cleanup needed (${baseline_count} baselines)"
    fi
}

# Main execution
main() {
    log "Starting load testing baseline establishment"
    log "Baseline name: ${BASELINE_NAME}"
    
    # Check prerequisites
    check_prerequisites
    
    # Load environment
    load_environment
    
    # Create baseline directory
    create_baseline_dir
    
    # Run all scenarios
    if run_all_scenarios; then
        success "Baseline establishment completed successfully"
    else
        warning "Baseline establishment completed with some failures"
    fi
    
    # Cleanup old baselines
    cleanup_old_baselines
    
    # Display results
    log "Baseline location: ${RESULTS_DIR}/${BASELINE_NAME}"
    log "Summary file: ${RESULTS_DIR}/${BASELINE_NAME}/baseline-summary.md"
    
    success "Baseline establishment script completed"
}

# Handle script interruption
trap 'error "Script interrupted"; exit 1' INT TERM

# Run main function
main "$@"