#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT_DIR}/load-tests/results/runs"
BASELINE_DIR="${ROOT_DIR}/load-tests/results/baseline"
TIMESTAMP="$(date +"%Y%m%d-%H%M%S")"
INDEX_FILE="${BASELINE_DIR}/${TIMESTAMP}-baseline-index.txt"

mkdir -p "${RESULTS_DIR}" "${BASELINE_DIR}"

scenarios=("sustained" "spike" "stress" "soak")

echo "Running all load test scenarios..." | tee "${INDEX_FILE}"
echo "Timestamp: ${TIMESTAMP}" | tee -a "${INDEX_FILE}"
echo "" | tee -a "${INDEX_FILE}"

for scenario in "${scenarios[@]}"; do
  echo "=== ${scenario} ===" | tee -a "${INDEX_FILE}"
  "${ROOT_DIR}/load-tests/run.sh" "${scenario}"

  latest_run="$(ls -1dt "${RESULTS_DIR}"/*-"${scenario}" | head -n 1)"
  echo "${scenario}: ${latest_run}" | tee -a "${INDEX_FILE}"
done

echo "" | tee -a "${INDEX_FILE}"
echo "Baseline index written to: ${INDEX_FILE}" | tee -a "${INDEX_FILE}"
