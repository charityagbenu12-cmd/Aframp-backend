#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: ./load-tests/run.sh <scenario>"
  echo "Scenarios: sustained | spike | stress | soak"
  exit 1
fi

SCENARIO="$1"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT_DIR}/load-tests/results/runs"
TIMESTAMP="$(date +"%Y%m%d-%H%M%S")"
RUN_DIR="${RESULTS_DIR}/${TIMESTAMP}-${SCENARIO}"

mkdir -p "${RUN_DIR}"

SCRIPT_PATH="${ROOT_DIR}/load-tests/scenarios/${SCENARIO}.js"
if [[ ! -f "${SCRIPT_PATH}" ]]; then
  echo "Unknown scenario '${SCENARIO}'. Expected sustained|spike|stress|soak."
  exit 1
fi

echo "Running k6 scenario: ${SCENARIO}"
echo "Output directory: ${RUN_DIR}"

k6 run \
  --summary-export "${RUN_DIR}/summary.json" \
  --out "json=${RUN_DIR}/metrics.json" \
  "${SCRIPT_PATH}" | tee "${RUN_DIR}/stdout.log"

cp "${ROOT_DIR}/load-tests/results/latest-summary.md" "${RUN_DIR}/summary.md" || true

echo "Completed: ${RUN_DIR}"
