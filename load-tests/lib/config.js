export const DEFAULT_HEADERS = {
  "Content-Type": "application/json",
};

export const BASE_URL = __ENV.BASE_URL || "http://localhost:8000";
export const API_KEY = __ENV.LOAD_TEST_API_KEY || "";
export const TEST_WALLET_ADDRESS =
  __ENV.TEST_WALLET_ADDRESS ||
  "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
export const TEST_TX_ID = __ENV.TEST_TX_ID || "tx-load-test-placeholder";

export const TARGETS = JSON.parse(open("../config/targets.json"));

export function requestHeaders() {
  if (!API_KEY) {
    return DEFAULT_HEADERS;
  }
  return {
    ...DEFAULT_HEADERS,
    Authorization: `Bearer ${API_KEY}`,
  };
}

export function endpointThresholds() {
  const thresholds = {
    http_req_failed: [`rate<${TARGETS.global.max_error_rate}`],
  };

  for (const [key, target] of Object.entries(TARGETS.endpoints)) {
    thresholds[`http_req_duration{endpoint:${key}}`] = [`p(95)<${target.p95_ms}`];
    thresholds[`endpoint_reqs{endpoint:${key}}`] = [
      `rate<${target.max_throughput_rps}`,
    ];
    thresholds[`checks{endpoint:${key}}`] = ["rate>0.98"];
  }
  return thresholds;
}

export function commonK6Options(overrides = {}) {
  return {
    thresholds: endpointThresholds(),
    summaryTrendStats: ["avg", "min", "med", "p(50)", "p(95)", "p(99)", "max"],
    ...overrides,
  };
}
