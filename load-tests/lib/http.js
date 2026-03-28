import http from "k6/http";
import { check } from "k6";
import { Counter, Rate } from "k6/metrics";
import { BASE_URL, TEST_TX_ID, TEST_WALLET_ADDRESS, requestHeaders } from "./config.js";

export const endpointReqs = new Rate("endpoint_reqs");
export const endpointSuccess = new Rate("endpoint_success");
export const endpointFailures = new Counter("endpoint_failures");

function markResult(res, endpointTag) {
  const tags = { endpoint: endpointTag };
  endpointReqs.add(1, tags);
  const ok = res.status >= 200 && res.status < 400;
  endpointSuccess.add(ok ? 1 : 0, tags);
  if (!ok) {
    endpointFailures.add(1, tags);
  }

  check(
    res,
    {
      "status is success": () => ok,
      "response time under 2s": (r) => r.timings.duration < 2000,
    },
    tags,
  );
}

export function postOnrampQuote() {
  const payload = {
    amount_ngn: "50000",
    wallet_address: TEST_WALLET_ADDRESS,
    provider: "flutterwave",
    chain: "stellar",
  };
  const res = http.post(`${BASE_URL}/api/onramp/quote`, JSON.stringify(payload), {
    headers: requestHeaders(),
    tags: { endpoint: "onramp_quote" },
  });
  markResult(res, "onramp_quote");
}

export function postOnrampInitiate() {
  const payload = {
    quote_id: "load-test-quote-id",
    wallet_address: TEST_WALLET_ADDRESS,
    provider: "flutterwave",
  };
  const res = http.post(
    `${BASE_URL}/api/onramp/initiate`,
    JSON.stringify(payload),
    {
      headers: requestHeaders(),
      tags: { endpoint: "onramp_initiate" },
    },
  );
  markResult(res, "onramp_initiate");
}

export function getOnrampStatus() {
  const res = http.get(`${BASE_URL}/api/onramp/status/${TEST_TX_ID}`, {
    headers: requestHeaders(),
    tags: { endpoint: "onramp_status" },
  });
  markResult(res, "onramp_status");
}

export function postOfframpQuote() {
  const payload = {
    amount_cngn: "1000",
    wallet_address: TEST_WALLET_ADDRESS,
    bank_code: "058",
    account_number: "0123456789",
  };
  const res = http.post(`${BASE_URL}/api/offramp/quote`, JSON.stringify(payload), {
    headers: requestHeaders(),
    tags: { endpoint: "offramp_quote" },
  });
  markResult(res, "offramp_quote");
}

export function postOfframpInitiate() {
  const payload = {
    quote_id: "load-test-offramp-quote-id",
    wallet_address: TEST_WALLET_ADDRESS,
    bank_details: {
      bank_code: "058",
      account_number: "0123456789",
      account_name: "Load Test User",
    },
  };
  const res = http.post(
    `${BASE_URL}/api/offramp/initiate`,
    JSON.stringify(payload),
    {
      headers: requestHeaders(),
      tags: { endpoint: "offramp_initiate" },
    },
  );
  markResult(res, "offramp_initiate");
}

export function postBillsPay() {
  const payload = {
    wallet_address: TEST_WALLET_ADDRESS,
    provider: "ekedc",
    account_number: "1234567890",
    amount: "5000",
    asset: "cNGN",
  };
  const res = http.post(`${BASE_URL}/api/bills/pay`, JSON.stringify(payload), {
    headers: requestHeaders(),
    tags: { endpoint: "bills_pay" },
  });
  markResult(res, "bills_pay");
}

export function getRates() {
  const res = http.get(`${BASE_URL}/api/rates?from=USD&to=NGN`, {
    headers: requestHeaders(),
    tags: { endpoint: "rates" },
  });
  markResult(res, "rates");
}
