import { sleep } from "k6";
import { commonK6Options } from "../lib/config.js";
import {
  getOnrampStatus,
  getRates,
  postBillsPay,
  postOfframpInitiate,
  postOfframpQuote,
  postOnrampInitiate,
  postOnrampQuote,
} from "../lib/http.js";
import { handleSummary } from "../lib/report.js";

export const options = commonK6Options({
  scenarios: {
    sustained_mixed_traffic: {
      executor: "constant-arrival-rate",
      rate: 45,
      timeUnit: "1s",
      duration: "30m",
      preAllocatedVUs: 80,
      maxVUs: 240,
    },
  },
});

export default function () {
  const r = Math.random();
  if (r < 0.24) postOnrampQuote();
  else if (r < 0.39) postOnrampInitiate();
  else if (r < 0.56) getOnrampStatus();
  else if (r < 0.73) postOfframpQuote();
  else if (r < 0.84) postOfframpInitiate();
  else if (r < 0.91) postBillsPay();
  else getRates();

  sleep(0.2);
}

export { handleSummary };
