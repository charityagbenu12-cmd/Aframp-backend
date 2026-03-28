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
    soak_moderate_load: {
      executor: "constant-arrival-rate",
      rate: 25,
      timeUnit: "1s",
      duration: "2h",
      preAllocatedVUs: 70,
      maxVUs: 220,
    },
  },
});

export default function () {
  const r = Math.random();
  if (r < 0.2) postOnrampQuote();
  else if (r < 0.33) postOnrampInitiate();
  else if (r < 0.47) getOnrampStatus();
  else if (r < 0.61) postOfframpQuote();
  else if (r < 0.72) postOfframpInitiate();
  else if (r < 0.82) postBillsPay();
  else getRates();

  sleep(0.3);
}

export { handleSummary };
