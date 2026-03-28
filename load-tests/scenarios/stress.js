import { sleep } from "k6";
import { commonK6Options } from "../lib/config.js";
import {
  getOnrampStatus,
  getRates,
  postOfframpInitiate,
  postOfframpQuote,
  postOnrampInitiate,
  postOnrampQuote,
} from "../lib/http.js";
import { handleSummary } from "../lib/report.js";

export const options = commonK6Options({
  scenarios: {
    ramp_until_failure: {
      executor: "ramping-arrival-rate",
      startRate: 20,
      timeUnit: "1s",
      preAllocatedVUs: 100,
      maxVUs: 1200,
      stages: [
        { target: 40, duration: "5m" },
        { target: 80, duration: "5m" },
        { target: 140, duration: "5m" },
        { target: 220, duration: "5m" },
        { target: 320, duration: "5m" },
      ],
    },
  },
});

export default function () {
  const r = Math.random();
  if (r < 0.26) postOnrampQuote();
  else if (r < 0.43) postOnrampInitiate();
  else if (r < 0.62) postOfframpQuote();
  else if (r < 0.76) postOfframpInitiate();
  else if (r < 0.91) getOnrampStatus();
  else getRates();

  sleep(0.05);
}

export { handleSummary };
