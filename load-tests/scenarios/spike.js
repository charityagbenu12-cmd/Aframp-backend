import { sleep } from "k6";
import { commonK6Options } from "../lib/config.js";
import {
  postOfframpInitiate,
  postOfframpQuote,
  postOnrampInitiate,
  postOnrampQuote,
} from "../lib/http.js";
import { handleSummary } from "../lib/report.js";

export const options = commonK6Options({
  scenarios: {
    spike_quotes_and_initiates: {
      executor: "ramping-arrival-rate",
      startRate: 25,
      timeUnit: "1s",
      preAllocatedVUs: 120,
      maxVUs: 600,
      stages: [
        { target: 25, duration: "2m" },
        { target: 250, duration: "3m" },
        { target: 250, duration: "5m" },
        { target: 35, duration: "4m" },
      ],
    },
  },
});

export default function () {
  const r = Math.random();
  if (r < 0.4) postOnrampQuote();
  else if (r < 0.7) postOnrampInitiate();
  else if (r < 0.9) postOfframpQuote();
  else postOfframpInitiate();
  sleep(0.1);
}

export { handleSummary };
