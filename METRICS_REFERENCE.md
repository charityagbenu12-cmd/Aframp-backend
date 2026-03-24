# Aframp Backend — Prometheus Metrics Reference

All metrics are exposed at `GET /metrics` in [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).

Every metric name is prefixed with `aframp_` and follows Prometheus naming conventions (snake_case, unit suffix where applicable).

---

## HTTP Request Metrics

| Name | Type | Labels | Description |
|------|------|--------|-------------|
| `aframp_http_requests_total` | Counter | `method`, `route`, `status_code` | Total HTTP requests received |
| `aframp_http_request_duration_seconds` | Histogram | `method`, `route` | HTTP request processing duration in seconds |
| `aframp_http_requests_in_flight` | Gauge | `route` | Number of HTTP requests currently being processed |

**Label values:**
- `method`: HTTP verb — `GET`, `POST`, `PATCH`, etc.
- `route`: Axum matched path template — e.g. `/api/onramp/quote`
- `status_code`: HTTP response status as string — e.g. `200`, `404`, `500`

---

## cNGN Transaction Metrics

| Name | Type | Labels | Description |
|------|------|--------|-------------|
| `aframp_cngn_transactions_total` | Counter | `tx_type`, `status` | Total cNGN transactions by type and status |
| `aframp_cngn_transaction_volume_ngn` | Histogram | `tx_type` | cNGN transaction amounts in NGN |
| `aframp_cngn_transaction_duration_seconds` | Histogram | `tx_type` | Transaction processing duration from initiation to completion |

**Label values:**
- `tx_type`: `onramp` | `offramp` | `bill_payment`
- `status`: `completed` | `failed` | `refunded`

**Histogram buckets — volume (NGN):** 100, 500, 1 000, 5 000, 10 000, 50 000, 100 000, 500 000, 1 000 000

**Histogram buckets — duration (seconds):** 1, 5, 15, 30, 60, 120, 300, 600, 1 800

---

## Payment Provider Metrics

| Name | Type | Labels | Description |
|------|------|--------|-------------|
| `aframp_payment_provider_requests_total` | Counter | `provider`, `operation` | Total payment provider API requests |
| `aframp_payment_provider_request_duration_seconds` | Histogram | `provider`, `operation` | Payment provider request duration in seconds |
| `aframp_payment_provider_failures_total` | Counter | `provider`, `failure_reason` | Total payment provider failures |

**Label values:**
- `provider`: `paystack` | `flutterwave` | `mpesa`
- `operation`: `initiate` | `verify` | `withdraw`
- `failure_reason`: error message string from the provider

**Histogram buckets (seconds):** 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30

---

## Stellar Service Metrics

| Name | Type | Labels | Description |
|------|------|--------|-------------|
| `aframp_stellar_tx_submissions_total` | Counter | `status` | Total Stellar transaction submissions |
| `aframp_stellar_tx_submission_duration_seconds` | Histogram | _(none)_ | Stellar transaction submission duration in seconds |
| `aframp_stellar_trustline_attempts_total` | Counter | `status` | Total trustline creation attempts |

**Label values:**
- `status` (submissions): `success` | `failed`
- `status` (trustlines): `success` | `failed` | `already_exists`

**Histogram buckets (seconds):** 0.1, 0.5, 1, 2, 5, 10, 20, 30

---

## Background Worker Metrics

| Name | Type | Labels | Description |
|------|------|--------|-------------|
| `aframp_worker_cycles_total` | Counter | `worker` | Total background worker processing cycles |
| `aframp_worker_cycle_duration_seconds` | Histogram | `worker` | Worker cycle duration in seconds |
| `aframp_worker_records_processed` | Gauge | `worker` | Records processed in the last worker cycle |
| `aframp_worker_errors_total` | Counter | `worker`, `error_type` | Total worker errors by type |

**Label values:**
- `worker`: `onramp_processor` | `offramp_processor` | `transaction_monitor` | `webhook_retry` | `bill_processor`
- `error_type`: descriptive error string — e.g. `timeout`, `stellar_error`, `database`, `trustline_not_found`

**Histogram buckets (seconds):** 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60

---

## Redis Cache Metrics

| Name | Type | Labels | Description |
|------|------|--------|-------------|
| `aframp_cache_hits_total` | Counter | `key_prefix` | Total Redis cache hits |
| `aframp_cache_misses_total` | Counter | `key_prefix` | Total Redis cache misses |
| `aframp_cache_operation_duration_seconds` | Histogram | `operation` | Redis operation duration in seconds |

**Label values:**
- `key_prefix`: first colon-delimited segment of the Redis key — e.g. `rates`, `wallet`, `quote`, `fees`
- `operation`: `get` | `set` | `delete`

**Histogram buckets (seconds):** 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5

---

## Database Metrics

| Name | Type | Labels | Description |
|------|------|--------|-------------|
| `aframp_db_query_duration_seconds` | Histogram | `query_type`, `table` | Database query duration in seconds |
| `aframp_db_connections_active` | Gauge | `pool` | Active connections in the database pool |
| `aframp_db_errors_total` | Counter | `error_type` | Total database errors |

**Label values:**
- `query_type`: `select` | `insert` | `update` | `delete`
- `table`: table name — e.g. `transactions`, `wallets`, `exchange_rates`
- `pool`: `primary`
- `error_type`: `connection_error` | `query_error` | `timeout` | `constraint_violation`

**Histogram buckets (seconds):** 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5

---

## Scrape Configuration Example

```yaml
# prometheus.yml
scrape_configs:
  - job_name: aframp_backend
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: /metrics
    scrape_interval: 15s
```
