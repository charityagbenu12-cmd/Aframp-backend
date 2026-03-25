# Request Signing & Replay Prevention

Every mutating API request must carry an HMAC signature that binds the request
body, selected headers, and timestamp to a cryptographic value only the
legitimate key holder can produce.  This makes payload tampering immediately
detectable even if an attacker intercepts a valid request in transit.

---

## Required Headers

| Header | Format | Description |
|---|---|---|
| `Content-Type` | `application/json` | Must be included in the canonical request |
| `X-Aframp-Key-Id` | String | Your API key identifier |
| `X-Aframp-Timestamp` | Unix timestamp (seconds) | When the request was signed |
| `X-Aframp-Signature` | See format below | The computed HMAC signature |
| `X-Aframp-Nonce` | UUID v4 or 32-byte hex | Unique per request (replay prevention) |
| `X-Aframp-Consumer` | String | Your consumer ID (replay prevention) |

---

## Signature Header Format

```
X-Aframp-Signature: algorithm=HMAC-SHA256,timestamp=<unix_ts>,signature=<hex>
```

- `algorithm` — `HMAC-SHA256` (standard) or `HMAC-SHA512` (high-value endpoints)
- `timestamp` — same Unix timestamp as `X-Aframp-Timestamp`
- `signature` — lowercase hex-encoded HMAC output

---

## Signing Key Derivation

The signing key is derived from your API secret using HKDF-SHA256.  It is
**never stored or transmitted** — the server re-derives it on every request
from the stored key hash.

```
PRK  = HMAC-SHA256(salt="aframp-hmac-salt-v1", ikm=api_secret)
OKM  = HMAC-SHA256(PRK, info="aframp-request-signing-v1" || 0x01)
```

The derived key is 32 bytes.  Using a dedicated signing key (separate from the
authentication key) limits the blast radius if either key is compromised.

---

## Canonical Request Format

The canonical request is the exact string that is signed.  Every component
must be constructed identically on both the client and the server.

```
{METHOD}\n
{path}\n
{query_string}\n
content-type:{value}\n
x-aframp-key-id:{value}\n
x-aframp-timestamp:{value}\n
{sha256_hex_of_body}
```

### Construction rules

| Component | Rule |
|---|---|
| `METHOD` | Uppercase (`POST`, `GET`, …) |
| `path` | Lowercase; strip trailing `/` except for root `/`; percent-encode consistently |
| `query_string` | Sort `key=value` pairs alphabetically by key, join with `&`; empty string when absent |
| Header lines | `{lowercase_name}:{trimmed_value}` — exactly `content-type`, `x-aframp-key-id`, `x-aframp-timestamp` in that order |
| Body hash | `SHA-256(raw_body_bytes)` hex-encoded lowercase; use SHA-256 of an empty string for requests with no body |

### Annotated example

Request:
```
POST /api/onramp/initiate?ref=abc&locale=en
Content-Type: application/json
X-Aframp-Key-Id: key_prod_abc123
X-Aframp-Timestamp: 1700000000

{"wallet_address":"GXXX","amount":"5000","currency":"KES"}
```

Step 1 — Method:
```
POST
```

Step 2 — Path (lowercase, no trailing slash):
```
/api/onramp/initiate
```

Step 3 — Query string (sorted alphabetically):
```
locale=en&ref=abc
```

Step 4 — Required headers (lowercase name, trimmed value):
```
content-type:application/json
x-aframp-key-id:key_prod_abc123
x-aframp-timestamp:1700000000
```

Step 5 — SHA-256 of body:
```
sha256('{"wallet_address":"GXXX","amount":"5000","currency":"KES"}')
= 3b4c...  (64 hex chars)
```

Step 6 — Concatenate with `\n`:
```
POST\n/api/onramp/initiate\nlocale=en&ref=abc\ncontent-type:application/json\nx-aframp-key-id:key_prod_abc123\nx-aframp-timestamp:1700000000\n3b4c...
```

Step 7 — Derive signing key and compute HMAC-SHA256:
```
signing_key = HKDF(api_secret)
signature   = HMAC-SHA256(signing_key, canonical_request)
```

Step 8 — Set header:
```
X-Aframp-Signature: algorithm=HMAC-SHA256,timestamp=1700000000,signature=<hex>
```

---

## Reference Implementations

### JavaScript / TypeScript

```javascript
import { createHmac, createHash, randomUUID } from 'crypto';

function deriveSigningKey(apiSecret) {
  // HKDF extract
  const prk = createHmac('sha256', 'aframp-hmac-salt-v1')
    .update(apiSecret)
    .digest();
  // HKDF expand T(1)
  const info = Buffer.concat([
    Buffer.from('aframp-request-signing-v1'),
    Buffer.from([0x01]),
  ]);
  return createHmac('sha256', prk).update(info).digest();
}

function buildCanonicalRequest(method, path, query, headers, bodyBytes) {
  const normPath = path.toLowerCase().replace(/\/$/, '') || '/';
  const sortedQuery = query
    .split('&')
    .filter(Boolean)
    .sort()
    .join('&');
  const bodyHash = createHash('sha256').update(bodyBytes).digest('hex');
  const requiredHeaders = ['content-type', 'x-aframp-key-id', 'x-aframp-timestamp'];
  const headerLines = requiredHeaders.map(
    (h) => `${h}:${(headers[h] || '').trim()}`
  );
  return [method.toUpperCase(), normPath, sortedQuery, ...headerLines, bodyHash].join('\n');
}

export function signRequest({ method, url, headers, body, apiSecret }) {
  const parsed = new URL(url);
  const bodyBytes = typeof body === 'string' ? Buffer.from(body) : body ?? Buffer.alloc(0);
  const canonical = buildCanonicalRequest(
    method,
    parsed.pathname,
    parsed.search.slice(1),
    headers,
    bodyBytes
  );
  const signingKey = deriveSigningKey(apiSecret);
  const signature = createHmac('sha256', signingKey).update(canonical).digest('hex');
  const timestamp = headers['x-aframp-timestamp'];
  return `algorithm=HMAC-SHA256,timestamp=${timestamp},signature=${signature}`;
}

// Usage
const timestamp = String(Math.floor(Date.now() / 1000));
const nonce = randomUUID();
const body = JSON.stringify({ wallet_address: 'GXXX', amount: '5000', currency: 'KES' });

const headers = {
  'content-type': 'application/json',
  'x-aframp-key-id': 'key_prod_abc123',
  'x-aframp-timestamp': timestamp,
  'x-aframp-nonce': nonce,
  'x-aframp-consumer': 'consumer_xyz',
};

headers['x-aframp-signature'] = signRequest({
  method: 'POST',
  url: 'https://api.aframp.io/api/onramp/initiate',
  headers,
  body,
  apiSecret: 'your-api-secret',
});

await fetch('https://api.aframp.io/api/onramp/initiate', {
  method: 'POST',
  headers,
  body,
});
```

---

### Python

```python
import hashlib
import hmac as hmac_lib
import time
import uuid
from urllib.parse import urlparse, parse_qs, urlencode

import httpx


def derive_signing_key(api_secret: bytes) -> bytes:
    """HKDF-SHA256 key derivation."""
    salt = b"aframp-hmac-salt-v1"
    info = b"aframp-request-signing-v1"
    prk = hmac_lib.new(salt, api_secret, hashlib.sha256).digest()
    okm = hmac_lib.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm


def build_canonical_request(
    method: str,
    path: str,
    query: str,
    headers: dict[str, str],
    body: bytes,
) -> str:
    norm_path = path.lower().rstrip("/") or "/"
    sorted_query = "&".join(sorted(p for p in query.split("&") if p))
    body_hash = hashlib.sha256(body).hexdigest()
    required = ["content-type", "x-aframp-key-id", "x-aframp-timestamp"]
    header_lines = [f"{h}:{headers.get(h, '').strip()}" for h in required]
    parts = [method.upper(), norm_path, sorted_query] + header_lines + [body_hash]
    return "\n".join(parts)


def sign_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    api_secret: str,
) -> str:
    parsed = urlparse(url)
    canonical = build_canonical_request(
        method, parsed.path, parsed.query, headers, body
    )
    signing_key = derive_signing_key(api_secret.encode())
    signature = hmac_lib.new(signing_key, canonical.encode(), hashlib.sha256).hexdigest()
    timestamp = headers.get("x-aframp-timestamp", "0")
    return f"algorithm=HMAC-SHA256,timestamp={timestamp},signature={signature}"


# Usage
timestamp = str(int(time.time()))
nonce = str(uuid.uuid4())
body = b'{"wallet_address":"GXXX","amount":"5000","currency":"KES"}'

headers = {
    "content-type": "application/json",
    "x-aframp-key-id": "key_prod_abc123",
    "x-aframp-timestamp": timestamp,
    "x-aframp-nonce": nonce,
    "x-aframp-consumer": "consumer_xyz",
}
headers["x-aframp-signature"] = sign_request(
    "POST",
    "https://api.aframp.io/api/onramp/initiate",
    headers,
    body,
    api_secret="your-api-secret",
)

response = httpx.post(
    "https://api.aframp.io/api/onramp/initiate",
    content=body,
    headers=headers,
)
```

---

### Rust (internal microservices)

```rust
use Bitmesh_backend::middleware::hmac_signing::{sign_request, HmacAlgorithm};

let timestamp = chrono::Utc::now().timestamp().to_string();
let body = br#"{"wallet_address":"GXXX","amount":"5000","currency":"KES"}"#;

let headers = &[
    ("content-type", "application/json"),
    ("x-aframp-key-id", "key_prod_abc123"),
    ("x-aframp-timestamp", timestamp.as_str()),
];

let signature_header = sign_request(
    HmacAlgorithm::Sha256,
    "POST",
    "/api/onramp/initiate",
    "",          // query string
    headers,
    body,
    b"your-api-secret",
);

// signature_header == "algorithm=HMAC-SHA256,timestamp=...,signature=<hex>"
```

---

## Postman Pre-Request Script

Paste this into the **Pre-request Script** tab of your Postman collection.
Set `apiSecret` and `keyId` in your Postman environment variables.

```javascript
const apiSecret = pm.environment.get('apiSecret');
const keyId = pm.environment.get('keyId');
const consumerId = pm.environment.get('consumerId');

const timestamp = String(Math.floor(Date.now() / 1000));
const nonce = pm.variables.replaceIn('{{$guid}}');

// Derive signing key (HKDF-SHA256)
function deriveSigningKey(secret) {
  const salt = CryptoJS.enc.Utf8.parse('aframp-hmac-salt-v1');
  const prk = CryptoJS.HmacSHA256(CryptoJS.enc.Utf8.parse(secret), salt);
  const info = CryptoJS.enc.Utf8.parse('aframp-request-signing-v1\x01');
  return CryptoJS.HmacSHA256(info, prk);
}

// Build canonical request
const method = pm.request.method.toUpperCase();
const urlObj = new URL(pm.request.url.toString());
const normPath = urlObj.pathname.toLowerCase().replace(/\/$/, '') || '/';
const sortedQuery = urlObj.search.slice(1).split('&').filter(Boolean).sort().join('&');

const rawBody = pm.request.body ? pm.request.body.raw || '' : '';
const bodyHash = CryptoJS.SHA256(rawBody).toString(CryptoJS.enc.Hex);

const canonical = [
  method,
  normPath,
  sortedQuery,
  `content-type:${(pm.request.headers.get('content-type') || '').trim()}`,
  `x-aframp-key-id:${keyId}`,
  `x-aframp-timestamp:${timestamp}`,
  bodyHash,
].join('\n');

const signingKey = deriveSigningKey(apiSecret);
const signature = CryptoJS.HmacSHA256(canonical, signingKey).toString(CryptoJS.enc.Hex);

pm.request.headers.add({ key: 'X-Aframp-Key-Id',     value: keyId });
pm.request.headers.add({ key: 'X-Aframp-Timestamp',  value: timestamp });
pm.request.headers.add({ key: 'X-Aframp-Nonce',      value: nonce });
pm.request.headers.add({ key: 'X-Aframp-Consumer',   value: consumerId });
pm.request.headers.add({
  key: 'X-Aframp-Signature',
  value: `algorithm=HMAC-SHA256,timestamp=${timestamp},signature=${signature}`,
});
```

---

## Error Responses

| Code | HTTP | Meaning |
|---|---|---|
| `MISSING_SIGNATURE` | 401 | `X-Aframp-Signature` header absent |
| `INVALID_SIGNATURE_FORMAT` | 401 | Header does not match `algorithm=…,timestamp=…,signature=…` |
| `MISSING_KEY_ID` | 401 | `X-Aframp-Key-Id` header absent |
| `UNKNOWN_KEY_ID` | 401 | Key ID not recognised |
| `MISSING_REQUIRED_HEADER` | 401 | One of `content-type`, `x-aframp-key-id`, or `x-aframp-timestamp` is absent |
| `SIGNATURE_MISMATCH` | 401 | Computed signature does not match — body or headers were tampered |
| `BODY_TOO_LARGE` | 401 | Request body exceeds 1 MiB signing limit |
| `MISSING_TIMESTAMP` | 401 | `X-Aframp-Timestamp` header absent (replay prevention) |
| `MISSING_NONCE` | 401 | `X-Aframp-Nonce` header absent (replay prevention) |
| `INVALID_TIMESTAMP` | 401 | Timestamp is not a valid integer |
| `TIMESTAMP_TOO_OLD` | 401 | Request is older than the allowed window (default 5 min) |
| `TIMESTAMP_IN_FUTURE` | 401 | Request timestamp is too far ahead of server time (default 30 s) |
| `REPLAY_DETECTED` | 401 | Nonce has already been used |
| `NONCE_STORE_UNAVAILABLE` | 503 | Transient Redis error — retry with a **new** nonce |

---

## Timestamp & Nonce Rules

- `X-Aframp-Timestamp` must be within **±5 minutes** of server time.
- `X-Aframp-Nonce` must be unique per request (UUID v4 or 32-byte hex, ≥128 bits entropy).
- The nonce is stored server-side for `timestamp_window + 60 s`.  Never reuse nonces.

## Environment Variables (Server-Side)

| Variable | Default | Description |
|---|---|---|
| `REPLAY_TIMESTAMP_WINDOW_SECS` | 300 | Max request age in seconds |
| `REPLAY_FUTURE_TOLERANCE_SECS` | 30 | Max future skew in seconds |
| `REPLAY_NONCE_TTL_BUFFER_SECS` | 60 | Extra Redis TTL buffer beyond the window |
| `REPLAY_CLOCK_SKEW_ALERT_SECS` | 60 | Clock skew delta that triggers a warning log |
| `REPLAY_ATTEMPT_ALERT_THRESHOLD` | 5 | Replay attempts per consumer before alerting |
