# Request Signing & Replay Prevention

Every signed API request must include three security headers. HMAC signature
verification alone does not prevent replay attacks — a correctly signed request
captured by an attacker is still a correctly signed request. The platform
combines timestamp validation with server-side nonce tracking so that each
signed request can only be processed **exactly once**.

## Required Headers

| Header | Format | Description |
|---|---|---|
| `X-Aframp-Timestamp` | Unix timestamp (seconds) | When the request was signed |
| `X-Aframp-Nonce` | UUID v4 or 32-byte hex | Unique random value per request |
| `X-Aframp-Consumer` | String | Your consumer ID |

## Timestamp Rules

- The timestamp must be within **±5 minutes** of server time (configurable via `REPLAY_TIMESTAMP_WINDOW_SECS`).
- Requests older than the window are rejected with `401 TIMESTAMP_TOO_OLD`.
- Requests more than 30 seconds in the future are rejected with `401 TIMESTAMP_IN_FUTURE`.
- Always use a reliable time source. If your clock is consistently skewed, the platform will emit a warning.

## Nonce Rules

- Must be **unique per request** — never reuse a nonce.
- Accepted formats: UUID v4 (e.g. `550e8400-e29b-41d4-a716-446655440000`) or a 32-byte cryptographically random hex string.
- Minimum entropy: 128 bits.
- The nonce is stored server-side for `timestamp_window + 60 seconds`. After that window, the nonce expires and the same value could theoretically be reused — but you should never reuse nonces regardless.
- A replayed nonce is rejected with `401 REPLAY_DETECTED`.

## Canonical Request String

The nonce **must** be included in the canonical request string that is signed.
This ensures a request with a swapped nonce fails signature verification.

```
METHOD\n
/path/to/endpoint\n
X-Aframp-Timestamp:<timestamp>\n
X-Aframp-Nonce:<nonce>\n
X-Aframp-Consumer:<consumer_id>\n
<sha256_hex_of_request_body>
```

---

## Nonce Generation Reference Implementations

### JavaScript / TypeScript

```javascript
// UUID v4 (Node.js 14.17+ / all modern browsers)
const nonce = crypto.randomUUID();

// 32-byte hex alternative (Node.js)
import { randomBytes } from 'crypto';
const nonce = randomBytes(32).toString('hex');

// Full signed request example
async function signedFetch(url, body, consumerSecret, consumerId) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomUUID();
  const bodyHash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(body)
  );
  const bodyHashHex = Array.from(new Uint8Array(bodyHash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  const method = 'POST';
  const path = new URL(url).pathname;
  const canonical = [
    method,
    path,
    `X-Aframp-Timestamp:${timestamp}`,
    `X-Aframp-Nonce:${nonce}`,
    `X-Aframp-Consumer:${consumerId}`,
    bodyHashHex,
  ].join('\n');

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(consumerSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(canonical));
  const signature = Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-Aframp-Timestamp': timestamp,
      'X-Aframp-Nonce': nonce,
      'X-Aframp-Consumer': consumerId,
      'X-Aframp-Signature': signature,
    },
    body,
  });
}
```

### Python

```python
import hashlib
import hmac
import time
import uuid
import secrets
import httpx

def generate_nonce() -> str:
    """UUID v4 nonce — 122 bits of entropy."""
    return str(uuid.uuid4())

def generate_nonce_hex() -> str:
    """32-byte hex nonce — 256 bits of entropy."""
    return secrets.token_hex(32)

def signed_request(
    method: str,
    url: str,
    body: bytes,
    consumer_id: str,
    consumer_secret: str,
) -> httpx.Response:
    timestamp = str(int(time.time()))
    nonce = generate_nonce()
    body_hash = hashlib.sha256(body).hexdigest()
    path = httpx.URL(url).path

    canonical = "\n".join([
        method.upper(),
        path,
        f"X-Aframp-Timestamp:{timestamp}",
        f"X-Aframp-Nonce:{nonce}",
        f"X-Aframp-Consumer:{consumer_id}",
        body_hash,
    ])

    signature = hmac.new(
        consumer_secret.encode(),
        canonical.encode(),
        hashlib.sha256,
    ).hexdigest()

    return httpx.post(
        url,
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Aframp-Timestamp": timestamp,
            "X-Aframp-Nonce": nonce,
            "X-Aframp-Consumer": consumer_id,
            "X-Aframp-Signature": signature,
        },
    )
```

### Rust

```rust
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Generate a UUID v4 nonce.
pub fn generate_nonce() -> String {
    Uuid::new_v4().to_string()
}

/// Generate a 32-byte cryptographically random hex nonce.
pub fn generate_nonce_hex() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn sign_request(
    method: &str,
    path: &str,
    body: &[u8],
    consumer_id: &str,
    consumer_secret: &str,
) -> (String, String, String) {
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let nonce = generate_nonce();

    let body_hash = hex::encode(Sha256::digest(body));
    let canonical = format!(
        "{}\n{}\nX-Aframp-Timestamp:{}\nX-Aframp-Nonce:{}\nX-Aframp-Consumer:{}\n{}",
        method.to_uppercase(),
        path,
        timestamp,
        nonce,
        consumer_id,
        body_hash,
    );

    let mut mac = HmacSha256::new_from_slice(consumer_secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    (timestamp, nonce, signature)
}
```

---

## Error Responses

| Code | HTTP | Meaning |
|---|---|---|
| `MISSING_TIMESTAMP` | 401 | `X-Aframp-Timestamp` header absent |
| `MISSING_NONCE` | 401 | `X-Aframp-Nonce` header absent |
| `INVALID_TIMESTAMP` | 401 | Timestamp is not a valid integer |
| `TIMESTAMP_TOO_OLD` | 401 | Request is older than the allowed window |
| `TIMESTAMP_IN_FUTURE` | 401 | Request timestamp is too far ahead of server time |
| `REPLAY_DETECTED` | 401 | Nonce has already been used |
| `NONCE_STORE_UNAVAILABLE` | 503 | Transient Redis error — safe to retry with a **new** nonce |

## Environment Variables (Server-Side)

| Variable | Default | Description |
|---|---|---|
| `REPLAY_TIMESTAMP_WINDOW_SECS` | 300 | Max request age in seconds |
| `REPLAY_FUTURE_TOLERANCE_SECS` | 30 | Max future skew in seconds |
| `REPLAY_NONCE_TTL_BUFFER_SECS` | 60 | Extra Redis TTL buffer beyond the window |
| `REPLAY_CLOCK_SKEW_ALERT_SECS` | 60 | Clock skew delta that triggers a warning log |
| `REPLAY_ATTEMPT_ALERT_THRESHOLD` | 5 | Replay attempts per consumer before alerting |
