# Aframp API — Quick Start

## Authentication

All authenticated endpoints require a JWT bearer token in the `Authorization` header:

```
Authorization: Bearer <your_jwt_token>
```

Tokens are obtained from the authentication service. Contact the platform operator for
credentials. Include the token on every request that requires authentication.

## Making Your First Quote Request

```bash
curl -X POST https://api.aframp.example.com/api/onramp/quote \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_jwt_token>" \
  -d '{
    "amount_ngn": "10000",
    "wallet_address": "<YOUR_STELLAR_WALLET>",
    "provider": "paystack",
    "chain": "stellar"
  }'
```

The response includes a `quote_id` that expires in 5 minutes. Use it immediately in the
`/api/onramp/initiate` request.

## Checking Transaction Status

```bash
curl https://api.aframp.example.com/api/onramp/status/<transaction_id> \
  -H "Authorization: Bearer <your_jwt_token>"
```

Poll this endpoint until `status` transitions to `completed` or `failed`.

## cNGN Trustline Requirement

Your Stellar wallet must have an active cNGN trustline before receiving cNGN.
See the [cNGN Integration Guide](/docs/cngn/wallet-setup.md) for setup instructions.

## Rate Limits

| Tier | Requests per minute |
|---|---|
| Default | 60 |
| Partner | 300 |
| Admin | Unlimited |

## Support

For integration support, file an issue at the project repository.
