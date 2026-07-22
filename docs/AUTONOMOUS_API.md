# Autonomous payment-intent API

The autonomous API exposes SolGuard's existing fail-closed decision gateway without a
wallet or settlement route. A human configures one mandate and registers the agent's
public identity key. The agent then submits signed canonical payment intents without
payment-by-payment interaction.

This is a hackathon-stage, process-local service. It does not provide production identity
provisioning, durable replay coordination, multi-tenant isolation, wallet key custody, or
blockchain settlement.

## Trust boundary

The agent identity key and wallet settlement key are separate:

```text
Agent Ed25519 key -> authenticates the payment intent
SolGuard authorization -> permits one exact request to approach a wallet
Wallet key -> signs a blockchain transaction in a later isolated component
```

The API can return an authorization after `ALLOW`; it cannot sign or settle. A
`REQUIRE_APPROVAL` decision is returned as `QUARANTINED` and never becomes unattended
approval.

## Configuration

Create a local JSON file containing one registered public identity and one mandate:

```json
{
  "agent_identity": {
    "agent_id": "research-agent-01",
    "key_id": "research-agent-key-01",
    "public_key": "BASE64_ENCODED_32_BYTE_ED25519_PUBLIC_KEY"
  },
  "mandate": {
    "mandate_id": "research-mandate-01",
    "agent_id": "research-agent-01",
    "purpose": "Purchase verified research APIs",
    "asset": "USDC",
    "max_single_payment": "10",
    "allowed_recipients": ["weather-api"],
    "blocked_recipients": ["attacker-wallet"],
    "valid_from": "2026-07-25T09:00:00Z",
    "expires_at": "2026-07-26T00:00:00Z"
  }
}
```

Only the public key belongs in this file. Do not store a private key, seed phrase, wallet
key, bearer token, or RPC credential in the repository.

Run the service:

```bash
uv run solguard-api --config ./autonomous-api.json
```

## Request authentication

Submit the canonical `PaymentRequest` JSON to:

```text
POST /v1/payment-intents/evaluate
Content-Type: application/json
X-SolGuard-Key-Id: research-agent-key-01
X-SolGuard-Signature: <standard-Base64 Ed25519 signature>
```

The signed message is canonical JSON with these fields:

```json
{
  "agent_id": "<request agent_id>",
  "created_at": "<canonical UTC request timestamp>",
  "domain": "solguard-agent-intent-v1",
  "key_id": "<X-SolGuard-Key-Id>",
  "nonce": "<request nonce>",
  "request_digest": "<SHA-256 digest of the canonical PaymentRequest>"
}
```

Use `solguard.agent_auth.sign_agent_request` when the agent runs in Python. The helper
accepts an in-memory `Ed25519PrivateKey` and returns the Base64 signature; it never exports
the private key.

## Response semantics

Every parsed response includes:

- `decision`: `ALLOW`, `REQUIRE_APPROVAL`, or `BLOCK`;
- `execution_state`: `AUTHORIZED`, `QUARANTINED`, or `BLOCKED`;
- stable `reason_codes` and the canonical `request_digest`;
- an authorization only for `ALLOW`; and
- a sanitized hash-linked audit receipt digest for authenticated requests.

Invalid signatures use one generic `AGENT_AUTHENTICATION_FAILED` reason so the response
does not reveal whether a key identifier or signature was wrong. Invalid, unsigned,
expired, replayed, policy-blocked, and internal-failure requests never receive an
authorization.

The response may show that an intent is authorized, but it never claims the intent was
signed, settled, or confirmed on-chain.
