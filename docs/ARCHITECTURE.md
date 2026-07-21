# SolGuard Architecture

## 1. Objective

SolGuard is a pre-signing authorization gateway for autonomous-agent payments. Its security boundary ends before the wallet signer: a transaction may proceed only when the gateway returns an authenticated `ALLOW` decision for the exact request under evaluation.

The prototype must demonstrate three properties:

1. A legitimate payment can complete through the gateway.
2. A malicious payment is stopped before a signature exists.
3. Every decision can be explained and reproduced from recorded inputs.

## 2. Trust boundaries

```text
Untrusted                         Controlled                    External
-----------------------          --------------------------    ----------------
Agent prompt / tools      --->    SolGuard gateway       --->  Wallet signer
Payment metadata                 Mandate store                  Payment protocol
Recipient quote                  Detection state               Sandbox settlement
Protocol response                Nonce store
                                  Audit receipts
```

The agent, payment metadata, merchant quote, recipient, and protocol response are treated as untrusted. The wallet signer trusts only a valid SolGuard authorization bound to the exact payment request.

## 3. Request lifecycle

### 3.1 Normalize

Protocol adapters convert Pay.sh, x402, or synthetic traffic into a canonical payment request. Values are parsed using fixed-precision decimal types. Unknown or malformed fields cause a fail-closed decision.

### 3.2 Bind intent

The request is matched to an active Agent Financial Mandate. The binding covers agent, purpose, recipient, asset, maximum value, expiry, and authorization identifier.

### 3.3 Sanitize metadata

Sensitive values are redacted before persistence or display. The original request is not mutated for signing; instead, the sanitizer creates a safe observability representation.

### 3.4 Verify integrity

The basic request integrity guard currently validates:

- A non-empty canonical request nonce
- Request expiry at the exact gateway-clock boundary
- Atomic, per-agent nonce consumption
- Replay rejection before policy, detection, or settlement

Canonical request digests bind later decisions and simulated settlement to the exact request. Mandate-expiry enforcement, durable replay coordination, and wallet-bound single-use authorization remain separate controls rather than hidden behavior in this basic guard.

### 3.5 Enforce hard policy

The policy engine evaluates deterministic controls, including per-payment limits, cumulative budgets, recipient rules, permitted assets, and approval thresholds.

### 3.6 Evaluate behaviour

The behaviour engine evaluates amount deviation, request velocity, recipient novelty, and compound drain patterns. Only approved payments update clean baselines.

### 3.7 Combine decisions

Severity is monotonic:

```text
BLOCK > REQUIRE_APPROVAL > ALLOW
```

No low-risk result may cancel a hard block. Each contributor returns stable reason codes and evidence rather than an opaque score alone.

### 3.8 Authorize signing

An `ALLOW` authorization is bound to the canonical request digest, expires quickly, and can be consumed once. A wallet integration must reject missing, expired, mismatched, or already-consumed authorizations.

### 3.9 Record evidence

The audit layer records the sanitized request, decision, reason codes, policy version, request digest, timing, and settlement reference where one exists.

## 4. Canonical data contracts

### Payment request

```json
{
  "request_id": "req_01",
  "agent_id": "research-agent-01",
  "mandate_id": "mandate_01",
  "recipient": "weather-api",
  "amount": "0.05",
  "asset": "USDC",
  "purpose": "weather research",
  "nonce": "unique-value",
  "created_at": "2026-07-25T10:00:00Z",
  "expires_at": "2026-07-25T10:01:00Z",
  "metadata": {}
}
```

### Decision

```json
{
  "request_id": "req_01",
  "decision": "BLOCK",
  "reason_codes": [
    "POLICY_SINGLE_PAYMENT_LIMIT",
    "RISK_COMPOUND_DRAIN"
  ],
  "evidence": {
    "amount_multiple": "400.0",
    "recipient_state": "FIRST_SEEN",
    "attempts_in_window": 8
  },
  "request_digest": "sha256:...",
  "authorization": null
}
```

## 5. Component responsibilities

| Component | Owns | Must not own |
|---|---|---|
| Protocol adapter | External-to-canonical conversion | Security decision |
| Gateway | Orchestration and fail-closed response | Private wallet keys |
| Mandate engine | Deterministic delegated authority | Behaviour baselines |
| Behaviour engine | Contextual and compound signals | Policy exceptions |
| Integrity guard | Nonce, expiry, digest, consumption | Settlement |
| Privacy filter | Safe logs and display representation | Silent request modification |
| Decision combiner | Severity and reason aggregation | Hidden overrides |
| Wallet adapter | Enforcing valid authorization | Re-evaluating policy |
| Audit service | Evidence and decision receipts | Raw secrets |

## 6. Availability and failure behaviour

The security-critical path fails closed. Timeouts, malformed protocol data, unavailable mandate state, integrity-store failure, or internal exceptions return `BLOCK` with a system reason code. The demonstration should explicitly test at least one dependency failure.

Observability failures may degrade without blocking only when the authorization decision and replay store remain trustworthy. This distinction must be explicit in code.

## 7. Adapter strategy

The canonical request and decision contracts isolate the security engine from payment protocols:

```text
Pay.sh sandbox ----\
x402 client --------> canonical request -> SolGuard -> signing authorization
Synthetic demo ----/
```

The first target is one reliable sandbox integration. Additional adapters are stretch goals and must not destabilize the core demonstration.

## 8. Performance target

The hackathon prototype should report gateway evaluation latency separately from network and settlement latency. A reasonable prototype target is a deterministic local decision within 50 ms at the 95th percentile, but this remains a target until benchmarked.

## 9. Production gaps

The hackathon prototype is not production-ready. Production deployment would additionally require hardened key boundaries, durable and highly available state, authenticated policy administration, tenant isolation, independent security review, abuse testing, privacy review, monitoring, incident response, and protocol-specific threat analysis.
