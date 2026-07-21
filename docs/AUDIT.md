# Audit Receipts and Local Event Stream

Every processed payment produces a sanitized audit event after the gateway decision. The event stream is local, in-memory, bounded, and independent of external databases or brokers.

## Event schema

Schema version `1.0` records:

- Ordered sequence and observation time
- Request identifier and canonical request digest
- Agent, recipient, fixed-precision amount, and asset
- Decision, stable reason codes, and decision evidence
- Deterministic active-policy digest
- Measured gateway latency
- Sanitized metadata with redaction counts
- Signing state and simulated settlement reference
- Explicit traffic and settlement context

The browser dashboard subscribes to this stream through its in-process state store. Retained receipts are also available locally from `GET /api/audit` for inspection and reconnect testing.

## Tamper evidence

Each receipt digest covers the canonical event payload and the previous receipt digest. This creates an ordered local hash chain. Altering an amount, decision, reason, metadata result, policy version, or chain link changes the expected digest.

Receipt digests are tamper-evident hashes, not digital signatures. They do not prove an external identity and must not be presented as signed attestations.

## Retention and subscribers

The prototype retains only a bounded in-memory event window. Late subscribers can replay the retained window in publication order; one failing observability subscriber cannot change or interrupt an already-made payment-security decision.

Production use would require durable append-only storage, authenticated transport, tenant isolation, access controls, retention policy, external time guarantees, key-backed signatures where appropriate, and independent review.
