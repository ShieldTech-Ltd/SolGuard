# Request Integrity and Replay Protection

SolGuard applies one basic request-integrity boundary before policy, behavioural detection, authorization creation, or settlement. It has no external dependency and uses no custom cryptography.

## Decision order

For each canonical payment request, the gateway:

1. Rejects a missing or malformed nonce during contract validation.
2. Rejects the request when the gateway clock is at or beyond `expires_at`.
3. Atomically consumes the `(agent_id, nonce)` pair in the nonce store.
4. Returns `REQUEST_REPLAYED` if that pair was already consumed.
5. Continues to mandate and behavioural evaluation only for a fresh pair.

Expired and malformed requests never reach the nonce store. A fresh, structurally valid request consumes its nonce at the integrity boundary even if a later policy, detection, or settlement control blocks it. Retrying a corrected request therefore requires a new nonce.

## Fail-closed behavior

The store exposes one atomic `consume_if_unused` operation so the security decision never depends on a separate read followed by a write. An exception or invalid response from the store becomes `SYSTEM_FAILURE`; no authorization or settlement is produced.

## Prototype limits

`InMemoryNonceStore` is thread-safe but process-local and non-durable. Restarting the process clears replay state, and separate instances do not coordinate. Production deployment requires an atomic durable store, authenticated tenant isolation, retention controls, and operational monitoring.

Request-nonce replay protection is distinct from single-use authorization enforcement at the wallet boundary. The implemented wallet guard maintains a separate process-local store because request observation and signing authority are different security boundaries.
