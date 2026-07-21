# Single-Use Wallet Authorization

Every `ALLOW` decision creates a short-lived `SigningAuthorization` bound to the exact canonical request identifier and digest. Both the simulated settlement adapter and the Pay.sh sandbox adapter enforce that authorization at their wallet boundary before any balance mutation or external command.

## Wallet decision order

The wallet guard:

1. Rejects a missing authorization with `AUTHORIZATION_MISSING`.
2. Rejects a request identifier or digest mismatch with `AUTHORIZATION_MISMATCH`.
3. Rejects an authorization when the wallet clock is at or beyond `expires_at` with `AUTHORIZATION_EXPIRED`.
4. Atomically consumes the authorization identifier.
5. Rejects an already-consumed identifier with `AUTHORIZATION_REPLAYED`.
6. Permits exactly one settlement invocation after every check passes.

`BLOCK` and `REQUIRE_APPROVAL` decisions never contain an authorization and never call a settlement adapter. Invalid authorization attempts do not count as settlement attempts and cannot change the simulated balance or invoke the Pay CLI.

## Failure behavior

The authorization is consumed before settlement begins. If an external call fails afterward, it remains consumed; a retry requires a new payment challenge, request nonce, gateway decision, and authorization. This avoids reusing signing authority after an ambiguous external failure.

An unavailable or invalid authorization store fails closed as `SYSTEM_FAILURE`. Internal exception messages are excluded from decision evidence.

## Prototype limits

`InMemoryAuthorizationStore` is thread-safe but process-local and non-durable. Restarting the process clears consumption state, and multiple processes do not coordinate. Production deployment requires an atomic durable store, authenticated tenant isolation, controlled retention, hardened key custody, and independent review.
