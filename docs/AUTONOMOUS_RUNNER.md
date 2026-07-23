# Autonomous security runner

`solguard-autonomous` is the reproducible, headless proof that SolGuard can control an
autonomous payment loop without a person approving each transaction. It is independent of the
dashboard: CLI events and gateway audit receipts are the authoritative evidence, while a UI may
observe them passively.

## Deterministic sequence

The local command executes one fixed sequence against the real contracts, identity verifier,
integrity guard, mandate engine, behavioural engine, decision API service, authorization guard,
and simulated settlement boundary:

1. Three 10 USDC payments to a known recipient are allowed and settled. These confirmed clean
   settlements establish a 10 USDC behavioural average.
2. A 10 USDC payment to a first-seen but policy-allowed recipient is quarantined. It receives no
   authorization and never reaches settlement.
3. The exact same signed request and nonce are submitted again. Replay protection blocks it
   before behaviour evaluation and settlement.
4. A manipulated x402 requirement requests 20 USDC for a new attacker recipient at the fifth
   evaluated attempt inside ten seconds. The documented compound rule is therefore true: new
   recipient + at least 2x the clean average + high velocity. SolGuard blocks the request without
   authorization or settlement.

There is no random compromise trigger. Scenario inputs, ordering, and observed time are fixed for
each run.

## Execution boundary

```text
simulated paid resource -> x402 parser -> canonical PaymentRequest
    -> Ed25519 agent signature -> authenticated decision API
        -> ALLOW -> request-bound authorization -> injected settlement boundary
        -> REQUIRE_APPROVAL -> quarantine; stop that intent
        -> BLOCK -> stop that intent
```

The runner owns an agent identity key but has no wallet-signing method. Its only payment dependency
is the injected settlement protocol. The default implementation uses the existing in-memory
settlement adapter and labels every result `SIMULATED`.

The decision API itself is constructed with a forbidden settlement adapter. This makes an
accidental attempt to settle from the policy service an explicit failure.

## Behaviour state

Only a successful settlement calls `BehaviourEngine.record_allowed`. Quarantined, replayed,
blocked, or failed traffic cannot enter the clean amount/recipient baseline. Attempts still count
toward the velocity rule, as required for rapid-drain detection.

## Output and exit status

The command emits a single JSON object containing ordered runtime events and computed totals. It
returns zero only when all expected decisions and signer-boundary invariants are observed. A
resource, protocol, API, authorization, or settlement failure stops safely and returns non-zero.

No result from this command is a real Solana transaction or a real asset balance. Real devnet
confirmation remains a separate opt-in integration and must be supported by RPC-derived evidence.
