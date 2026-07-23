# Autonomous attack resistance proof

`solguard-security-proof` is the authoritative network-independent security demonstration. It is
headless, deterministic, problem-first, and independent of the dashboard. A UI may render its JSON
events, but cannot create or alter evidence.

## Act 1: show the unprotected failure

The isolated `solguard_demo_reference.UnsafeReferenceWallet` receives the canonical scenario
requests. It validates and produces real Ed25519 signatures over the offline transaction fixture,
then updates a simulated ledger without asking SolGuard for financial authorization.

The component is deliberately separate from the protected signer package. There is no runtime
toggle that disables SolGuard inside the protected wallet. Its mode is always
`UNSAFE_OFFLINE_REFERENCE_SIMULATION`; its signatures are not presented as Solana transactions.

## Act 2: replay through SolGuard

The proof resets to the same configured balance and replays the identical canonical requests:

1. Three normal 10 USDC requests are authenticated, allowed, authorized, signed through the
   isolated wallet, and entered into the clean behavioural baseline.
2. A first-seen policy-allowed recipient is quarantined with no authorization.
3. The fifth rapid request is a velocity-only event and is quarantined, never hard-blocked.
4. A known-recipient request at exactly 8x the 10 USDC baseline is blocked.
5. The primary manipulated x402 request uses a new recipient, exactly 2x the baseline, and high
   velocity. The compound-drain rule blocks it.
6. A 150 USDC request violates the 100 USDC hard mandate and is blocked.
7. The exact first request and nonce are replayed and blocked by integrity protection.
8. Eleven seconds later, a normal 10 USDC request is allowed and signed, proving safe recovery.

Blocked and quarantined requests have no authorization identifier, wallet invocation, offline
wallet signature, Solana transaction signature, settlement reference, or balance change.

## Wallet and failure probes

The same command also executes and verifies:

- transaction mutation after authorization
- exact single-use authorization replay
- direct protected-wallet invocation without authorization
- decision security-path failure
- isolated signer failure
- facilitator/network settlement failure
- independent Solana RPC confirmation failure

Every probe must return its expected fail-closed reason and no transaction signature. A mismatch
causes a non-zero process exit.

## Evidence contract

Each request records only runtime-derived values: canonical request and digest, agent and mandate,
stable decision reasons, policy version, authorization presence/absence, signer invocation,
signing state, sanitized audit receipt, and computed before/after simulated balance.

The output explicitly distinguishes:

- `UNSAFE_OFFLINE_REFERENCE_SIMULATION`
- `SOLGUARD_PROTECTED_OFFLINE_CRYPTOGRAPHIC_SIMULATION`
- `NOT_SUBMITTED_SIMULATION` RPC state
- `NOT_EXECUTED_CREDENTIALS_REQUIRED` real-devnet state

No simulated signature is placed in the `solana_transaction_signature` field.

## Reproducibility

Run:

```bash
uv run solguard-security-proof
```

The test suite also executes three consecutive fresh Python processes and requires the expected
normal, velocity-only, exact-8x block, compound-drain block, and recovery decisions each time.

## Remaining live gate

This command satisfies the deterministic attack-resistance proof but does not manufacture the
credentialed evidence required by issue #34/#35. A complete live claim still requires the same
authorized flow to obtain a real paid resource, a genuine Solana-devnet signature, independent RPC
confirmation and token deltas, and a sanitized evidence package tied to the exact source commit.

Direct theft of an independently usable wallet private key is outside the demonstrated threat
boundary. The protected architecture prevents the autonomous agent from possessing or directly
invoking that key.
