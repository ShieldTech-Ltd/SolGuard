# Technical Q&A

## What is the security boundary?

SolGuard sits between an untrusted agent payment intent and wallet settlement. The
wallet boundary accepts only a short-lived authorization bound to the exact request
identifier and canonical digest. `BLOCK` and `REQUIRE_APPROVAL` produce no such
authorization.

## What did the demonstrated attack prove?

The deterministic sequence established a clean three-payment baseline, then submitted
five attack requests. Four required approval and the compound request was blocked. The
blocked request was `NOT_SIGNED`, had no settlement reference, and left the post-baseline
simulated balance unchanged at 970 USDC. A reset then allowed one legitimate payment.

This proves the behavior of the tagged prototype under its test inputs. It is not a
claim about all attacks or real funds.

## What are the four behavioural rules?

- Spending guard: an amount at least 8x the clean average blocks.
- Rate limiter: velocity alone requires approval; it does not block.
- Recipient novelty: a first-seen permitted recipient requires approval.
- Compound drain: a new recipient, amount at least 2x the average, and high velocity
  together block.

The 8x and 2x comparisons are inclusive: a request exactly at either applicable
threshold triggers that rule.

Hard mandate violations also block and cannot be overridden by behavioural results.

## Can an allowed decision be replayed or altered?

The gateway rejects expired requests and reused per-agent nonces. The wallet guard
checks the exact request identifier and digest, expiry, and single-use authorization
identifier before settlement. These stores are thread-safe but process-local; durable
cross-process coordination remains production work.

## What happens if SolGuard fails?

Exceptions and unavailable security-critical state fail closed. The prototype returns
a system block and does not invoke settlement. An external settlement failure after an
authorization is consumed does not make that authorization reusable.

## Does it make a real payment?

The captured external path exercised the official Pay CLI against Pay.sh's sandbox and
returned `SETTLED` for 0.01 USDC. It used an ephemeral sandbox wallet. The reference is
locally computed evidence for that run, not a mainnet transaction signature. The
reliable fallback uses an in-memory simulated balance.

## How is sensitive data handled?

Payment metadata is sanitized before logs and dashboard output. Known sensitive keys,
credential-like values, and URL query values are redacted. The prototype still requires
a full privacy review and production log-retention policy.

## How fast is it?

On the recorded Windows test host, 500 local gateway calls had a median of 0.1222 ms and
a p95 of 0.2561 ms. The benchmark includes local policy, integrity, behavioural,
authorization, audit, and in-memory settlement work. It excludes network and external
settlement latency. One separate Pay.sh sandbox demo completed in 5433.5796 ms; that
single observation is evidence, not a network performance benchmark.

## What would be required before production?

At minimum: durable atomic stores, tenant and policy authentication, hardened key and
wallet boundaries, protocol-specific threat analysis, load and failure testing,
monitoring, incident response, privacy review, supply-chain/code scanning, and an
independent security assessment.
