# Threat Model

## Scope

This document describes the intended security model for the SolGuard hackathon prototype. It does not assert that the controls are implemented until corresponding code and tests exist.

## Protected assets

- Authority to sign a payment
- Agent and owner funds
- Financial mandates and policy configuration
- Authorization nonces and replay state
- Payment and decision integrity
- Sensitive payment metadata
- Audit evidence used to explain decisions

## Adversaries

1. **Compromised agent:** The agent's prompt, memory, model output, or tools are controlled by an attacker.
2. **Malicious recipient:** A service returns an inflated price or substitutes a recipient.
3. **Replay attacker:** A valid request or authorization is captured and submitted again.
4. **Baseline poisoner:** Malicious requests attempt to redefine normal agent behaviour.
5. **Metadata attacker:** Secrets or personal data are inserted into logged fields.
6. **Availability attacker:** A dependency is made unavailable to encourage insecure bypass.

## Primary abuse cases

| Abuse case | Intended control | Safe outcome |
|---|---|---|
| Payment exceeds delegated maximum | Hard mandate limit | Block before signing |
| Recipient is prohibited | Recipient policy | Block before signing |
| Recipient is new but permitted | Approval threshold | Require approval |
| Rapid high-value payments to new recipient | Compound drain rule | Block before signing |
| Authorization is reused | Single-use nonce store | Block replay |
| Request changes after approval | Canonical digest binding | Reject mismatch |
| Mandate or request expired | Time-bound authorization | Block before signing |
| Secret appears in metadata | Sanitized observability copy | Redact from logs/UI |
| Detection dependency fails | Fail-closed gateway | Block; do not bypass |
| Malicious traffic attempts baseline poisoning | Clean-only baseline update | Ignore blocked traffic |

## Security invariants

1. A wallet must not sign without a valid, unexpired SolGuard authorization.
2. An authorization must be valid for exactly one canonical request.
3. A consumed authorization or nonce must not be accepted twice.
4. A hard policy block must never be reduced by behavioural scoring.
5. A blocked request must not update a clean behavioural baseline.
6. An internal security-path failure must not return `ALLOW`.
7. Raw secrets must not be written to normal logs or dashboard events.

## Explicit non-goals for the hackathon

- Custodying production funds
- Replacing wallet key-management systems
- Detecting every possible financial fraud pattern
- Proving recipient identity globally
- Guaranteeing that an allowed purchase is commercially valuable
- Building custom cryptographic primitives
- Claiming regulatory or compliance certification

## Validation requirements

Every invariant requires at least one automated test. The live demonstration must prove request-digest binding, replay rejection, fail-closed behaviour, and unchanged wallet balance after the attack.

## Residual risk

Rules can produce false positives or miss novel attacks. A legitimate but harmful transaction may satisfy an overly broad mandate. System administrators may configure unsafe policies. Time, state, and concurrency errors can undermine limits. These risks require adversarial testing and independent review before real-fund deployment.
