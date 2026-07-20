# Demo and Validation Plan

## Success condition

The demonstration succeeds only if a real sandbox payment passes through SolGuard and a malicious request is rejected before signing. Dashboard animation alone is insufficient.

## Two-minute judge flow

| Time | Action | Visible proof |
|---|---|---|
| 0:00–0:15 | State the risk | Agent and wallet shown as separate trust boundaries |
| 0:15–0:35 | Submit legitimate paid API request | `ALLOW`, authorization digest, sandbox receipt |
| 0:35–0:45 | Trigger compromised-agent scenario | Agent state changes; request burst begins |
| 0:45–1:10 | Attempt drain | `BLOCK`, exact policy and compound-risk reasons |
| 1:10–1:25 | Prove enforcement | No signature, no settlement, balance unchanged |
| 1:25–1:40 | Submit another legitimate request | Normal commerce continues |
| 1:40–2:00 | Explain buyer and direction | Security control plane for agent wallets |

## Required scenarios

| Scenario | Expected decision |
|---|---|
| Known recipient, normal amount, valid mandate | `ALLOW` |
| Amount above hard single-payment limit | `BLOCK` |
| First-seen permitted recipient | `REQUIRE_APPROVAL` |
| High velocity alone | `REQUIRE_APPROVAL` |
| First-seen recipient + abnormal amount + burst | `BLOCK` |
| Expired mandate | `BLOCK` |
| Reused nonce | `BLOCK` |
| Request modified after authorization | Wallet rejects authorization |
| Sensitive metadata | Redacted from audit event |
| Mandate store unavailable | `BLOCK` |

## Evidence displayed

- Canonical request identifier and digest
- Decision and stable reason codes
- Active mandate limits
- Amount multiple and recipient state
- Requests observed within the velocity window
- Authorization creation or explicit absence
- Settlement reference for allowed requests
- Wallet balance before and after the blocked attack
- Decision latency measured from the running gateway

No number may be hardcoded and presented as live evidence.

## Reliability checklist

- Run the full automated test suite.
- Run the complete demo from a clean process three times.
- Confirm sandbox dependencies and credentials.
- Record a 60–90 second successful fallback video.
- Export static screenshots of each critical state.
- Keep synthetic traffic available if the payment network fails.
- Clearly label simulated traffic and recorded footage.
- Prepare a local-only mode that demonstrates the same security decisions.

## Judge interaction

Give a judge one safe control: **Trigger compromised agent**. The test inputs remain deterministic so the outcome is explainable and repeatable. A second control resets the sandbox to the normal scenario.

## Claims policy

Say only what the current build proves. Describe unfinished protocol support as planned, simulated data as simulated, sandbox settlement as sandbox settlement, and recorded evidence as recorded evidence.
