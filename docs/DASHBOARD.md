# Autonomous Security Control Plane

The SolGuard control plane is a stage-facing local demonstration interface backed by
the running gateway. Humans define the mandate and inspect exceptional outcomes; the
gateway makes routine payment decisions autonomously before the wallet boundary. The
interface does not contain hardcoded transaction results, activity totals, invented
trust scores, or claimed network settlement.

## Run

```bash
uv run solguard-dashboard
```

Open `http://127.0.0.1:8765`.

The command processes one normal payment through the gateway before opening the server,
so the first screen contains computed `ALLOW`, authorization, settlement, receipt, and
balance evidence. **Reset local state** still returns the runtime to a genuine empty
state.

## Controls

- **Normal API purchase** resets the runtime and submits one known-recipient payment that
  satisfies the mandate and reaches simulated settlement.
- **First-seen recipient** establishes a three-payment clean baseline, then submits a
  permitted payment to a new destination. Recipient novelty produces
  `REQUIRE_APPROVAL`, with no authorization or settlement.
- **Replay intercepted request** submits the exact same canonical request and nonce
  twice. The first request is allowed; the second is blocked by the integrity guard
  before policy, behaviour, authorization, or settlement.
- **Compromised wallet drain** establishes a clean three-payment baseline and then
  submits five new-recipient drain attempts. The fifth attempt satisfies the documented
  compound rule and returns `BLOCK`.
- **Reset local state** constructs a new in-memory gateway, detector, balance, and event store.

All traffic is explicitly labelled `SIMULATED`.

## Product structure

The page is organized so a non-code reviewer can understand the product without opening
the repository:

1. the autonomous agent-to-gateway-to-wallet product position;
2. four clickable decision scenarios covering all three public outcomes;
3. the latest request and wallet-enforcement proof;
4. runtime-derived decision totals and attempted blocked value;
5. the active financial mandate and simulated wallet state;
6. a six-stage security pipeline highlighted from the latest decision;
7. the recent transaction stream; and
8. an inspectable hash-linked audit receipt chain.

## Visual proof

The above-the-fold decision stage renders the latest gateway event and its enforcement
evidence:

- the exact `ALLOW`, `REQUIRE_APPROVAL`, or `BLOCK` decision;
- request amount, asset, recipient, timestamp, and measured gateway latency;
- stable policy and detection reasons translated into judge-readable labels;
- whether the simulated wallet boundary was reached;
- whether a settlement reference exists;
- safe metadata redaction categories and computed counts; and
- the shortened digest of the hash-linked decision receipt.

The metric strip shows the current simulated wallet balance, attempted value blocked,
and decision totals. Attempted value blocked is the sum of the actual requests that the
running gateway blocked; it is not a claim about real funds saved.

## Data provenance

The interface computes its wallet balance from the simulated settlement adapter and its decision counts, blocked value, latency, signing state, reasons, and transaction feed from actual gateway outcomes. An empty runtime displays zero or “No data”; it does not generate example activity.

Payment metadata passes through the bounded sanitizer before appearing in the feed. The
dashboard shows redaction categories and counts, never original recognized values. The
UI constructs all untrusted runtime text with `textContent` rather than HTML injection.

## Security boundary

The browser can trigger only the four deterministic local scenario operations and a
local reset. It cannot edit a recipient, amount, mandate, wallet balance, or
authorization. HTTP errors return generic messages rather than internal exception
details.

The dashboard store subscribes to the bounded local audit event stream. The browser polls a computed state snapshot, while portable chained receipts remain available from the local `/api/audit` endpoint.
