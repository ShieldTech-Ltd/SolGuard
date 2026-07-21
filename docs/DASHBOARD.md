# Live Security Dashboard

The SolGuard dashboard is a stage-facing local demonstration interface backed by the
running gateway. It does not contain sample transactions, hardcoded activity totals,
invented trust scores, or claimed network settlement.

## Run

```bash
uv run solguard-dashboard
```

Open `http://127.0.0.1:8765`.

## Controls

- **Run normal payment** submits one local simulated payment through the mandate, detection, gateway, and settlement path.
- **Trigger compromised agent** establishes a clean three-payment baseline and then submits five new-recipient drain attempts. The fifth attempt satisfies the documented compound rule.
- **Reset local state** constructs a new in-memory gateway, detector, balance, and event store.

All traffic is explicitly labelled `SIMULATED`.

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

The browser can trigger only the three local scenario operations. It cannot edit a recipient, amount, mandate, wallet balance, or authorization. HTTP errors return generic messages rather than internal exception details.

The dashboard store subscribes to the bounded local audit event stream. The browser polls a computed state snapshot, while portable chained receipts remain available from the local `/api/audit` endpoint.
