# Local Security Dashboard

The SolGuard dashboard is a local demonstration interface backed by the running Phase 1 gateway. It does not contain sample transactions or hardcoded activity totals.

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

## Data provenance

The interface computes its wallet balance from the simulated settlement adapter and its decision counts, blocked value, latency, signing state, reasons, and transaction feed from actual gateway outcomes. An empty runtime displays zero or “No data”; it does not generate example activity.

Payment metadata passes through the bounded sanitizer before appearing in the feed. The dashboard shows redaction categories and counts, never original recognized values.

## Security boundary

The browser can trigger only the three local scenario operations. It cannot edit a recipient, amount, mandate, wallet balance, or authorization. HTTP errors return generic messages rather than internal exception details.

The dashboard store subscribes to the bounded local audit event stream. The browser polls a computed state snapshot, while portable chained receipts remain available from the local `/api/audit` endpoint.
