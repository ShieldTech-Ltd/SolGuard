# Judge demonstration runbook

This runbook presents the live dashboard as evidence of the running gateway, not as a
mock product animation. Use the guided mode so each screen is tied to one gateway result.

## Before presenting

1. Start `uv run solguard-dashboard` or open the verified hosted fallback.
2. Confirm `/healthz` returns `status: ok`.
3. Open the dashboard at a desktop width and select **Reset demo**.
4. Confirm the header says **LIVE SECURITY ENGINE** and **SIMULATED SETTLEMENT**.
5. Keep `uv run solguard-demo --skip-paysh` ready as a terminal fallback.

Do not describe a settlement as real, devnet, or on-chain unless its transaction signature
has been independently verified for that run.

## Two-minute story

### 1. State the problem

> An autonomous agent can hold valid wallet access and still make a dangerous payment.
> SolGuard decides whether that payment should reach the signer before money can move.

Select **Start guided demo**. Point to the separation between the agent, SolGuard, the
wallet boundary, and settlement.

### 2. Allow ordinary commerce

Run **Normal payment** and step through the request, integrity, mandate, behaviour, and
authorization stages.

Visible proof:

- decision is `ALLOW`;
- the request and policy digests come from the current event;
- signing state is `SIGNED`; and
- settlement is visibly labelled `SIMULATED`.

Say: "The owner did not approve this payment manually. The agent operated inside a
pre-approved mandate, so the gateway allowed it autonomously."

### 3. Escalate uncertainty without stopping everything

Run **First-seen recipient**.

Visible proof:

- decision is `REQUIRE_APPROVAL`;
- the reason identifies recipient novelty; and
- no signing authorization reaches the wallet.

Say: "Autonomy is bounded, not removed. An unfamiliar but otherwise plausible payment is
paused for approval instead of being silently signed."

### 4. Prove integrity enforcement

Run **Replay attack**.

Visible proof:

- the reused request is `BLOCK`;
- the reason is `REQUEST_REPLAYED`; and
- signing state remains `NOT_SIGNED`.

Say: "A valid-looking payment cannot be reused with the same per-agent nonce."

### 5. Trigger the memorable attack

Run **Compound drain** and advance to the behaviour, wallet, and evidence stages.

Visible proof:

- the decision is `BLOCK`;
- the reasons include compound drain, new recipient, and high velocity;
- the wallet is `NOT_SIGNED` and has no settlement reference;
- the simulated wallet balance does not fall for the blocked request;
- the email and bearer token are redacted; and
- the receipt chain verifies.

Say: "The important output is not the red alert. It is the missing signature. The blocked
request never crossed the wallet boundary."

### 6. Close with the product

> Payment protocols answer how an agent can pay. SolGuard answers whether that agent
> should be allowed to pay. We are looking for an agent platform or wallet partner to
> validate this pre-signing boundary with its own sandbox payment intents.

## If the network or hosted page fails

1. Start the local dashboard and repeat the same four controls.
2. If a browser is unavailable, run `uv run solguard-demo --skip-paysh` and show the
   emitted decisions and invariants.
3. Use the recorded evidence package only as clearly labelled backup footage.

Never replace a failed external integration with an unlabelled simulation. Reliability is
part of the demonstration; accurate labels preserve reviewer trust.

## Fast reviewer questions

- **Is settlement real?** The hosted fallback uses simulated settlement. The security
  decisions, signing-state outcome, sanitized receipt, and dashboard metrics are computed
  by the running local gateway.
- **Can blocked traffic poison the baseline?** No. The behaviour engine learns recipients
  and amounts only from approved traffic.
- **What stops replay?** Freshness and per-agent nonce checks run before policy and signing.
- **What happens if a control fails?** The gateway fails closed and does not issue signing
  authorization.
- **Is this production-ready?** No. Durable replay coordination, multi-tenant isolation,
  authenticated administration, hardened key custody, high availability, and independent
  security review remain production work.
