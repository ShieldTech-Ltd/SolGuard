# SolGuard Launch Brief

## One sentence

SolGuard is a pre-signing security gateway that constrains autonomous-agent payments
before a wallet authorization can reach settlement.

## Buyer and pain

The initial buyer hypothesis is an agent platform or wallet provider that allows
software agents to purchase APIs, data, or services. Its risk is not merely that a
payment fails: a compromised or misdirected agent can issue valid-looking payments at
machine speed while still holding legitimate wallet access.

## Product

An owner delegates a small financial mandate to an agent. SolGuard evaluates each
canonical payment request against:

- per-agent maximum spend and recipient allow/block rules;
- amount, velocity, recipient-novelty, and compound-drain detection;
- request expiry and per-agent nonce replay protection;
- a fail-closed decision gateway; and
- a short-lived, exact-request authorization consumed once at the wallet boundary.

The result is `ALLOW`, `REQUIRE_APPROVAL`, or `BLOCK`, with stable reason codes and a
sanitized audit receipt. A block produces no signing authorization.

## Demonstrated differentiation

The prototype enforces the decision before wallet settlement, rather than alerting
after funds move. The demonstrated build also keeps the security engine independent of
the payment rail: the same controls drive an in-memory fallback and one optional Pay.sh
sandbox adapter.

This is a verified prototype property, not a claim that SolGuard supports every wallet,
protocol, or production threat model.

## Commercial hypothesis

A possible entry model is usage-based screening for agent platforms and wallets,
followed by paid policy management, audit retention, and enterprise controls. No
customer, revenue, pricing-validation, or market-share claim is made.

## Design-partner ask

We are seeking one agent-platform or wallet team to validate:

1. where a pre-signing decision can be enforced in its real transaction path;
2. which mandate controls its users can understand and operate safely;
3. what latency and availability budgets that boundary requires; and
4. which audit evidence its security and compliance teams need.

The next validation step is a scoped sandbox integration using the partner's own
payment intents and adversarial cases, with no production funds.

## Production gaps and non-goals

The current build is not production-ready. It uses process-local state and does not
provide durable replay coordination, multi-tenant isolation, authenticated policy
administration, hardened key custody, high availability, incident response, or an
independent security review. Pay.sh activity is sandbox-only; the local balance and
settlement path are simulated. The x402 v2 adapter currently proves Solana-devnet
request mapping and pre-signing ordering only; its settlement remains simulated.

SolGuard does not custody keys, replace wallet cryptography, guarantee fraud
prevention, or claim that behavioural rules can identify every attack.
