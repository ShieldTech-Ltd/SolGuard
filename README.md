# SolGuard

> The pre-signing security gateway for autonomous agent payments.

[![Status: architecture phase](https://img.shields.io/badge/status-architecture%20phase-f59e0b)](#project-status)
[![Hackathon](https://img.shields.io/badge/Speed%20Build-2026-14f195)](#speed-build-2026)
[![Security model](https://img.shields.io/badge/security-fail%20closed-ef4444)](docs/THREAT_MODEL.md)

![SolGuard payment security architecture](docs/architecture.svg)

Autonomous agents can discover services, negotiate prices, and initiate payments at machine speed. That also means a compromised agent can lose funds at machine speed. SolGuard sits between an agent and its wallet, evaluates every proposed payment against an owner-approved financial mandate, and returns a decision **before a signature is produced**.

```text
Agent intent -> Payment request -> SolGuard -> ALLOW / REQUIRE_APPROVAL / BLOCK -> Wallet
```

SolGuard is being developed for **Speed Build 2026**, whose scenario asks builders to secure financial infrastructure against a future autonomous-agent attack. The objective is a working, explainable demonstration—not a claim of production readiness.

## Why SolGuard

Payment protocols answer: **How can an agent pay?**

SolGuard answers: **Should this agent be allowed to make this payment?**

The initial prototype is designed to defend against:

- Wallet drain and abnormal overpayment
- Rapid payment bursts
- First-seen or prohibited recipients
- Payments outside a delegated budget or purpose
- Replayed or expired authorizations
- Sensitive information leaking through payment metadata
- Security-service failure, using fail-closed signing

## The core primitive: Agent Financial Mandates

A human authorizes a constrained mandate instead of approving every transaction:

```json
{
  "agent_id": "research-agent-01",
  "purpose": "Purchase verified research APIs",
  "currency": "USDC",
  "max_single_payment": "2.00",
  "max_total": "20.00",
  "allowed_recipients": ["weather-api", "market-data-api"],
  "expires_at": "2026-07-26T00:00:00Z",
  "single_use_authorizations": true
}
```

Every proposed payment must match the mandate and pass behavioural checks. The mandate is intended to be deterministic and auditable; anomaly detection adds context but cannot override a hard owner policy.

## Decision model

| Decision | Meaning | Wallet behaviour |
|---|---|---|
| `ALLOW` | Request satisfies mandate and risk controls | Signing may continue |
| `REQUIRE_APPROVAL` | Request is plausible but outside learned behaviour | Pause for explicit approval |
| `BLOCK` | Hard policy, replay, integrity, or compound-risk violation | Do not sign |

The gateway returns machine-readable reason codes and a human-readable explanation for every decision.

## Architecture

```mermaid
flowchart LR
    U[Human owner] -->|delegates mandate| M[Mandate store]
    A[Autonomous agent] -->|payment intent| G[SolGuard gateway]
    X[Pay.sh / x402 adapter] --> G
    M --> P[Policy engine]
    G --> P
    G --> D[Behaviour engine]
    G --> I[Integrity and replay guard]
    G --> R[Metadata sanitizer]
    P --> E[Decision combiner]
    D --> E
    I --> E
    R --> E
    E -->|ALLOW| W[Wallet signer]
    E -->|REQUIRE_APPROVAL| U
    E -->|BLOCK| B[No signature]
    W --> S[Sandbox settlement]
    E --> L[Audit receipt]
```

Explore the planned flow in the [interactive architecture](docs/architecture.html), or read the detailed [architecture specification](docs/ARCHITECTURE.md).

## Demonstration

The target two-minute demonstration proves both safety and usability:

1. A legitimate agent purchases a low-cost API resource.
2. SolGuard validates the mandate and allows the sandbox payment.
3. The operator triggers a compromised-agent scenario.
4. The agent attempts a high-value burst toward a first-seen recipient.
5. SolGuard blocks the request before signing and shows exact reason codes.
6. The wallet balance remains unchanged.
7. A subsequent legitimate request still succeeds.

The judge-facing proof is not a dashboard alert. It is the absence of a wallet signature and settlement for the malicious request.

See the [demo and validation plan](docs/DEMO_PLAN.md).

## Planned repository layout

```text
SolGuard/
├── src/solguard/
│   ├── gateway/          # Request orchestration and fail-closed boundary
│   ├── mandates/         # Financial mandate validation
│   ├── detection/        # Behaviour and compound-risk rules
│   ├── integrity/        # Nonce, expiry, and replay protection
│   ├── privacy/          # Metadata sanitization
│   ├── adapters/         # Pay.sh, x402, and sandbox integrations
│   └── audit/            # Decision receipts and event history
├── dashboard/            # Live demonstration interface
├── tests/                # Unit, integration, attack, and failure tests
└── docs/                 # Architecture, threat model, and demo plan
```

## Security principles

1. **Pre-signing enforcement.** A post-settlement alert is too late.
2. **Fail closed.** If SolGuard cannot reach a trustworthy decision, the wallet does not sign.
3. **Hard policy outranks heuristics.** Behavioural scoring never bypasses a mandate.
4. **Explain every decision.** Each block includes stable reason codes and evidence.
5. **Learn only from approved traffic.** Blocked requests cannot poison an agent baseline.
6. **No custom cryptography.** Use established wallet and protocol primitives.
7. **Minimize sensitive data.** Sanitize metadata and avoid retaining secrets.
8. **Prove claims live.** Demo metrics must originate from the running gateway.

The detailed security boundaries, attacker assumptions, and non-goals are documented in [THREAT_MODEL.md](docs/THREAT_MODEL.md). Security reports should follow [SECURITY.md](SECURITY.md).

## Project status

**Current phase: architecture and repository foundation.**

The architecture and demonstration requirements are documented. The payment engine, adapters, dashboard, and security controls are not yet represented as completed in this repository. Features will only be marked complete after implementation and automated verification.

| Capability | Status |
|---|---|
| Architecture and threat model | Documented |
| Financial mandate engine | Planned |
| Pre-signing gateway | Planned |
| Replay protection | Planned |
| Behavioural detection | Planned |
| Metadata sanitizer | Planned |
| Pay.sh sandbox adapter | Planned |
| x402 adapter | Stretch goal |
| Live dashboard | Planned |
| Recorded fallback demo | Planned |

## Build order

1. Mandate schema and deterministic policy engine
2. Replay-safe pre-signing decision gateway
3. Behavioural and compound drain detection
4. Automated attack and fail-closed test suite
5. One real sandbox payment adapter
6. Live dashboard driven exclusively by gateway events
7. Backup recording and pitch rehearsal
8. Additional protocol adapters only after the core is reliable

## Business direction

SolGuard's proposed commercial wedge is usage-based transaction screening for agent platforms and wallets, with enterprise policy management and audit capabilities. Candidate design partners include agent-wallet providers, paid-API marketplaces, and organisations deploying autonomous purchasing agents.

This is an early product thesis, not evidence of existing customers, revenue, or production deployment.

## Documentation

- [System architecture](docs/ARCHITECTURE.md)
- [Interactive architecture](docs/architecture.html)
- [Threat model](docs/THREAT_MODEL.md)
- [Demo and validation plan](docs/DEMO_PLAN.md)
- [Security policy](SECURITY.md)
- [Contribution and release workflow](CONTRIBUTING.md)

## Speed Build 2026

SolGuard is an independent hackathon project for Speed Build 2026 in London, 25–26 July 2026. References to Pay.sh, x402, Solana, or CoralOS describe intended interoperability or planned experiments unless a test in this repository proves otherwise. No affiliation or endorsement is implied.

## Author

Created by [Tanvir Farhad (TFT444)](https://github.com/TFT444), founder of ShieldTech.

## License

SolGuard is available under the [MIT License](LICENSE). Copyright (c) 2026 ShieldTech Ltd.
