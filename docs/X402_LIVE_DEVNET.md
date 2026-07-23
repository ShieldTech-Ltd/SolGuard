# Real x402 Solana-Devnet Demonstration

## Status and boundary

This is an optional, explicitly confirmed demonstration path. It uses the official
x402 Python SDK to create an SVM payment payload and asks the x402.org test facilitator
to verify and settle a USDC payment on Solana devnet.

It is not enabled by the base install, it never targets mainnet, and it does not make
the repository production-ready. The deterministic simulated path remains available
when credentials, faucet funds, or public services are unavailable.

No real transaction signature is committed to this repository. A devnet transaction
is evidence only after this command returns `VERIFIED` with a non-empty
`transaction_signature` and an `on_chain_confirmation` object derived independently
from Solana RPC. Explorer is useful for presentation, but it is not the authoritative
confirmation source.

## What the demonstration proves

The command runs two requests through the same SolGuard gateway:

1. A request for twice the configured maximum returns `BLOCK`. The x402 signer is not
   called.
2. The exact permitted request returns `ALLOW`, consumes a single-use authorization at
   the wallet boundary, signs the x402 SVM payload, and requests facilitator settlement.
3. The returned signature is queried through `getSignatureStatuses` and
   `getTransaction`. The result is reported as verified only when RPC reports a
   successful confirmed/finalized transaction and the exact USDC source/destination
   token-account deltas match the canonical amount.

This is a direct facilitator-backed x402 devnet settlement demonstration. It is not a
complete paid-resource server/client round trip.

## Safe setup

Use two disposable Solana devnet wallets: one payer and one recipient. Never provide a
mainnet wallet key. Fund the payer with devnet USDC from Circle's public faucet. The
recipient must be able to receive that devnet USDC token.

Install the optional dependencies:

```bash
uv sync --locked --all-groups --extra devnet
```

The x402 SDK currently requires the legacy `solana.rpc` package layout, so the optional
extra pins `solana` below 0.40. The base SolGuard installation remains dependency-free.

Set credentials only in the current process environment. The repository ignores `.env`,
key, seed, and wallet JSON files; `.env.example` contains empty placeholders only.

PowerShell:

```powershell
$env:SOLGUARD_SVM_PRIVATE_KEY = "<DEVNET-ONLY BASE58 KEYPAIR>"
$env:SOLGUARD_SVM_RECIPIENT = "<DEVNET RECIPIENT ADDRESS>"
```

Print the payer's public address without submitting a transaction:

```bash
uv run --extra devnet solguard-x402-live --show-wallet-address
```

After the payer has devnet USDC, explicitly authorize one 0.001 USDC attempt:

```bash
uv run --extra devnet solguard-x402-live --amount 0.001 --confirm-devnet
```

The command emits machine-readable JSON. On success, retain the output as demonstration
evidence. The confirmation contains only RPC-derived signature, slot, status, mint,
owners, token accounts, and atomic balance deltas. It always states that devnet tokens
have no real monetary value. Do not assign a GBP value to them, and do not store the
private key or a populated environment file with the evidence.

The current command is a direct facilitator-backed settlement exercise, not a complete
paid-resource HTTP round trip. It also uses the official SDK's in-process keypair signer;
the separately tested SolGuard-signed isolated wallet boundary is not yet wired into that
SDK signer. Therefore code-level RPC readiness alone does not satisfy the full live
evidence issue. Keep that issue open until the paid resource, isolated signer, real
signature, RPC response, resource response, authorization receipt, exact command, and
source commit are captured together.

## Failures and fallback

The command fails closed when the mandate, request binding, authorization, SDK,
facilitator, independent RPC service, token-delta match, or settlement evidence fails.
CLI errors expose only a safe
error class, not exception details that could contain credentials or remote responses.

For a reliable presentation without external dependencies, run:

```bash
uv run solguard-x402-demo
```

That command is labeled `X402_DEVNET_SIMULATED`; it does not produce a transaction.

## Production gaps

The devnet command keeps its disposable key in process memory because the SDK needs a
signer. Production would require the isolated authorization-verifying signer, managed key
custody, durable authorization and replay state, authenticated configuration, private
RPC/facilitator policy, transaction-level SVM validation, monitoring, and an independent
mainnet security review.
