# Pay.sh Sandbox Integration

SolGuard supports one real external sandbox path through the official Pay CLI. The integration is deliberately optional: the deterministic simulated settlement path remains fully operational without Pay.sh, network access, Node.js, or wallet tooling.

## Install the official CLI

Follow the current [Pay.sh installation guide](https://pay.sh/docs/get-started/install). The supported npm route is:

```bash
npm install -g @solana/pay
pay --version
```

Sandbox mode creates and funds an ephemeral local wallet. Do not configure, import, export, or fund a mainnet account for this demonstration.

## Run one sandbox purchase

From the repository:

```bash
uv run solguard-paysh
```

The command defaults to the official debugger endpoint from the [Pay.sh client quickstart](https://pay.sh/docs/get-started/client-quickstart):

```text
https://debugger.pay.sh/mpp/quote/AAPL
```

If `pay` is not on `PATH`, provide the executable without placing a credential or key in the repository:

```powershell
$env:SOLGUARD_PAY_EXECUTABLE = "C:\path\to\pay.exe"
uv run solguard-paysh
```

## Security flow

1. SolGuard sends an unsigned probe to the configured HTTPS endpoint.
2. The endpoint must return an HTTP 402 `Payment` challenge.
3. The adapter strictly validates the MPP Solana sandbox charge, localnet, USDC mint, amount, decimals, recipient, and expiry.
4. Those requirements become a canonical `PaymentRequest` with the challenge identifier as its nonce.
5. The standard integrity, mandate, and behavioural gateway evaluates the request.
6. The Pay.sh wallet boundary validates and consumes the short-lived request-bound SolGuard authorization.
7. Only a valid, unused authorization invokes `pay --no-dna --sandbox fetch <endpoint>`.
8. The command emits only safe computed evidence: response length and digest, sanitized endpoint, amount, recipient, and a request-bound local settlement reference.

`BLOCK`, `REQUIRE_APPROVAL`, and rejected wallet authorizations never start the Pay process. Provider headers, descriptions, and responses are treated as untrusted. Query values, response bodies, CLI diagnostics, and wallet output are excluded from normal decision evidence.

## Result statuses

- `SETTLED`: SolGuard allowed the request and the Pay sandbox command returned a bounded response.
- `SECURITY_REJECTED`: policy, integrity, or behavioural controls stopped the request before Pay was invoked.
- `SETTLEMENT_UNAVAILABLE`: SolGuard reached `ALLOW`, but the external command timed out, failed, or returned an invalid response. The final outcome fails closed with `SETTLEMENT_UNAVAILABLE` and records `security_decision: ALLOW` separately.
- `NETWORK_FAILURE` or `PROTOCOL_FAILURE`: the initial challenge could not be retrieved or validated, so no gateway authorization or payment attempt occurred.

The `paysh:sandbox:sha256:` reference is computed locally from the successful Pay response digest, exact canonical request digest, endpoint, and SolGuard authorization identifier. It is evidence of this sandbox execution path, not a mainnet transaction signature.

## Reliable fallback

If Pay.sh or the network is unavailable, use the fully tested local demonstration:

```bash
uv run solguard-dashboard
```

The fallback is labelled `SIMULATED` throughout its receipts and interface. External integration failure must never prevent the local security demonstration from running.
