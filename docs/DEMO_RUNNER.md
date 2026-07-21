# Deterministic Demonstration Runner

`solguard-demo` packages the complete technical proof into one command while keeping external and simulated activity explicitly separated.

## Run the full path

After installing the official Pay CLI:

```bash
uv run solguard-demo
```

The command attempts one legitimate Pay.sh ephemeral-wallet sandbox purchase, then runs the deterministic local baseline, compromised-agent attack, pre-signing block, reset, and recovery sequence.

If `pay` is not on `PATH`, set `SOLGUARD_PAY_EXECUTABLE` or pass `--pay-executable`.

## Run the offline fallback

```bash
uv run solguard-demo --skip-paysh
```

This path has no external service dependency. It reports the external stage as `SKIPPED` and labels every local settlement value `SIMULATED`.

If Pay.sh is requested but unavailable, the command labels the external failure and still completes the verified local demonstration. External failure never changes local security decisions.

## Runtime-derived evidence

The JSON report contains only values produced by the current run:

- Total measured command duration
- External decision, status, and safe settlement evidence
- Initial, post-baseline, post-attack, and recovery wallet balances
- Baseline, attack, and recovery decision counts
- Number of attack attempts observed
- Latest attack decision and stable reason codes
- Explicit signing state and absent settlement reference for the block
- Value protected by blocked attempts
- Separate `PAYSH_SANDBOX` and `SIMULATED` settlement labels

The runner validates that baseline traffic is allowed, an attack block occurs, attack traffic does not change the post-baseline balance, the latest attack has no signature or settlement, and a clean recovery payment succeeds. It returns `LOCAL_DEMO_FAILED` rather than printing a successful report if any invariant is missing.

Provider response bodies, payment diagnostics, injected metadata secrets, and wallet material are not included in the report. The runner offers no control for entering an arbitrary recipient, amount, or wallet operation.

## Presentation use

Use the JSON command as machine-verifiable evidence and the local dashboard as the visual presentation surface. A recording and static presentation assets remain separate launch-readiness work; simulated and sandbox activity must retain their labels in those assets.
