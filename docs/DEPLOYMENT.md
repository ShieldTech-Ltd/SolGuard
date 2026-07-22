# Hosted demonstration

The public dashboard is a demonstration surface for the running SolGuard gateway. It is
not a production payment service. Every security decision is computed by the Python
gateway; settlement remains explicitly labelled `SIMULATED` unless separately verified
devnet evidence is supplied.

## Render deployment

The repository includes a Render Blueprint in `render.yaml`. It creates one Python web
service in Frankfurt, installs the package, starts the dashboard on Render's assigned
port, and checks `/healthz` before routing traffic. Automatic deployments wait for the
linked commit's checks to pass.

New Render services currently default to Python 3.14, which is outside this project's
supported range. The existing committed `.python-version` intentionally selects Python
3.11.

1. In Render, choose **New > Blueprint**.
2. Connect `ShieldTech-Ltd/SolGuard`.
3. For a temporary review deployment, select `feature/stage-dashboard`. After the pull
   request is reviewed and merged, deploy the protected integration branch instead.
4. Confirm the Blueprint path is `render.yaml` and create the service.
5. Wait for the health check to pass, then open the generated `onrender.com` URL.
6. Run all four dashboard scenarios and confirm the page still says
   **SIMULATED SETTLEMENT**.

No wallet key, RPC credential, Pay.sh credential, or x402 secret is required or permitted
for this hosted fallback. Do not add secrets to the Blueprint. A real devnet exercise is
a separate, opt-in CLI path documented in `X402_LIVE_DEVNET.md`.

## Local production-shaped check

Run the same command shape used by Render:

```bash
uv run solguard-dashboard --host 0.0.0.0 --port 10000
```

Then verify:

```bash
curl http://127.0.0.1:10000/healthz
```

Expected response:

```json
{"service":"solguard-dashboard","settlement":"simulated","status":"ok"}
```

The dashboard state is intentionally process-local and resets on restart. This keeps the
fallback deterministic and avoids presenting the prototype as durable production
infrastructure.
