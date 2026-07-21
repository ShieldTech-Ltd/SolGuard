# SolGuard Release Evidence

This directory is the offline evidence package for the source build tagged
[`v0.1.0-demo`](https://github.com/ShieldTech-Ltd/SolGuard/tree/v0.1.0-demo), commit
`dd0a157fd73955fb4257b915ee65ef20ba70c05c`.

## Offline playback

Play [`solguard-offline-demo.mp4`](solguard-offline-demo.mp4) with any H.264-capable
player. The recording is 75 seconds, 1440 x 900, 10 frames per second, and does not
need a network connection.

The static normal, attack, blocked-wallet, and recovery states are under
[`screenshots/`](screenshots/). They are rendered from the recorded runtime JSON; they
are not browser captures. Every state is labelled `SIMULATED`, and the external result
is labelled `PAYSH_SANDBOX`.

## Machine-readable proof

- [`runtime-checkpoints.json`](data/runtime-checkpoints.json) contains the values used
  in the static evidence frames.
- [`clean-process-runs.json`](data/clean-process-runs.json) contains three independent
  local fallback runs.
- [`external-demo-run.json`](data/external-demo-run.json) contains one captured Pay.sh
  sandbox result plus the local attack and recovery sequence.
- [`benchmark.json`](data/benchmark.json) contains the local-only gateway measurements.
- [`dependency-audit.json`](data/dependency-audit.json) records the dependency audit
  result; [`locked-requirements.txt`](data/locked-requirements.txt) is its input.
- [`manifest.json`](manifest.json) binds the evidence files to the source commit with
  SHA-256 hashes.

None of these files proves a mainnet payment, production deployment, customer usage,
or an independent security assessment.

## Regenerate the runtime assets

From the evidence-packaging branch with the locked development environment installed:

```powershell
uv run --with pillow --with qrcode --with imageio --with imageio-ffmpeg `
  python scripts/generate_release_evidence.py --output evidence --iterations 500 `
  --source-commit v0.1.0-demo
```

The generator resolves the tag to its commit and refuses to run if `src/`,
`pyproject.toml`, or `uv.lock` differs from that frozen build.

That command captures the external-independent path. To capture Pay.sh sandbox evidence,
add `--pay-executable C:\path\to\pay.exe`. Do not use or import a funded wallet.
