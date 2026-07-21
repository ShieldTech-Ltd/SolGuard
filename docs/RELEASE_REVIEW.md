# Demonstration Release Review

Review date: 2026-07-21

## Frozen build

- Source commit: [`dd0a157fd73955fb4257b915ee65ef20ba70c05c`](https://github.com/ShieldTech-Ltd/SolGuard/commit/dd0a157fd73955fb4257b915ee65ef20ba70c05c)
- Signed tag: [`v0.1.0-demo`](https://github.com/ShieldTech-Ltd/SolGuard/tree/v0.1.0-demo)
- GitHub tag verification: valid SSH signature
- Source status: merged into `develop` through PR #24
- Required CI: [`Verify Python 3.11`](https://github.com/ShieldTech-Ltd/SolGuard/actions/runs/29869626614/job/88766319383), passed
- Dependency graph update: [`update-uv-graph`](https://github.com/ShieldTech-Ltd/SolGuard/actions/runs/29869630365/job/88766335748), passed

The evidence manifest, recording, and static states all name this commit. The evidence
packaging changes are intentionally separate from the frozen source tag.

## Verification results

The full locked suite was run on Windows with Python 3.11.9 and uv 0.11.30:

- Ruff lint: passed.
- mypy strict type checking: passed for 29 source files.
- pytest: 266 passed in 6.63 seconds.
- Coverage: 1428 statements and 304 branches, 100% reported coverage.
- Lock validation: `uv lock --check` passed.
- Three fresh `solguard.demo --skip-paysh` processes: all returned `VERIFIED`.

The three independent fallback runs completed in 6.8929 ms, 9.4199 ms, and 7.6594 ms.
Each produced a compound-drain `BLOCK`, `NOT_SIGNED`, unchanged post-baseline balance,
and a successful recovery payment.

On this Windows checkout, `core.autocrlf=true` converts existing tracked Python files to
CRLF, so a local `ruff format --check .` reports 22 existing files as different from the
configured LF form. The exact frozen commit's required Ubuntu CI formatting check
passed. No source file was reformatted merely to conceal that host-specific difference.

## Local decision benchmark

Environment:

- Microsoft Windows 11 Home 10.0.26200
- 12th Gen Intel Core i5-12500H, 16 logical processors
- Python 3.11.9
- uv 0.11.30

Method: 500 sequential `PaymentGateway.process` calls with a deterministic clock, valid
known-recipient requests, all local security controls, and in-memory simulated
settlement. Network activity and Pay.sh settlement are excluded.

| Metric | Measured result |
|---|---:|
| Allowed decisions | 500 |
| Other decisions | 0 |
| Minimum | 0.0992 ms |
| Median | 0.1222 ms |
| Mean | 0.1515196 ms |
| p95 | 0.2561 ms |
| Maximum | 0.5068 ms |

Reproduce from the frozen source:

```powershell
uv run --with pillow --with qrcode --with imageio --with imageio-ffmpeg `
  python scripts/generate_release_evidence.py --output evidence --iterations 500 `
  --source-commit v0.1.0-demo
```

Results vary by host and run. Do not compare these local figures to network settlement
latency.

## External sandbox observation

One Pay.sh sandbox demonstration returned `SETTLED` for a 0.01 USDC request and then
completed the same local attack/recovery sequence. Its total command duration was
5433.5796 ms. This is a single captured sandbox observation, not a latency benchmark,
mainnet payment, or production availability claim.

## Dependency and repository security review

- The project declares no runtime Python dependencies.
- `uv.lock` was exported with all development groups; pip-audit checked the 13
  applicable third-party packages and reported no known vulnerabilities on 2026-07-21.
- GitHub secret scanning, secret-scanning push protection, and Dependabot security
  updates are enabled.
- Safe API queries returned zero open secret-scanning alerts and zero open Dependabot
  alerts at review time.
- A local `detect-secrets` scan of the changed non-binary files reported only the public
  Pay.sh sandbox recipient address and evidence digest/hash fields. They were reviewed
  as non-secret evidence values.
- `main` and `develop` require the `Verify Python 3.11` check, current branches, pull
  requests, linear history, resolved conversations, and administrator enforcement.
  Force pushes and branch deletion are disabled.
- GitHub code scanning has no analysis configured. Required approving review count is
  zero and signed commits are not enforced by branch protection. Those are explicit
  hardening gaps, not passing controls.

No secret value was printed or retained during this review.

## Evidence integrity

[`evidence/manifest.json`](../evidence/manifest.json) records the exact source commit,
labels, artifact sizes, and SHA-256 hashes. Independent media inspection confirmed 750
frames at 10 fps, a 75-second duration, H.264 video, yuv420p pixel format, and 1440 x 900
resolution. The QR image decoded to the repository URL.

## Known limitations and release decision

This is an evidence-backed demonstration release, not a production release. Remaining
gaps include process-local replay and authorization state, no tenant isolation or
authenticated policy administration, no hardened key custody, no high-availability
design, no code-scanning workflow, no independent assessment, and only one external
sandbox adapter. x402 is not implemented.

The tagged build is suitable for the documented sandbox/offline demonstration. It is
not approved for real funds, production traffic, or security guarantees beyond the
verified scenarios.
