# Contributing to SolGuard

## Branch model

SolGuard uses two long-lived branches:

- `develop` is the integration branch for active development.
- `main` contains release-ready work only.

Feature and repair work should branch from `develop` and return to `develop`. A release pull request promotes the verified state of `develop` into `main`.

```text
feature/<issue>-<slug> -> develop -> main
```

Do not push feature work directly to `main`. Force pushes and branch deletion are disabled for both long-lived branches.

## Development workflow

1. Start from the latest `develop` branch.
2. Create a narrowly scoped branch named `feature/<issue>-<slug>`, `fix/<issue>-<slug>`, or `docs/<issue>-<slug>`.
3. Implement one issue and its tests.
4. Run the complete local verification suite.
5. Open a pull request into `develop` and complete the repository checklist.
6. Merge only after all configured checks pass and conversations are resolved.

## Release workflow

1. Confirm every included issue is implemented and verified.
2. Confirm the complete test suite and security checks pass on `develop`.
3. Open a release pull request from `develop` into `main`.
4. Describe the verified functionality, test evidence, known limitations, and rollback plan.
5. Squash-merge only when the release candidate is ready to represent the public production baseline.

No direct feature branch should target `main`.

## Security requirements

- Never commit credentials, wallet keys, seed phrases, tokens, or populated `.env` files.
- Use fixed-precision financial values; never binary floating point for money.
- Keep security decisions fail closed.
- Add tests for every changed security invariant.
- Do not present simulated activity as real settlement.
- Do not add placeholder statistics that appear to be runtime evidence.
- Report vulnerabilities through GitHub private vulnerability reporting, following `SECURITY.md`.

## Completion standard

An issue is complete only when its acceptance criteria are implemented, its tests pass, the existing suite remains green, and the feature has been run successfully at least once.
