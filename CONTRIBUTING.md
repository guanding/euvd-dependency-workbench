# Contributing

## Current contribution boundary

Project source code and documentation owned by Ding Guan are licensed under
Apache License 2.0. Unless explicitly stated otherwise, contributions
intentionally submitted for inclusion are provided under Section 5 of that
license. Contributors must have the right to submit their work and must not
submit customer, confidential, or unapproved third-party material. Repository
publication, support channels, and contribution intake remain subject to the
release gates in `PUBLIC_RELEASE_CHECKLIST.md`.

## Development checks

Use a clean checkout and a supported Python interpreter. The intended local
checks are:

```text
python -m pip install --require-hashes -r requirements.lock
python -m venv .ci-tools
.ci-tools/bin/python -m pip install --require-hashes -r requirements-dev.lock
.ci-tools/bin/ruff check app tests scripts release
python scripts/check_version_consistency.py --no-health
python -m unittest discover -s tests
docker build -t euvd-dependency-workbench:local .
```

These commands are engineering checks only. They do not establish release or
customer-delivery approval.

## Pull request requirements

- Keep changes bounded; avoid unrelated formatting churn.
- Add or update tests for observable behavior.
- Use synthetic or explicitly redistributable fixtures.
- Never commit customer uploads, jobs, databases, output packages, backups,
  credentials, local runtime files, or machine-specific paths.
- Record source, version, cryptographic hash, license candidate, and named
  redistribution decision for every copied or generated third-party asset.
- Treat `NOT_APPROVED` and `AWAITING_NAMED_REVIEW` as fail-closed states.
- Explain any change to matching confidence, evidence semantics, export scope,
  or security boundaries.

The PR template is the minimum evidence set. Release-affecting changes require
a second independent reviewer under `RELEASE_PROCESS.md`.

## Commit and review expectations

Write focused commits with an imperative summary. Do not rewrite another
contributor's history. A CODEOWNER review routes responsibility but does not
replace rights review, security review, or release approval.
