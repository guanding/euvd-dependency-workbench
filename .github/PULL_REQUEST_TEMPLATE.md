## Summary

Describe the problem, the bounded change, and the observable outcome.

## Verification

- [ ] `ruff check app tests scripts release`
- [ ] `python -m unittest discover -s tests`
- [ ] Version consistency was checked when release-facing behavior changed.
- [ ] Container build/smoke testing was performed when runtime behavior changed.

## Rights, data, and security

- [ ] No customer data, credentials, embargoed vulnerability details, local databases, backups, or machine-specific paths were added.
- [ ] New dependencies and copied/generated assets have source, version, hash, license, and redistribution status recorded.
- [ ] No `NOT_APPROVED` or `AWAITING_NAMED_REVIEW` material is presented as releasable.
- [ ] Security-sensitive changes include a threat/abuse-case note and regression coverage.

## Release boundary

- [ ] I understand that CI success is not public-release, customer-delivery, or conformity approval.
- [ ] If this changes a release artifact, the fixed commit and exact artifact set will receive independent review under `RELEASE_PROCESS.md`.
