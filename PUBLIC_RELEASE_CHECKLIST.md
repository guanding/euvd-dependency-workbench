# Public source and artifact release checklist

## Current state

| Lane | Status |
| --- | --- |
| Public GitHub source repository | **ELIGIBLE** when the fixed clean commit passes current CI and the strict source-candidate gate |
| GitHub Release or signed tag | **BLOCKED / NOT OFFERED** |
| Container image or registry publication | **BLOCKED / NOT OFFERED** |
| Windows portable bundle | **BLOCKED / NOT OFFERED** |
| Customer delivery or conformity evidence | **OUT OF SCOPE** |

Repository visibility and artifact distribution are separate decisions. Making
the source repository public does not approve a GitHub Release, package,
container image, portable bundle, customer delivery, or CRA conclusion.

## Solo-maintainer record

Ding Guan (`@guanding`) is the copyright holder, repository owner, source
rights declarant, security contact, and conduct moderator. The project has no
second reviewer or alternate contact. Source-publication decisions are
therefore maintainer self-review and must not be described as independent or
four-eye approval.

## Source repository visibility gate

For the exact commit made public:

- [ ] the worktree is clean and `release/build_public_candidate.py --strict`
      reports `source_repository_publication_eligible: true`;
- [ ] current CI and security workflows pass from a clean clone;
- [ ] the Apache-2.0 `LICENSE`, `NOTICE`, and source-only rights record agree;
- [ ] the explicit allowlist excludes the PRO-03B-derived workbook, live EUVD
      snapshots, customer/runtime data, outputs, backups, caches, and secrets;
- [ ] the Git history and public Actions logs/artifacts contain no customer,
      credential, local-path, or internal-only material;
- [ ] no workflow can publish a Release, package, portable bundle, or image;
- [ ] GitHub private vulnerability reporting is enabled after visibility changes;
- [ ] README, SECURITY, and SUPPORT describe an unreleased source preview with
      no SLA and no conformity/customer-evidence claim.

A single CODEOWNER is valid for this project. Automated checks are technical
gates, not independent approval.

## Artifact distribution gate

Keep every artifact lane blocked until the exact proposed bytes have:

- [ ] a complete direct/transitive license, notice, compatibility, and
      source-obligation review;
- [ ] an exact manifest, hashes, SBOM, provenance/attestation, and signature;
- [ ] a reviewed vulnerability scan for every container architecture;
- [ ] clean-platform reproduction and documented installation/smoke tests;
- [ ] Windows receiving-machine validation for any portable bundle;
- [ ] support, maintenance, rollback, and disclosure terms for the version;
- [ ] a recorded maintainer authorization naming the exact commit and hashes.

If an independent reviewer is unavailable, do not invent one. Record
`SOLE_MAINTAINER_SELF_REVIEW` and the resulting assurance limitation.

CI success, an SBOM, a hash, or a signature does not by itself authorize
artifact distribution or establish customer delivery, certification, or
conformity.
