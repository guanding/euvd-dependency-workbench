# Release process

## Two independent lanes

### Lane A — public source repository

The Apache-2.0 project source may be made publicly visible from a fixed clean
commit after the strict source-candidate gate and current CI pass. This lane
publishes Git source only. It does not publish or approve a GitHub Release,
container image, Windows portable bundle, customer data, customer deliverable,
or conformity evidence.

### Lane B — versioned artifacts

This lane is currently **BLOCKED / NOT OFFERED**. No workflow may push a
container image, upload a portable bundle, create a GitHub Release, or publish
a package. Artifact rights, vulnerabilities, provenance, signatures, platform
tests, support terms, and exact hashes require a separate decision.

## Current roles and assurance

Ding Guan (`@guanding`) is the sole maintainer, copyright holder, source
rights declarant, security contact, and conduct moderator. There is no alternate
or independent reviewer. Source publication is explicitly recorded as
`SOLE_MAINTAINER_SELF_REVIEW`; CODEOWNERS and CI do not turn it into
independent approval.

Independent review may be requested for a future artifact, but it is not a
condition imposed on public source visibility and must never be fabricated.

## Source-publication procedure

1. Freeze a clean commit and confirm the explicit public allowlist.
2. Run the strict candidate builder; verify the exact-set manifest and source
   visibility status.
3. Scan the clean tree and its short public history for secrets, customer data,
   local paths, private runtime state, and excluded binaries.
4. Run the current CI/security workflows. They may build images for smoke tests
   but must not publish them.
5. Confirm README, LICENSE, NOTICE, THIRD_PARTY_NOTICES, SECURITY, SUPPORT, and
   contribution terms agree with the source-only boundary.
6. Change repository visibility to public, enable private vulnerability
   reporting and CodeQL default setup, then verify the public clone and checks.

## Future artifact procedure

Before any tag, GitHub Release, container image, or portable bundle:

1. freeze the exact commit, platform matrix, and artifact allowlist;
2. review every direct/transitive dependency and container layer for
   authoritative licenses, notices, compatibility, and source obligations;
3. reproduce builds and run supported-platform, receiving-machine, and
   vulnerability tests;
4. generate exact manifests, hashes, SBOMs, provenance/attestations, and
   signatures;
5. record support, rollback, revocation, and disclosure terms;
6. authorize only the named hashes, with the review model honestly labeled.

Rebuilding after authorization invalidates the artifact decision.
GitHub-generated source snapshots are not controlled artifact releases.

## CodeQL

The repository contains the intended CodeQL scope configuration. Enable GitHub
CodeQL default setup immediately after the repository becomes public, or later
add an advanced workflow pinned to a maintainer-verified full action SHA.
