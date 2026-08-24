# Public release checklist

**Current readiness: BLOCKED. Do not create a public repository or GitHub
Release from the current candidate.**

Copy this checklist into the release record for one fixed commit and exact
artifact set. Do not inherit checkmarks from an older build.

## Repository and governance

- [ ] GitHub remote ownership, visibility, branch protection, and required
      checks are approved.
- [ ] `CODEOWNERS` resolves to at least two active, independent reviewers for
      release-sensitive paths.
- [ ] Named security and conduct contacts, including alternates, are configured.
- [ ] `SECURITY.md`, `SUPPORT.md`, contribution terms, and response targets match
      the versions actually offered.
- [ ] Issue/PR templates were tested on the public repository.

## Rights

Standing decision: all project-authored source code, documentation,
configuration data, synthetic examples, and test fixtures in the public-source
candidate are independently authored by Ding Guan, contain no customer or
third-party material, and are licensed under Apache-2.0. The checkbox below
verifies one fixed release; it does not approve dependencies, container layers,
third-party facts, names, trademarks, tools, or separately governed inputs.

- [ ] The exact release contains the official Apache-2.0 `LICENSE` and
      `Copyright 2026 Ding Guan` in `NOTICE`, and package/documentation metadata
      agrees.
- [ ] Every distributed container image contains `LICENSE`, `NOTICE`, and
      `THIRD_PARTY_NOTICES.md` under `/app/licenses/`, verified against the
      fixed image digest.
- [ ] Direct and transitive dependency licenses, required notices, source-offer
      obligations, and compatibility were independently reviewed.
- [ ] The excluded PRO-03B-derived workbook remains absent; every included
      project-authored template/asset matches the recorded author declaration.
- [ ] `THIRD_PARTY_NOTICES.md` names the reviewer, date, scope, and exact bytes;
      no `NOT_APPROVED` or `AWAITING_NAMED_REVIEW` item remains.

## Repository and data hygiene

- [ ] A clean public clone contains no customer upload, job, audit, database,
      output, backup, runtime, self-test, credential, private key, local path,
      `.serena`, or internal-only planning material.
- [ ] An approved scanner checked the current tree and full Git history.
- [ ] Binaries, Office files, archives, generated reports, SBOMs, container
      layers, and metadata were inspected separately.
- [ ] The portable builder uses a tested allowlist and excludes `.git`,
      `backups`, `self-test`, `runtime`, caches, local data, and unapproved assets.

## Build and security

- [ ] CI passes on Python 3.13 and 3.14 from a clean clone.
- [ ] The image is built and smoke-tested from the fixed commit without local
      EUVD or customer data.
- [ ] The fixed image SBOM and license bundle cover the resolved Python and OS
      component graph for every published architecture.
- [ ] Dependabot is active and dependency audit has no unresolved prohibited
      finding.
- [ ] `requirements.lock` was regenerated from the reviewed direct inputs;
      Python 3.13/3.14 and Windows/Linux installations accept only recorded
      distribution hashes.
- [ ] Windows bootstrap downloads the recorded Python archive and fixed pip
      zipapp only after verifying both SHA-256 values on a clean receiver.
- [ ] CodeQL default setup or an advanced workflow with reviewed full action
      SHAs completed successfully.
- [ ] A reviewed digest-pinned container scanner reports zero unwaived critical
      or high findings, or approved time-bounded exceptions are attached.
- [ ] All Actions use verified full commit SHAs and least-privilege permissions.

## Version and artifacts

- [ ] Application, compose image, documentation, release notes, tag, and
      artifact filenames use one approved version.
- [ ] CHANGELOG/release notes describe security, compatibility, migration, and
      known limitations.
- [ ] Each artifact has a SHA-256, exact-set manifest, SPDX or CycloneDX SBOM,
      provenance/attestation, and verifiable signature.
- [ ] A separate reviewer reproduced installation and startup from downloaded
      release artifacts.
- [ ] The signed annotated tag points to the reviewed commit, and the GitHub
      Release contains only reviewed artifact hashes.

## Approval

- [ ] Release owner: name, date, fixed commit.
- [ ] Rights reviewer: name, date, approved artifact hashes.
- [ ] Security/supply-chain reviewer: name, date, approved artifact hashes.
- [ ] Post-release verification and rollback/revocation owner are recorded.

CI success, an SBOM, a hash, a signature, or historical test evidence does not
by itself satisfy this checklist or establish customer delivery, certification,
or conformity.
