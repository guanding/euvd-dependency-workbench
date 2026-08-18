# Release process

## Release state

All project-authored material in the public-source candidate is declared by
Ding Guan as independently authored, free of customer or third-party material,
and licensed under Apache-2.0, Copyright 2026 Ding Guan. Public release remains
blocked because third-party dependencies and distribution inputs are not
approved, CodeQL is not yet enabled, and no reviewed container vulnerability
scanner is configured. The portable exporter uses a tested explicit allowlist,
but Windows receiving-machine execution and the final fixed candidate still
require independent validation.

No automated publishing workflow is provided while those conditions remain.
A workflow artifact, local ZIP, container image, SBOM, signature, or green CI
run is a candidate only.

## Roles

Assign named people for each release:

- **Release owner:** fixes the commit and exact artifact set.
- **Rights reviewer:** approves the project license, dependencies, templates,
  data, images, and notices.
- **Security/supply-chain reviewer:** independently reviews secret scans,
  vulnerabilities, build provenance, SBOMs, and signatures.

The rights reviewer and security/supply-chain reviewer must not both be
replaced by the release owner. CODEOWNERS routing alone is insufficient.

## Procedure

1. **Freeze scope.** Start from a clean protected branch, record the commit
   SHA, version, supported Python versions, target platforms, and artifact
   allowlist.
2. **Close rights gates.** Verify the recorded Apache-2.0 grant and NOTICE are
   present in the exact source and container release bytes. Verify the image
   copies `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md` to `/app/licenses/`.
   Approve `THIRD_PARTY_NOTICES.md`; remove every unapproved asset.
3. **Sanitize.** Scan the current tree, full Git history, binaries, archives,
   Office metadata, container layers, and generated outputs for secrets,
   personal data, customer data, local paths, and internal-only material.
4. **Verify in clean environments.** Run CI on the supported Python matrix,
   build the container from the frozen commit, and smoke-test it without local
   data. Rebuild any Windows portable artifact from an explicit allowlist on a
   clean machine.
5. **Run security gates.** Complete dependency audit, CodeQL, approved
   full-history secret scanning, and a reviewed digest-pinned container
   vulnerability scan. Document any time-bounded exception with owner and
   expiry.
6. **Create evidence.** Produce checksums, an exact-set manifest, SPDX or
   CycloneDX SBOMs, provenance/attestations, and signatures for every released
   artifact.
7. **Independent review.** Both reviewers examine the fixed commit and final
   artifact hashes. Rebuilding after review invalidates that approval.
8. **Publish.** Create a signed annotated tag and GitHub Release only after all
   items in `PUBLIC_RELEASE_CHECKLIST.md` are complete.
9. **Post-release.** Verify downloads, hashes, signatures, documentation, and
   vulnerability-reporting access from a separate account/machine. Record the
   rollback or revocation path.

## Expected artifacts

At minimum, an approved release should contain a controlled source archive,
container image by immutable digest, checksums, release notes, dependency
notices, SBOMs, and provenance. A Windows portable artifact is optional and
must not be published until its export implementation excludes `.git`,
backups, runtime/work data, caches, and unapproved assets by construction.

GitHub-generated source snapshots must be evaluated separately from controlled
release archives because their byte set and timestamps may differ.

## CodeQL activation

`.github/codeql/codeql-config.yml` defines the intended analysis scope. No
advanced CodeQL workflow was added because a trustworthy full commit SHA for
`github/codeql-action` was not available in the offline authoring environment.
Before release, either enable GitHub CodeQL default setup and record a
successful analysis, or add an advanced workflow using a maintainer-verified
full action SHA. A mutable reference such as `@v3` is not acceptable.
