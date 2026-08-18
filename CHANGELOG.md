# Changelog

All notable changes to this project are documented here. The project has not
yet published a stable public release.

## 2.4.0-rc.1 - Unreleased

### Added

- Explicit, fail-closed public-source and Windows portable allowlists.
- Synthetic clean-clone snapshot bootstrap and an explicit Mirror boundary.
- GitHub CI, supply-chain inventory, governance, security, and release-gate
  documents.
- Accessibility and public-release contract tests.
- Apache License 2.0 project licensing and the Ding Guan copyright notice.

### Changed

- VEX intake now requires a matching receipt and admitted issuer ID.
- Spreadsheet exports neutralize formula-like untrusted cell values.
- Template tooling is implemented with public Python dependencies.
- Application, container, UI, and documentation versions are aligned.
- CSV encoding detection is a pinned runtime dependency so clean environments
  preserve both cp1252 and GB18030 input instead of taking an environment-
  dependent fallback.
- Container SBOM generation scans a read-only image archive and no longer
  grants the scanner container access to the Docker daemon socket.
- Runtime dependencies now use a cross-platform transitive lock with hashes;
  Docker, CI, and the Windows runtime installer fail closed on hash mismatch.
- Windows bootstrap uses a fixed, hash-verified pip zipapp and no longer runs
  the mutable `get-pip.py` endpoint or installs pip into the runtime bundle.

### Security and compatibility notes

- The default VEX issuer registry is empty and therefore fails closed.
- The built-in database is synthetic and reports degraded status; it is never
  a production EUVD fallback.
- Windows receiving-machine execution, full accessibility testing, native
  AMD64 verification, and container vulnerability scanning remain release
  gates.
- Project-owned source is licensed under Apache-2.0. Third-party rights,
  release governance, and independent validation remain open, so this
  candidate is not yet approved for public release or customer delivery.
