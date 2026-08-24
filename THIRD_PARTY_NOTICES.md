# Third-party material register — draft

**Third-party release status: NOT APPROVED FOR PUBLIC DISTRIBUTION.**

This file is a release-preparation register. It is not a license grant, legal
opinion, compatibility decision, or authorization to redistribute any item.
Every entry requires named rights review against the exact release bytes.

## Project-owned material

All project-authored source code, documentation, configuration data, synthetic
examples, and test fixtures included in the public-source candidate were
declared by Ding Guan on 2026-08-17 to be independently authored and to contain
no customer or third-party material. They are licensed under the Apache License
2.0; see `LICENSE` and `NOTICE`. That project license does not grant rights to
dependencies, container layers, third-party specifications, facts, names,
trademarks, tools, or other separately governed inputs listed below.

Source archives retain those files at their root. The project container image
retains `LICENSE`, `NOTICE`, and this register under `/app/licenses/`. Their
presence records the project grant and the unresolved third-party boundary; it
does not approve or relicense any dependency or base-image component.

## Declared Python dependencies

The current runtime declaration includes:

| Package | Declared version | Rights status |
| --- | --- | --- |
| FastAPI | 0.140.7 | License and notice review required |
| Starlette | 1.3.1 | License and notice review required |
| Uvicorn with `standard` extra | 0.51.0 | License and transitive-extra review required |
| python-multipart | 0.0.32 | License and notice review required |
| HTTPX | 0.28.1 | License and notice review required |
| openpyxl | 3.1.5 | License and notice review required |
| packaging | 26.2 | License and notice review required |
| charset-normalizer | 3.4.9 | MIT metadata; authoritative license and notice review required |

This human-readable table lists direct inputs only. `requirements.lock`
enumerates the current 28-package cross-platform graph (27 packages on Linux
plus Windows-only `colorama`) and records distribution hashes. The lock and
CI-generated metadata inventory are technical evidence only; package metadata
is not a substitute for reviewing authoritative license texts, notices,
source-offer obligations, or compatibility with the project's Apache-2.0
license.

## Container and build inputs

| Item | Current identity | Rights status |
| --- | --- | --- |
| Python builder image | Digest recorded in `Dockerfile` | Image contents and redistribution terms require review |
| Chainguard Python runtime image | Digest recorded in `Dockerfile` | Image contents and redistribution terms require review |
| Anchore Syft | `v1.50.0` image digest recorded in repository | Tool/image license and notices require review |
| PyPA pip zipapp | `26.2.1` URL and SHA-256 recorded in `scripts/setup-runtime.ps1` | Build-only Windows bootstrap; provenance and tool-license review required |
| GitHub Actions | Full commit SHAs recorded in workflow files | Marketplace/source licenses and update provenance require review |

Pre-review scans of the pinned runtime image on ARM64 and AMD64 each found 27
Python packages and 25 Wolfi APK packages. The package metadata includes
GPL-3.0-or-later, LGPL-2.1-or-later, MPL-2.0, PSF-2.0, Apache-2.0, MIT, BSD and
compound expressions. This observation is not a compatibility decision. The
final per-architecture image digest, complete SBOM, license texts, modification
status, and any corresponding-source or notice mechanism still require named
review before distribution.

The `uv`, `ruff`, and `pip-audit` CI tool graph is separately fixed with hashes
in `requirements-dev.lock` and installed outside the runtime environment. That
integrity record does not replace license, notice, or GitHub Actions review.

## Templates and generated assets

`app/assets/客户SBOM导入模板_PRO-03B_v1.4兼容版.xlsx` is described by its
generator as derived from a PRO-03B workbook. The original workbook rights,
the authority to create and distribute the derivative, embedded metadata, and
required attribution have not received named public-release approval.

No template, screenshot, sample, database extract, generated report, or other
asset may enter a public release merely because it is tracked in Git.

The public-source candidate contains the project-authored
`config/product-aliases.csv` and `tests/fixtures/e2e-cve-sbom.csv`. Ding Guan
declared both files independently authored and free of customer or third-party
material. Product, vendor, package and vulnerability identifiers in them are
treated only as factual interoperability/test labels; no ownership of
third-party names or trademarks is claimed. The exact approved scope is
recorded in `release/rights_review.json`.

## Required release evidence

Before changing this status, attach to the fixed release commit:

1. the exact direct and transitive dependency set with hashes;
2. authoritative license texts and required notices;
3. a compatibility/obligations review;
4. a source and rights decision for each template and asset;
5. the name, date, and scope of the approving rights reviewer.
