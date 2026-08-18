# EUVD Dependency Workbench 2.4.0-rc.1

## Status

`2.4.0-rc.1` is a release candidate, not a released or customer-approved
artifact. `app/version.py` is the version authority; `docker-compose.yml` and
`/api/health` must report the same value.

## Clean-clone smoke path

```bash
python3 scripts/bootstrap_demo_snapshot.py --output-dir data
mkdir -p outputs
docker compose up -d --build
python3 scripts/demo_template_roundtrip.py --output-dir outputs/template-demo
```

The bootstrap record is synthetic and the application reports the snapshot as
degraded. It proves only that the local software path can start and process a
fixture. It is not ENISA data, current vulnerability intelligence, customer
evidence, a CRA Article 14/SRP decision, a conformity assessment, release
approval, or customer-delivery approval.

The container image contains the same tiny fixture so an unmounted image can be
smoke-tested. Compose explicitly overlays it with the files under `data/`.
Production operation must replace that overlay with an approved Mirror-derived
snapshot; the built-in fixture is never a production fallback.

## Mirror boundary

The authoritative Mirror is independently operated and is not implemented in
this repository. Production use requires an approved Mirror database to be
converted by `scripts/build_local_euvd_snapshot.py`. The Web consumer accepts
only `euvd-readonly.sqlite3` together with its matching external SHA-256
sidecar and opens the database read-only. See `mirror/README.md`.

## VEX boundary

VEX intake remains experimental and fail-closed. The endpoint requires all of:

- the original VEX JSON bytes;
- the matching Workbench intake receipt;
- an issuer ID admitted in `app/vex_issuer_allowlist.json`.

The endpoint re-derives document and canonical statement hashes but does not
re-run cosign verification. The default public registry admits no issuer.

## Portable boundary

Portable export uses an explicit source allowlist and never includes runtime,
Git metadata, customer data, databases, reports, backups, or local tool state.
The legacy `-WithData` switch fails before staging. Receiving-machine runtime
installation and Windows execution still require independent validation.

## Release gate

Before changing this RC to a release, require a clean-clone build, exact
dependency environment, full tests, container smoke test, supported-platform
tests, security and accessibility review, third-party rights approval, and an
immutable release manifest reviewed by an independent person.
