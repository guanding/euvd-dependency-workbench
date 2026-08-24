# Mirror component boundary

This public repository contains the read-only Web consumer. It does **not**
contain an ENISA synchronization service and must not be treated as the
authoritative EUVD Mirror.

The production interface is deliberately narrow:

1. An independently operated and approved Mirror synchronizes public source
   data under its own change control.
2. `scripts/build_local_euvd_snapshot.py` copies only its explicit table
   allowlist into `euvd-readonly.sqlite3`, removes Mirror/customer workflow
   tables, runs an integrity check, and emits the external SHA-256 sidecar.
3. This Web application mounts both files read-only and fails closed when the
   sidecar is missing or does not match.

`scripts/bootstrap_demo_snapshot.py` is a separate clean-clone smoke-test path.
Its record is synthetic, visibly degraded, and not ENISA data. A demo PASS only
shows that the local software path runs; it is not current vulnerability
intelligence, customer evidence, a CRA Article 14/SRP decision, a conformity
assessment, or release approval.

Production snapshots and Mirror databases are runtime artifacts. They must not
be committed to this repository or bundled into portable/source releases.
