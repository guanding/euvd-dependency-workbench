# Public release builder

Build candidates only through the explicit allowlist:

```bash
python3 release/build_public_candidate.py --output /tmp/euvd-workbench-public
```

Use `--strict` for the formal release gate. It verifies the canonical
Apache-2.0 license, the Ding Guan copyright notice, third-party rights status,
and source cleanliness. It intentionally returns non-zero while any required
release decision remains pending.

The public source candidate excludes the PRO-03B-derived XLSX asset until its
redistribution rights receive named approval. The builder does not establish
copyright ownership, customer-data clearance, conformity, certification, or
release approval.
