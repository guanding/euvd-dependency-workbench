# Public release builder

Build candidates only through the explicit allowlist:

```bash
python3 release/build_public_candidate.py --output /tmp/euvd-workbench-public
```

Use `--strict` for the public-source visibility gate. It verifies the
canonical Apache-2.0 license, the Ding Guan copyright notice, source rights,
and source cleanliness. A passing result means only that the allowlisted source
is eligible for public Git visibility.

The public source candidate excludes the PRO-03B-derived XLSX asset until its
redistribution rights receive explicit approval. The builder does not approve a
GitHub Release, image, portable bundle, copyright ownership, customer-data
clearance, conformity, certification, or artifact distribution.
