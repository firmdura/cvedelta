# Quick-start example inputs

These files let you try a comparison without a Yocto build. Follow the
[main README](../../README.md) to build CVEDelta, run the commands from the
repository root and inspect the results.

All files in this directory are original Apache-2.0 fixtures. The identifiers,
revisions, database contents and coverage declarations are invented. These
files are not Yocto build outputs or NVD data, and their metadata should not
be copied into a production comparison.

Comparing `baseline.json` with `candidate.json`, using their corresponding
`.meta.json` files, produces exit 1 and three findings:

| CVE ID | Category | Example change |
| --- | --- | --- |
| `CVE-2099-0001` | `status_changed` | `Unpatched` becomes `Patched`; the version and detail text also change. |
| `CVE-2099-0002` | `no_longer_reported` | The finding disappears, but its component remains present (`finding_absent`). |
| `CVE-2099-0003` | `new` | The candidate adds the finding. |

These are changes in reported information, not evidence of remediation.

`candidate-database.meta.json` differs from `candidate.meta.json` only in its
database hash: it refers to `database-other.json` instead of `database.json`.
Using it produces exit 3 with the same finding changes, even with
`--fail-on none`, because the declared database snapshots differ.

The metadata includes hashes of the exact report, database and serialized
coverage-policy bytes. The comparison command receives only the reports and
metadata; it checks the report hashes and trusts the database and coverage
declarations. The [provenance guide](../../docs/provenance.md) explains how to
capture this information for real builds. The acceptance checks verify these
example files without rewriting them.
