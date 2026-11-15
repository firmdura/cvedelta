# Synthetic contract examples

SPDX-License-Identifier: Apache-2.0

All files in this directory are original CVEDelta test data. Names, CVE IDs,
reported statuses and provenance are invented; they make no claim about real
product vulnerabilities or remediation. The reports follow the documented
Scarthgap version-1 format. They are separate from the fixture whose bytes
come from the pinned public producer writer.

`baseline.json` and `candidate.json` exercise all five categories, both absence
reasons, version changes, status changes that take precedence over context
changes, native and multilib identities, quoted multiline reasons, and absent
versus empty attributes. Each report's metadata contains its raw checksum.
`database.json` is illustrative data, not a CVE database, and
`coverage-policy.json` is an illustrative policy. Their exact bytes are hashed
in the metadata.

`report-changes.json`, `report-none.json` and `report-incomparable.json` define
expected reports for exits 1, 0 and 3. `outcomes.json` also records the
configuration mismatch that produces exit 2 with no report.

Metadata variants isolate scanner, database and coverage differences, plus
incomplete coverage. The `all` variant combines them. The
`wrong-checksum.meta.json` document has a valid metadata structure but is
intentionally invalid for the report because its report checksum does not match.
