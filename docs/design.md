# CVEDelta v1.0.0 design

This document describes CVEDelta v1.0.0 scope, comparison rules, and verification
requirements. For installation and current usage, start with the
[README](../README.md).

## Objective

Deliver an offline Go library and CLI that compare two Yocto cve-check JSON
reports for the same firmware configuration. Make finding changes easy to
review without treating a missing finding or scanner status as proof of
remediation.

## Supported input and provenance

The release supports only the `version: "1"` report format documented for
[Yocto Scarthgap](https://docs.yoctoproject.org/scarthgap/dev-manual/vulnerabilities.html).
A report has a top-level `package` array. Each package has `name`, `layer`,
`version` and an `issue` array; each issue has `id` and `status`. Recognized
optional issue attributes are `detail`, `description`, `summary`, `link`,
`modified`, `scorev2`, `scorev3`, `scorev4`, `vector` and `vectorString`.
`products` and other additional report metadata are accepted but ignored.
This is one version-1 adapter, not generic scanner or schema support.

Every report must have a separate metadata document supplied by the caller.
The [metadata schema](../schemas/metadata-v1.schema.json) requires:

- `schema_version: 1` and the raw report's SHA-256.
- Firmware configuration and build IDs, plus an immutable source revision.
- Scanner name `yocto-cve-check` and an immutable producer revision.
- The SHA-256 of the actual CVE database snapshot used for the scan.
- The coverage policy's SHA-256 and an explicit completeness boolean.

`configuration_id` identifies the same intended target and image configuration
across releases. The coverage policy records recipe selection and omissions;
its exact bytes must be retained and hashed consistently. All hashes contain
64 lowercase hexadecimal characters. No values are guessed from filenames or
the clock. Metadata is caller-supplied provenance, not independently verified
truth. CVEDelta recomputes the raw report hash; it does not receive the database
or policy files and cannot verify their declared hashes against those files.
The [provenance guide](../docs/provenance.md) explains how to capture all evidence
from the same build.

The foundation required a small, clearly labeled synthetic fixture and a
redistributable fixture produced by a pinned public writer, with licenses and
provenance retained. The producer fixture uses original local data and does
not claim to be a real firmware scan.

## Comparison rules

A component's identity is the exact pair `(layer, name)`, preserving native,
multilib and other prefixes or suffixes. Package version is context, so an
upgrade alone does not make every finding new. A finding's identity adds the
uppercase CVE identifier. Duplicate components or finding rows are invalid,
even when they match; v1 does not resolve multiple versions or choose the most
favorable status. Accepted statuses are exactly `Patched`, `Unpatched` and
`Ignored`.

Every finding present in either report belongs to one category:

| Category | Meaning |
| --- | --- |
| `new` | Present only in the candidate |
| `no_longer_reported` | Present only in the baseline |
| `status_changed` | Present in both, with a different status |
| `context_changed` | Present in both with the same status, but a different version or recognized issue attribute |
| `unchanged` | Present in both, with no recognized changes |

A status change takes precedence over a context change, while retaining all
other changes. Both raw statuses, recognized attributes, component versions
and report provenance remain available. For a missing finding, the report
states whether the component itself is absent or only that issue is absent.
A disappeared finding is never relabeled as fixed. Unknown metadata does not
create comparison changes.

Different configuration IDs are invalid input: exit 2 with no report.
Differences in scanner revision, database hash or coverage-policy hash, or
incomplete coverage on either side, still produce an observed report with
`comparable:false`, explicit reasons and exit 3. Build IDs, source revisions
and raw report hashes may differ. Matching provenance is necessary for
comparability, but does not prove completeness or correctness.

Records are sorted by layer, component name and CVE ID. Counts and output are
deterministic; neither format adds current timestamps, host paths or fabricated
evidence. The [contract reference](../docs/contracts.md) defines exact ordering,
absence reasons and field semantics.

## CLI, API and error precedence

The CLI contract is:

```text
cvedelta compare --baseline old.json --baseline-meta old.meta.json \
  --candidate new.json --candidate-meta new.meta.json \
  [--format json|markdown] [--fail-on CATEGORIES]
```

The filenames are placeholders, and brackets indicate optional flags. Markdown
is the default format. The default policy selects all four changed categories;
`--fail-on none` disables that change check only. Category selectors use the
exact snake_case names above. The first applicable outcome determines the exit:

| Condition | Exit |
| --- | --- |
| Invalid input, tool error or output error | 2 |
| Valid but incomparable reports | 3 |
| Comparable reports with changes in a selected category | 1 |
| Otherwise | 0 |

No flag bypasses incomparability. Diagnostics go to stderr. Valid observed
reports go to stdout, including exits 1 and 3. Invalid inputs and configuration
mismatches emit no report. The CLI renders completely before writing stdout,
so parsing or rendering errors cannot publish a partial report. An output write
failure exits 2 and may leave bytes already written.

Schema-1 output contains both metadata documents, comparability and reasons,
sorted records with before and after contexts, category counts, component-version
changes and the resolved change policy. JSON decoding preserves the full report,
including quoted strings and newlines. Markdown escapes untrusted content and
keeps source links inert. Human-readable output must preserve the source's
claims and limitations.

The public API under `pkg/cvedelta` is:

```go
ReadInput(report io.Reader, metadata io.Reader) (Input, error)
Compare(baseline Input, candidate Input, options Options) (Report, error)
WriteJSON(io.Writer, Report) error
WriteMarkdown(io.Writer, Report) error
```

`Input` holds validated immutable data and the raw report hash. `Options` selects
categories; `Report` contains the decision mapped to the CLI exits above. The
library never prints, exits or opens network connections. Feature packages share
`internal/model` and do not import the public facade.

## Validation and limits

Each report is limited to 64 MiB, 100,000 components and 1,000,000 finding rows.
Each metadata document is limited to 1 MiB. Both JSON documents permit at most
10,000 simultaneously open objects and arrays, including ignored metadata.
The root object has depth 1; depth 10,001 is invalid.

Malformed or trailing JSON, duplicate object keys, unsupported report versions,
wrong types, missing required values, duplicate identities, invalid CVE IDs and
unsupported statuses are rejected. Unknown metadata-document fields are also
rejected. Additional report fields are accepted without assigning them meaning;
only recognized fields are retained. Input streams are read-only. CVEDelta does
not execute inputs, modify them, persist report content temporarily or make
network requests during comparison.

## Out of scope

The release does not support SPDX, CycloneDX, sbom-cve-check or arbitrary
scanners. It does not download live CVE databases, score risk, determine
applicability, author VEX, modify recipes, create issues, perform remediation,
provide dashboards, suppress findings automatically or make regulatory-compliance
judgments. Yocto status labels remain reported facts; CVEDelta does not
independently verify `Patched` or `Ignored` claims.

## Verification and documentation requirements

`make verify` checks formatting, vet, race-enabled tests and expected output
files. `make acceptance` runs the real CLI on repository fixtures through all
four exits, compares CLI and library output, checks determinism and unchanged
inputs, and parses JSON output. `make verify-linux` runs both in the pinned
offline Linux container after explicit setup. The producer fixture must load
without semantic edits; synthetic fixtures cover adversarial cases.

Acceptance includes checksum binding, version upgrades, native variants, changed
databases and missing coverage. Cumulative review must account for every input
finding, check that upgrades preserve identity without merging native variants,
verify that invalid input takes precedence over policy and incomparability over
`--fail-on none`, and inspect both formats for false remediation or compliance
claims. Missing evidence must never become a passing result.

User documentation must explain installation, builds, support, accepted Yocto
format and export paths, same-build provenance capture, metadata schema,
identities, status precedence, categories, exits, invalid and incomparable
results, limits, interpretation, library errors, offline behavior and fixture
notices. The five-minute example must show new, status-changed and disappeared
findings, then a changed-database comparison that exits 3. Library and automation
examples must distinguish exits 1, 2 and 3 while retaining valid reports.

## Build and release requirements

The foundation selected the current supported stable Go release from
[go.dev/dl](https://go.dev/dl/) at implementation time, pinned its exact toolchain
and pinned the Linux verification image by digest. v1.0.0 supports Linux amd64;
other hosts use the documented container. Original code and package documentation
use Apache-2.0, with third-party licenses and fixture provenance retained. The
running tool is offline and needs no credentials. Dependency downloads and
container setup are explicit preparation steps, separate from offline tests.
All build outputs belong in ignored `dist/`.

Release verification includes versioned archives and `SHA256SUMS`, acceptance
from a clean checkout in the pinned Linux environment, and source, archive,
privacy and license checks.
