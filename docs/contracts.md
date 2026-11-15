# CVEDelta version-1 contracts

This reference defines the input, comparison and output contracts implemented
in CVEDelta v1.0.0. Original code, schemas and original fixtures use Apache-2.0.
The upstream producer sources retain their MIT license; see the
[producer fixture notice](../testdata/provenance/producer/README.md).

## Report input

CVEDelta accepts the [Scarthgap cve-check version-1 JSON
format](https://docs.yoctoproject.org/scarthgap/dev-manual/vulnerabilities.html).
Recipe reports are written to `tmp/deploy/cve/*_cve.json`; image reports are
under `tmp/deploy/images/<machine>/`, where `<machine>` is your Yocto machine
name. `sbom-cve-check` and other report versions are unsupported. The input
schema is [yocto-v1.schema.json](../schemas/yocto-v1.schema.json).

The report must contain `version` with the string value `"1"` and a `package`
array. Each package, called a component in CVEDelta, must contain the strings
`name`, `layer` and `version`, plus an `issue` array. Both arrays may be empty.
Each issue must contain an `id` matching `^CVE-[0-9]{4}-[0-9]{4,}$` and a
`status` whose exact value is `Patched`, `Unpatched` or `Ignored`.

Required strings must contain at least one non-whitespace character. CVEDelta
preserves their exact values: it does not trim whitespace, change case or check
whether the year in a CVE identifier is plausible.

The following optional issue attributes are recognized. Each must be a string
when present:

```text
detail, description, summary, link, modified,
scorev2, scorev3, scorev4, vector, vectorString
```

An empty string is valid and differs from an absent attribute. Explicit `null`
values and numeric scores are invalid. Strings retain quotes and newlines;
CVEDelta does not interpret scores, vectors, dates or links. Additional fields,
including `products`, are accepted at the report, component and issue levels
as arbitrary JSON values, then ignored. They are neither retained nor compared.
Duplicate JSON object keys are invalid, including inside ignored metadata.

## Provenance metadata

The caller supplies a separate metadata document for each report. All fields
in [metadata-v1.schema.json](../schemas/metadata-v1.schema.json) are required,
including the boolean `coverage.complete`. Unknown fields are rejected at every
level of this document. `schema_version` must be the integer `1`; each hash must
contain exactly 64 lowercase hexadecimal characters; and `scanner.name` must
be `yocto-cve-check`. Other identity and revision strings must be nonblank.

These values are caller declarations. CVEDelta does not infer them from
filenames, the clock, environment variables or network sources. It recomputes
the raw report's SHA-256 and checks it against `report_sha256`. Comparison does
not receive the database or coverage-policy files, so it cannot recompute their
hashes or verify that the scanner used them. Their declared hashes are checked
for format and compared between reports.

Capture the report and its supporting evidence from the **same completed
build**. The [provenance guide](provenance.md) gives the full procedure:

1. Preserve the raw report bytes and hash them without reformatting the JSON.
2. Set `firmware.configuration_id` to a managed, stable identity for the target,
   machine, distro, image and relevant configuration. Reuse it only for the same
   intended firmware configuration. Record each build's label and immutable
   source revision in `build_id` and `source_revision`.
3. Set `scanner.revision` to an immutable producer revision that includes any
   local patches. A release name alone does not identify a patched producer.
4. Stop database writers and prepare a consistent, standalone SQLite CVE
   snapshot before scanning. SQLite's backup API includes committed data from
   its write-ahead log (WAL). Configure the producer to use that snapshot without
   updating it during the scan. Hash the file actually used and verify that it
   remains unchanged after the build. A later database download cannot supply
   evidence for an earlier report. CVEDelta does not download databases or scan
   firmware.
5. Create a UTF-8 coverage-policy file that names the image or target, selected
   recipe names and layers (including native and multilib variants), every
   omission, `CVE_CHECK_SKIP_RECIPE`, and relevant cve-check exclusion or skip
   settings. Use a fixed serialization, such as sorted JSON keys and recipe
   lists with LF line endings and one final newline. Preserve and hash those
   exact bytes for `coverage.scope_sha256`. Reuse the same policy bytes when
   coverage is unchanged. Build labels belong in `firmware.build_id`; package
   versions belong in each report component's `version` field.
   Set `complete:true` only when the declared selection has finished
   reporting and the policy accounts for every omission. If coverage is
   uncertain, supply a policy and set `complete:false`.

The original fixtures include example policies and hashes. They describe
synthetic test data, not real scans. Matching provenance is necessary for
comparability, but does not prove that a report is complete, true or applicable
to the firmware.

## Validation and data ownership

All feature packages share `internal/model` and never import the public facade.
`Document`, `Component`, `Issue` and `Metadata` are values used to construct an
input. `NewInput(document, metadata, rawSHA256) (Input, error)` validates semantic
invariants and copies all nested data. `Input.Document()` returns a new deep
copy; `Metadata()` and `RawSHA256()` return immutable scalar data. The zero
value of `Input` has `Valid() == false` and is rejected by comparison.

The reader validates JSON syntax, required fields, types, null values, duplicate
keys and trailing data. It also enforces read limits, hashes the raw bytes and
reports structural error locations. `NewInput` then checks the report version,
identities, required values, counts, statuses and metadata/hash consistency.
It cannot establish that a supplied hash came from the raw report; the reader
must compute that hash before calling it. `coverage.complete:false` is valid
input and leads to an incomparable report.

Input limits are:

| Limit | Maximum |
| --- | --- |
| Raw report size | 64 MiB |
| Metadata document size | 1 MiB |
| Components per report | 100,000 |
| Issue rows per report | 1,000,000 |
| Simultaneously open JSON objects and arrays | 10,000 per document |

An extra byte beyond either size limit is rejected. For nesting depth, the root
object counts as 1 and each nested object or array adds 1. Containers in ignored
report metadata count too. Object keys, scalar values and braces or brackets
inside strings do not add depth. The pinned Go decoder accepts depth 10,000
and rejects depth 10,001. This ceiling does not relax the metadata schema's
field and type restrictions.

Duplicate `(layer, name)` components are invalid even if their contents match
or their versions differ. A component cannot contain duplicate CVE IDs, even
with identical statuses. CVEDelta never merges duplicates or selects a more
favorable status.

Stream I/O errors propagate to the caller. Validation diagnostics identify a
structural location without dumping the report body. Input reports are never
modified, executed or stored in temporary files, and comparison makes no network
requests. JSON Schema checks structure; the reader and model enforce additional
rules such as duplicate keys and identities, total row counts, raw checksums
and resource limits.

## Comparison and policy

The internal packages expose these functions. Interfaces with matching method
signatures are also available in `internal/model`.

| Package | Function |
| --- | --- |
| `internal/reader` | `ReadInput(io.Reader, io.Reader) (model.Input, error)` |
| `internal/delta` | `Compare(model.Input, model.Input) (model.Delta, error)` |
| `internal/decision` | `Apply(model.Delta, model.Options) (model.Report, error)` |
| `internal/render` | `WriteJSON(io.Writer, model.Report) error`, `WriteMarkdown(io.Writer, model.Report) error` |

These packages perform no filesystem or network operations. A `Delta` describes
observed differences before policy is applied; it has no decision and cannot be
rendered as a report. The public facade combines input reading, comparison and
policy through these functions:

```go
ReadInput(report io.Reader, metadata io.Reader) (Input, error)
Compare(baseline Input, candidate Input, options Options) (Report, error)
WriteJSON(io.Writer, Report) error
WriteMarkdown(io.Writer, Report) error
```

Public aliases and wrappers preserve `Input`'s immutable semantics. The library
never prints or exits. Invalid options are rejected even when the inputs are
incomparable. No policy can turn invalid input or an incomparable result into
a passing decision.

A component's identity is the exact pair `(layer, name)`, including `-native`,
`lib32-` and every other prefix or suffix. A finding's identity adds its CVE ID.
Package version supplies context, so an upgrade alone does not create a new
finding. Every identity present in either report produces exactly one record:

| Presence or change | Category | Before and after contexts |
| --- | --- | --- |
| Candidate only | `new` | Before is null; after is present |
| Baseline only | `no_longer_reported` | Before is present; after is null |
| Both, with different statuses | `status_changed` | Both are present; other changes are also retained |
| Both, with the same status but different versions or recognized attributes | `context_changed` | Both are present |
| Both, with no recognized changes | `unchanged` | Both are present |

For a record present on only one side, `absence_reason` describes the missing
side: `component_absent` means the component is absent; `finding_absent` means
the component exists but does not contain that CVE. Records present on both
sides have `absence_reason:null`.

`changed_fields` lists all changes for `status_changed` and `context_changed`
records in this fixed order: `version`, `status`, `detail`, `description`,
`summary`, `link`, `modified`, `scorev2`, `scorev3`, `scorev4`, `vector`,
`vectorString`. It is `[]` for `new`, `no_longer_reported` and `unchanged`.
An absent attribute differs from a present empty string. Ignored metadata
cannot cause a context change.

The report also lists each version change for a component present in both
inputs, including components with no issues. Component additions and removals
do not appear in that list; findings for those components appear as `new` or
`no_longer_reported` records.

Different configuration IDs cause an error with no report. Otherwise, the
comparison collects all applicable reasons in this order:

| Reason code | Trigger |
| --- | --- |
| `scanner_revision_changed` | Scanner revisions differ |
| `database_changed` | Database SHA-256 values differ |
| `coverage_scope_changed` | Coverage-policy SHA-256 values differ |
| `baseline_coverage_incomplete` | Baseline `coverage.complete` is false |
| `candidate_coverage_incomplete` | Candidate `coverage.complete` is false |

Each `Reason.Message` contains nonblank explanatory text; consumers identify
the reason by its code. `Comparable` is true exactly when the reason list is
empty. Build IDs, source revisions and raw report hashes may differ without
making the reports incomparable. Both metadata documents are retained in full,
including in incomparable reports.

Statuses are the producer's claims. A disappeared finding is never labeled
“fixed”, and neither `Patched` nor `Ignored` independently proves remediation,
applicability or compliance.

`Options.FailOn == nil` selects all four changed categories. A non-nil empty
slice selects none. Unknown categories, `unchanged` and duplicate selections
are errors. The resolved `Policy.FailOn` list uses this order: `new`,
`no_longer_reported`, `status_changed`, `context_changed`.

The first applicable condition determines the outcome:

| Condition, in precedence order | Decision | CLI exit |
| --- | --- | --- |
| Input, configuration, options, tool, render or output error | No report decision | 2 |
| Any comparability reason | `incomparable` | 3 |
| Comparable, with at least one changed row in a selected category | `changes_detected` | 1 |
| Otherwise | `clean` | 0 |

An unchanged report with incomplete coverage still exits 3. `--fail-on none`
disables only the check for selected changes. A component-version change with
no finding rows does not trigger that check by itself.

## Output and CLI

[report-v1.schema.json](../schemas/report-v1.schema.json) defines the exact
schema-1 JSON output. Every field defined by the schema is required except the
optional source attributes. Schema validation rejects unknown fields. Lists
are always arrays, including empty `reasons`, `records`,
`component_version_changes`, `changed_fields` and `policy.fail_on`. Missing
contexts and absence reasons are explicit nulls. Optional source attributes
are omitted when absent and retain empty strings when present.

Counts cover all five categories and sum to the record count. Records are
sorted by layer, component name and CVE ID using Go's string byte order.
Component-version changes are sorted by layer and name. Output contains no
current timestamp, host path or invented evidence. Decoding JSON into
`model.Report` preserves the full report. Rendering rejects invalid or
unresolved reports rather than presenting an intermediate `Delta` as a pass.

The CLI syntax is shown below. Square brackets mark optional flags; the file
names are placeholders for your reports and metadata documents.

```text
cvedelta compare --baseline old.json --baseline-meta old.meta.json \
  --candidate new.json --candidate-meta new.meta.json \
  [--format json|markdown] [--fail-on CATEGORIES]
```

The default format is `markdown`, and the default policy selects all four
changed categories. `CATEGORIES` is a comma-separated list of their exact names,
or `none` alone. Empty tokens, surrounding whitespace, unknown names, duplicates,
`unchanged`, and `none` mixed with categories are invalid. All four input flags
are required. Unknown commands or flags and extra positional arguments fail.
No flag bypasses incomparability.

Diagnostics go to stderr. Valid observed reports go to stdout even when the
exit code is 1 or 3. Invalid inputs and configuration mismatches produce no
report. The CLI renders the full report before writing stdout, so parsing or
rendering errors cannot publish a partial report. A stdout write error exits 2
and may leave bytes already written. Library writers also propagate errors.

Markdown escapes untrusted HTML, pipes, backticks, terminal control sequences
and multiline content. Source links remain inert text. Rendering preserves
every finding and provenance limitation without silent truncation.

## Fixtures and verification

`testdata/provenance/synthetic/` contains original inputs and explicit expected
schema-1 reports. They cover all finding categories, status changes that take
precedence over context changes, native and multilib identities, version-only
context changes, absent versus empty attributes, and both absence reasons.
Metadata variants exercise every comparability reason separately and together.
`outcomes.json` records exits 0, 1, 2 and 3, including configuration failure
before policy evaluation and incomparability despite `--fail-on none`. These
expected values are fixed test examples, not output generated by the comparison
engine. Reader, comparison, policy and renderer tests check behavior against them.

The [producer fixture notice](../testdata/provenance/producer/README.md) records
upstream URLs, revision, licenses, checksums and the offline reproduction
procedure. Its report is unedited output from the pinned producer's JSON
writer, using original local test data. It is not a full Yocto build or a scan
against a real vulnerability database.

The [verification guide](../build/README.md) gives the exact toolchain and
container pins, host prerequisites and setup instructions:

- `make setup-linux` prepares the environment with network access.
- `make verify` checks formatting, vet, race-enabled tests, schemas, examples
  and producer reproduction.
- `make verify-foundation-linux` runs those checks in the pinned offline Linux
  container.
- `make acceptance` runs the real CLI through all four outcomes, validates
  output schemas, compares output bytes with the public library, checks
  determinism and unchanged inputs, and runs the documented examples.
- `make verify-linux` runs verification and acceptance in the pinned offline
  Linux container after setup.

The JSON Schema validator is a test dependency. Runtime Go code uses only the
standard library.
