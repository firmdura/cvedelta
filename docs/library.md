# Use CVEDelta from Go

The public package reads reports, compares findings and writes JSON or
Markdown. It uses only the readers, writers and values you supply: it never
opens files, makes network requests, prints or exits your program. Original
documentation: Apache-2.0.

## Add the package

The repository pins Go **1.27.4**. In your own Go module, add the released
dependency while network access is available:

```sh
go get github.com/firmdura/cvedelta@v1.0.9
```

Then import the public package:

```go
import "github.com/firmdura/cvedelta/pkg/cvedelta"
```

No internal imports or sibling checkout are needed. To try the complete
example in this repository, finish the [README setup](../README.md), stay in
the repository root and run:

```sh
go run ./examples/library
```

The example opens the quick-start report and metadata files, writes JSON to
stdout and exits successfully. It deliberately leaves decisions about valid
reports to the application. See
[examples/library/main.go](../examples/library/main.go) for its file handling
and error handling.

## Read, compare and write

Choose a baseline and candidate for the same firmware configuration, and supply
a metadata reader for each report. The metadata describes the build and scan;
the [provenance guide](provenance.md) explains how to collect it. CVEDelta
checks the report's raw-byte checksum, but trusts the caller's database and
coverage declarations. It does not receive the database or policy files.

This fragment belongs inside a function returning `error`. Supply your own
readers and writer:

```go
baseline, err := cvedelta.ReadInput(baselineReportReader, baselineMetadataReader)
if err != nil {
    return err
}
candidate, err := cvedelta.ReadInput(candidateReportReader, candidateMetadataReader)
if err != nil {
    return err
}
report, err := cvedelta.Compare(baseline, candidate, cvedelta.Options{})
if err != nil {
    return err
}
return cvedelta.WriteJSON(outputWriter, report)
```

A valid comparison decision is data, not a Go error. Inspect
`report.Decision` to decide how your application should respond:

| Decision | Meaning | Corresponding CLI exit constant |
| --- | --- | --- |
| `cvedelta.Clean` | The inputs are comparable and no changes match the selected categories. | `ExitClean` (0) |
| `cvedelta.ChangesDetected` | The inputs are comparable and at least one change matches the selected categories. | `ExitChangesDetected` (1) |
| `cvedelta.Incomparable` | The inputs are valid, but their provenance prevents a comparable result. | `ExitIncomparable` (3) |

An incomparable report still contains the finding changes and reasons. It
remains incomparable when no change categories are selected. Applications that
follow the CLI's exit convention should map errors to `ExitError` (2).
See the [CLI guide](usage.md) for category meanings and decision precedence.

## Select the change categories

`Options{}` and `Options{FailOn: nil}` select all four changed categories.
To select a subset, supply it explicitly:

```go
options := cvedelta.Options{
    FailOn: []cvedelta.Category{cvedelta.New, cvedelta.StatusChanged},
}
```

To select none, use a non-nil empty slice:

```go
options := cvedelta.Options{FailOn: []cvedelta.Category{}}
```

These options affect the decision, not which records appear in the report.
Unknown categories, duplicates and `cvedelta.Unchanged` return an error, even
when the inputs are incomparable. The report stores selected categories in
the fixed order `new`, `no_longer_reported`, `status_changed`, `context_changed`.

## Input ownership and errors

`ReadInput(io.Reader, io.Reader) (Input, error)` strictly validates both JSON
documents, checks the raw report hash and returns an `Input` that owns an
immutable copy of the validated data. The hash includes every report byte,
including whitespace. `ReadInput` does not close either reader; your
application owns that responsibility. The zero value of `Input` is invalid.

`Input.Document()` returns a fresh deep copy. `Input.Metadata()` returns a
value copy of the metadata, and `Input.RawSHA256()` returns the report hash.
`Compare(Input, Input, Options) (Report, error)` rejects invalid inputs,
invalid options and different firmware configuration IDs. Otherwise, it
returns a complete report whose data do not alias either input. All nested
input and output types, and the associated constants, are available through
the public package.

When budgeting memory for a large comparison, count unchanged findings too:
each keeps both contexts. Its `ChangedFields` slice is empty (`[]` in JSON)
and needs no backing array for field names.

`WriteJSON(io.Writer, Report) error` and `WriteMarkdown(io.Writer, Report)
error` validate the report before writing and return any writer error. A
failed write may leave partial output. Both writers use the finding records
and component version changes from `Compare` without copying them for sorting.
If you reorder either list, the writers sort a copy of that list and leave
your report untouched. An intermediate `Delta`, which has no resolved policy
or decision, cannot be rendered as a report.

I/O and JSON syntax errors preserve their underlying types for `errors.Is`
and `errors.As`. Semantic validation errors have descriptive messages, but
those messages are not a stable machine-readable API. Use `Reason.Code` and
`Decision` to interpret valid reports in programs.

## Decode saved reports

Use `encoding/json` to decode JSON output into `cvedelta.Report`. If you need
to enforce the schema on an untrusted document, also validate it against
[report-v1.schema.json](../schemas/report-v1.schema.json); decoding into a Go
struct alone does not enforce JSON Schema.

The [technical contract](contracts.md) describes every output field. For the
same inputs and options, the CLI and library produce byte-identical JSON and
Markdown. Results describe reported findings: they do not independently
establish remediation, applicability or compliance.
