# CLI usage and report interpretation

Start with the [README example](../README.md) to build the tool and try a
comparison. This guide explains the command, its decisions and the report
fields. Original documentation: Apache-2.0.

## Identify the installed version

Run `cvedelta --version` to print the release version, for example
`cvedelta v1.0.2`. It needs no input files, writes one line to stdout and exits
0. Use this top-level option on its own; additional arguments are invalid.
As with comparison output, a failed stdout write returns exit 2.

## Supply the inputs

The **baseline** is the earlier report; the **candidate** is the report you
want to compare against it. Each needs a separate metadata file describing
the build and scan that produced it. Follow the
[provenance guide](provenance.md) to create those files from your builds.

The command has this form. Replace the example filenames with your input
paths. If you built from source, use `./dist/cvedelta` from the repository
root in place of `cvedelta`:

```text
cvedelta compare --baseline old.json --baseline-meta old.meta.json \
  --candidate new.json --candidate-meta new.meta.json \
  [--format json|markdown] [--fail-on CATEGORIES]
```

All four paths are required. CVEDelta opens them read-only, never infers
metadata and does not accept stdin in place of a path. Database and
coverage-policy files are not command inputs: their hashes are declarations in
the metadata. CVEDelta verifies the report checksums itself, but cannot verify
those declarations without the original build evidence.

Markdown is the default output format. `--format json` selects JSON report
schema 1. `compare` is the only command; unknown flags, extra positional
arguments and unsupported formats produce exit 2.

## Choose which changes affect the exit status

By default, all four changed categories can cause exit 1:
`new,no_longer_reported,status_changed,context_changed`. Use `--fail-on` with
a nonempty comma-separated subset, such as `--fail-on new,status_changed`,
or use `--fail-on none` to disable exit 1.

Category spelling is exact. Empty entries, whitespace, duplicates,
`unchanged`, unknown categories and `none` combined with a category are invalid.
This option controls the decision only: every finding still appears in the
report, and the same comparability checks always apply. A component version
change with no associated findings does not by itself cause exit 1.

## Understand finding categories

A **component** is identified by its exact layer and name, written as
`(layer,name)`. A **finding** is that component together with a CVE ID.
For example, `alpha`, `alpha-native` and `lib32-alpha` in the same layer are
three separate components. Names are matched exactly, including all prefixes
and suffixes.

The version is additional context, rather than part of the identity. An
upgrade therefore allows the same finding to be compared across versions.
Duplicate components, including entries with different versions, are invalid.
So are repeated CVE IDs within one component; CVEDelta never merges them.
For either error, the diagnostic gives both zero-based locations in the input
report. For example, `report.package[3]: duplicate component identity (first
at report.package[1])` points to the fourth and second entries in the `package`
array, without printing their names.

Each finding receives one category:

| Category | When it applies | What it means |
| --- | --- | --- |
| `new` | Only the candidate contains the finding. | The finding is newly reported for this component. |
| `no_longer_reported` | Only the baseline contains the finding. | The candidate no longer reports it; this alone does not show that it was fixed. |
| `status_changed` | Both contain it, with different statuses. | The report preserves both statuses and any other changes. |
| `context_changed` | Both contain it with the same status, but the version or a recognized issue attribute differs. | Supporting information changed without a status change. |
| `unchanged` | Both contain it with the same status, version and recognized attributes. | The compared information is the same. |

A status change takes precedence over a context change. For example, a finding
whose status and component version both change is `status_changed`, with both
changes listed in `changed_fields`. A missing attribute differs from an
attribute containing an empty string. Scores, vectors, dates and links are
compared as source strings; CVEDelta does not interpret their values.

Each record has `before` and `after` contexts. When a finding is present on
only one side, the missing context is `null`, and `absence_reason` explains
whether that side lacks the entire component (`component_absent`) or just the
finding (`finding_absent`). For findings present on both sides,
`absence_reason` is `null`.

For findings present on both sides, `changed_fields` lists differences in this
fixed order: `version`, `status`, `detail`, `description`, `summary`, `link`,
`modified`, `scorev2`, `scorev3`, `scorev4`, `vector`, `vectorString`. It is
empty for `new`, `no_longer_reported` and `unchanged` records.

## Check comparability before using the decision

The metadata records the caller's declarations about the reports' origins,
known as provenance. Matching metadata does not independently establish that
the reports are complete or correct. In particular, a `Patched` or `Ignored`
status remains the scanner's claim; CVEDelta does not verify remediation,
applicability or compliance.

Different firmware configuration IDs are invalid: the CLI returns exit 2 and
writes no report. Different build labels, firmware source revisions and raw
report hashes are allowed because those can change between firmware releases.

For reports with the same configuration ID, these conditions make the inputs
**incomparable**. CVEDelta still reports the finding changes, but returns exit
3 and includes every applicable reason in this order:

| Reason code | Condition |
| --- | --- |
| `scanner_revision_changed` | The scanner revisions differ. |
| `database_changed` | The declared database hashes differ. |
| `coverage_scope_changed` | The declared coverage-policy hashes differ. |
| `baseline_coverage_incomplete` | Baseline `coverage.complete` is `false`. |
| `candidate_coverage_incomplete` | Candidate `coverage.complete` is `false`. |

Use reason codes in programs; messages explain the reasons to readers. Even
unchanged or empty reports are incomparable when coverage is declared
incomplete. Matching hashes and `complete:true` satisfy these checks but do
not prove the declarations are true.

The first applicable condition in this table determines the exit status:

| Condition | Exit | Report `decision` |
| --- | --- | --- |
| An input, configuration, option, tool, rendering or output error occurred. | 2 | No valid decision |
| At least one incomparability reason applies. | 3 | `incomparable` |
| The inputs are comparable and a change matches the selected categories. | 1 | `changes_detected` |
| None of the above applies. | 0 | `clean` |

`clean` means only that no changes matched the selected categories. It says
nothing about the number or severity of existing findings, or whether they
are correct. `--fail-on none` prevents exit 1, but errors still return 2 and
incomparable inputs still return 3. The [CI wrapper](../examples/ci.sh) shows
how to preserve these distinct statuses and their output.

## Read or save the report

For comparison exits 0, 1 and 3, stdout contains a complete report. Diagnostics go to
stderr. Parsing, comparison and rendering all finish before the CLI begins
writing to stdout. An output write failure returns exit 2 and can leave partial
bytes; discard that output.

JSON includes both metadata documents, comparability and its reasons, every
finding record, counts for all five categories, component version changes,
the selected categories and the decision. The counts sum to the number of
records. See [report schema 1](../schemas/report-v1.schema.json) for exact
field names and types.

Records are sorted by layer, component name and CVE ID using Go's bytewise
string order. For components present in both reports, version changes are
listed even when the component has no findings, and sorted by layer and name.
Lists are arrays even when empty. Missing recognized attributes are omitted;
attributes containing empty strings are preserved. Additional source metadata
is ignored.

Markdown includes the same findings and provenance limitations. It escapes
untrusted HTML, pipes, backticks, control and ANSI text, and newlines; source
URLs appear as text rather than active links. Both formats produce identical
bytes on repeated runs with identical inputs and options. Neither adds current
timestamps, input paths or invented evidence.
