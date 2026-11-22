# Accepted inputs, limits and offline behavior

CVEDelta accepts one report format: the Scarthgap cve-check JSON format with
`version: "1"`. Each report must have a separate metadata document describing
the same build and scan. See the [provenance guide](provenance.md) to create
that metadata. Original documentation: Apache-2.0.

## Report fields

The top-level report object requires a `package` array. Each component in that
array requires nonblank string fields `name`, `layer` and `version`, plus an
`issue` array. Each issue requires an uppercase CVE ID matching
`^CVE-[0-9]{4}-[0-9]{4,}$` and a status of exactly `Patched`, `Unpatched` or
`Ignored`.

CVEDelta preserves strings exactly; it does not trim whitespace, change case
or check whether a CVE's year is plausible. Required nonblank strings cannot
be empty or consist only of whitespace. Arrays may be empty, but an empty
report still needs all required metadata.

These optional issue fields are recognized and compared: `detail`,
`description`, `summary`, `link`, `modified`, `scorev2`, `scorev3`, `scorev4`,
`vector` and `vectorString`. Each must be a string when present, including
scores. `null` and numeric scores are invalid. An empty string is valid and
differs from a missing field.

`products` and other additional report, component and issue fields may contain
any otherwise valid JSON value. CVEDelta checks their JSON structure but
ignores their meaning and does not preserve them in the comparison. Duplicate
object keys are invalid even within these ignored fields. Support for extra
fields does not extend support to other scanners or report versions.

## Metadata fields

The metadata document uses integer `schema_version: 1`. Every field in
[metadata-v1.schema.json](../schemas/metadata-v1.schema.json) is required,
including the boolean `coverage.complete`. Unknown fields are invalid at
every level of the metadata document.

All hashes must contain exactly 64 lowercase hexadecimal characters.
`scanner.name` must be exactly `yocto-cve-check`. The other identity and
revision strings must be nonblank. CVEDelta does not fill in missing values
from filenames, the environment or the current time.

`report_sha256` must match the exact report bytes. A format error means the
metadata field is not a 64-character lowercase hex digest. A checksum mismatch
means the digest is well-formed but differs from the SHA-256 of the supplied
report. Check that the report and metadata came from the same build and that
the report hasn't been reformatted; even an extra newline changes its checksum.

Database and coverage hashes are checked for the required format, then compared
as caller-supplied declarations. CVEDelta does not receive the database or
coverage-policy files and cannot check whether those hashes describe the build
correctly.
`coverage.complete: false` is valid metadata, but makes the inputs
incomparable; it does not produce an input error.

## Size and nesting limits

| Limit | Maximum |
| --- | --- |
| Raw report size | 64 MiB (67,108,864 bytes) per report |
| Raw metadata size | 1 MiB (1,048,576 bytes) per metadata document |
| Components | 100,000 per report |
| Findings | 1,000,000 per report |
| JSON nesting depth | 10,000 per report or metadata document |

An extra byte, component or finding beyond a limit is invalid. JSON nesting
depth counts simultaneously open objects and arrays: the root object has
depth 1, and each nested object or array adds 1. Containers in ignored fields
count too. Scalars, object keys and brackets inside strings do not add depth.
Depth 10,000 is allowed; 10,001 is rejected by the pinned Go decoder.
This limit does not permit extra fields or structures in metadata.

## Validation failures

CVEDelta rejects malformed JSON, invalid UTF-8, unpaired Unicode surrogate escapes,
trailing JSON values, duplicate object keys, unsupported versions, missing
required fields, wrong types, duplicate component or finding identities,
invalid CVE IDs, unsupported statuses and report checksum mismatches. The
[CLI guide](usage.md) explains identity matching and comparability.

For invalid UTF-8 in a report or metadata file, the error points to the first
byte of the invalid sequence. For an unpaired Unicode surrogate escape, it
points to the escape's backslash. Positions count raw bytes from 1, not
characters; the diagnostic does not print the surrounding text.

For a duplicate JSON key, the error gives two byte positions in the affected
file: the repeated key first, then its first occurrence in the same object.
Each position counts from 1 and points to the key's closing quote. This also
works for keys inside ignored report fields, without printing the key or its
values.

Different firmware configuration IDs are also an error, as are invalid
options, read errors, invalid reports supplied to a writer and output errors.
The CLI returns exit 2 for these failures; no option can turn them into a
successful comparison. Diagnostics identify structural locations without
dumping whole report bodies. Input and rendering failures produce no report.
An output write failure may leave partial bytes, which must be discarded.

JSON schemas describe the document structure. They do not replace the reader's
checks for duplicate keys and identities, raw checksums and aggregate limits.

## Offline behavior and side effects

The library consumes caller-supplied readers and values. It opens no files,
executes no inputs, makes no network requests, mutates no inputs and creates
no temporary report files. The CLI opens its four input files read-only and
writes only to stdout and stderr. It renders the complete result in memory
before writing to stdout, so input or rendering errors cannot publish a
partial report. A write failure can still leave bytes already written.

Development setup is a separate, explicitly network-enabled step:
`go mod download` fetches dependencies, and `make setup-linux` prepares the
container image and its cache. After preparation, `make verify-linux` runs
with the container network disabled and source mounted read-only. Generated
outputs are confined to ignored `dist/` and the container's `/tmp`.

Reproducing the pinned producer fixture executes trusted fixture code as a
development check; comparison never executes code supplied with a report.
Packaging writes local archives under `dist/`. It does not tag or publish a
release or request package indexing. See the [build guide](../build/README.md)
for environment preparation and verification commands.
