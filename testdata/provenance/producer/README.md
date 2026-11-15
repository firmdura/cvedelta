# Pinned producer fixture

`report.json` is unedited output from the Scarthgap cve-check JSON writer,
invoked locally with original synthetic inputs. It was not produced by a
firmware image build, a real NVD database or an actual security scan. Its
CVE-shaped identifiers and statements are invented test data and make no claim
about real vulnerabilities.

Unlike the neighboring synthetic comparison fixtures, this report's exact
bytes were written by the pinned public producer. The fixture contains no
customer data, downloaded CVE records or proprietary firmware.

## Source and licenses

The producer is OpenEmbedded-Core, Scarthgap revision
`fc4316861becc9f0d41857b49f6438929ab4c291`, resolved on 2026-11-15.
The vendored files are byte-for-byte copies of:

- [meta/classes/cve-check.bbclass](https://raw.githubusercontent.com/openembedded/openembedded-core/fc4316861becc9f0d41857b49f6438929ab4c291/meta/classes/cve-check.bbclass)
- [meta/lib/oe/cve_check.py](https://raw.githubusercontent.com/openembedded/openembedded-core/fc4316861becc9f0d41857b49f6438929ab4c291/meta/lib/oe/cve_check.py)
- [LICENSE.MIT](https://raw.githubusercontent.com/openembedded/openembedded-core/fc4316861becc9f0d41857b49f6438929ab4c291/LICENSE.MIT)

Copyright OpenEmbedded Contributors. The upstream source is MIT licensed;
its notices and full license are retained in `upstream/`. Original inputs,
the reproduction harness and this documentation are Apache-2.0. Retain these
upstream notices with redistributions of this producer-derived fixture.

## Reproduce the report

From the repository root, use Python 3 to verify the output without network
access:

```sh
python3 testdata/provenance/producer/reproduce.py --check
```

To deliberately replace the checked-in output and checksums with regenerated
values, run:

```sh
python3 testdata/provenance/producer/reproduce.py --write
```

The harness checks the pinned source hashes before running the writer. It
compiles only `decode_cve_status`, `cve_write_data_json` and
`cve_check_write_json_output`, preserving their upstream definitions. It
provides a minimal BitBake data accessor and a logging stub that produces no
output.

The producer writes a temporary development output file. The harness copies
its exact bytes without normalization or semantic edits. This fixture-generation
step is separate from CVEDelta runtime, which never runs producer code or stores
input reports. The generated report has no final newline because the pinned
writer does not emit one.

## Inputs and metadata

`input.json` supplies recipe variables, three invented CVE-shaped identifiers,
status lists and explicit status flags. `database.json` supplies the original
synthetic `cve_data` snapshot directly to the writer. The harness performs no
upstream database lookup or applicability calculation. `coverage-policy.json`
describes this isolated invocation. These files do not provide evidence of a
production Yocto database or scan coverage.

`report.meta.json` is an illustrative schema-1 metadata document:

- The report hash covers the raw producer output.
- The database hash covers the synthetic snapshot.
- The coverage hash covers the exact policy bytes.
- The source revision is the SHA-256 of the exact `input.json` bytes.
- The scanner revision identifies the pinned producer.

Here, `complete:true` means all declared fixture rows were supplied. It asserts
nothing about real firmware coverage.

`SHA256SUMS` covers every retained file in this directory except itself.
`--check` verifies both exact regeneration and this checksum manifest offline.
Scores and recognized attributes retain their producer-emitted string values.
The pinned writer emits `products` metadata and all three supported statuses.
It does not emit `modified`, although CVEDelta accepts that optional attribute.
