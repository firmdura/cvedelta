# CVEDelta

[![Latest release](https://img.shields.io/github/v/release/firmdura/cvedelta)](https://github.com/firmdura/cvedelta/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/firmdura/cvedelta/pkg/cvedelta.svg)](https://pkg.go.dev/github.com/firmdura/cvedelta/pkg/cvedelta)

CVEDelta compares two Yocto cve-check JSON reports and shows how their reported
CVE findings changed between firmware builds. It runs offline as a command-line
tool or Go library and accepts the Scarthgap `version: "1"` report format.

Choose an earlier report as the **baseline** and a later report as the
**candidate**. Both must describe the same firmware configuration. Each report
also needs a metadata file describing its origin: the firmware build, scanner
revision, CVE database and scan coverage. This information is called
*provenance*. CVEDelta receives these four files; it does not read the database
or coverage-policy files themselves. It verifies each report's checksum and
trusts the caller's declarations about the database and coverage.

The results describe what the reports say. A finding that disappears is
**no longer reported**; that alone does not show that the vulnerability was
fixed. Likewise, `Patched` and `Ignored` are the scanner's reported statuses,
which CVEDelta preserves without independently verifying them.

## Build and try the example

Linux amd64 is the supported release target. You can download its binary from
the [v1.0.1 release](https://github.com/firmdura/cvedelta/releases/tag/v1.0.1),
or build from a source checkout with Go **1.27.4**, the exact toolchain pinned
in `go.mod`. The running tool needs no credentials or network access and uses
only Go's standard library.

For the source example below, you need Go 1.27.4, Make and Python 3. Run all
commands from the repository root. First prepare the dependency cache with
network access, then build the tool:

```sh
mkdir -p dist/cache/go-build dist/cache/go-mod
export GOTOOLCHAIN=local GOENV=off GOWORK=off
export GOCACHE="$PWD/dist/cache/go-build" GOMODCACHE="$PWD/dist/cache/go-mod"
go mod download
make build
```

The binary is now at `dist/cvedelta`. Run `./dist/cvedelta --version` to identify
the installed release. The remaining example commands run offline. All inputs
in `examples/quickstart` are invented, including the CVE
identifiers and metadata; they do not represent a real scan.

Run the comparison and save its JSON output. Exit 1 is expected because the
reports contain changes, so the command captures that status before displaying
the result:

```sh
compare_exit=0
./dist/cvedelta compare \
  --baseline examples/quickstart/baseline.json \
  --baseline-meta examples/quickstart/baseline.meta.json \
  --candidate examples/quickstart/candidate.json \
  --candidate-meta examples/quickstart/candidate.meta.json \
  --format json > dist/demo.json || compare_exit=$?
test "$compare_exit" -eq 1
python3 -m json.tool dist/demo.json
```

The result contains three findings:

| CVE ID | Category | What changed |
| --- | --- | --- |
| `CVE-2099-0001` | `status_changed` | The reported status changed from `Unpatched` to `Patched`; the component version and detail text also changed. |
| `CVE-2099-0002` | `no_longer_reported` | The candidate no longer lists this CVE, although it still lists the component. |
| `CVE-2099-0003` | `new` | Only the candidate lists this CVE for the component. |

The declared configuration, scanner revision, database and coverage policy
match, and both scans declare complete coverage. CVEDelta therefore marks the
inputs as comparable. That means the metadata permits a comparison; it does
not prove the findings are complete or correct.

Next, use the alternative candidate metadata, which declares a different
synthetic database snapshot. The report still shows the same finding changes,
but the database difference makes the inputs **incomparable**. Exit 3 takes
precedence even with `--fail-on none`:

```sh
compare_exit=0
./dist/cvedelta compare \
  --baseline examples/quickstart/baseline.json \
  --baseline-meta examples/quickstart/baseline.meta.json \
  --candidate examples/quickstart/candidate.json \
  --candidate-meta examples/quickstart/candidate-database.meta.json \
  --format markdown --fail-on none > dist/demo-incomparable.md || compare_exit=$?
test "$compare_exit" -eq 3
cat dist/demo-incomparable.md
```

## Use the results in automation

The exit status distinguishes a completed comparison from an input or output
error. The default change policy selects all four changed categories:
`new`, `no_longer_reported`, `status_changed` and `context_changed`.
`--fail-on` lets you choose which categories cause exit 1; it never removes
findings from the report.

| Exit | Meaning | Report on stdout |
| --- | --- | --- |
| 0 | The inputs are comparable and no changes match the selected categories. | Complete report |
| 1 | The inputs are comparable and at least one change matches the selected categories. | Complete report |
| 2 | An input, configuration, option, tool or output error occurred. | No usable report; discard any partial output. |
| 3 | The inputs are valid, but their provenance makes them incomparable. | Complete report with reasons |

Errors take precedence over incomparability, which takes precedence over the
selected changes. `--fail-on none` disables exit 1, but cannot turn an error or
incomparable inputs into exit 0. Diagnostics go to stderr. A failed stdout
write returns 2 and can leave partial output.

The [CI shell example](examples/ci.sh) saves JSON to `dist/ci/report.json` and
passes each exit status back to its caller. From the repository root, after
the build above, run:

```sh
compare_exit=0
sh examples/ci.sh \
  --baseline examples/quickstart/baseline.json \
  --baseline-meta examples/quickstart/baseline.meta.json \
  --candidate examples/quickstart/candidate.json \
  --candidate-meta examples/quickstart/candidate.meta.json \
  --format json || compare_exit=$?
test "$compare_exit" -eq 1
```

For Go applications, the [library guide](docs/library.md) explains how to read
inputs, compare them and handle the decision. The complete example uses only
the public package. Run it from the same repository root:

```sh
go run ./examples/library
```

It writes the example's JSON report and exits successfully. Applications
choose how to handle `Report.Decision`; a valid comparison decision is not a
Go error.

## Compare your own reports

Collect each report and its metadata from the same build using the
[provenance guide](docs/provenance.md). Yocto recipe reports normally appear
under `tmp/deploy/cve/*_cve.json`, and image JSON reports under
`tmp/deploy/images/<machine>/` in the Yocto build directory. See
[Yocto's vulnerability guide](https://docs.yoctoproject.org/scarthgap/dev-manual/vulnerabilities.html)
for report generation.

Read the [CLI guide](docs/usage.md) for categories, options and report
interpretation, or the [input guide](docs/limits.md) for accepted fields,
validation rules and limits. The [technical contract](docs/contracts.md) and
[report schema](schemas/report-v1.schema.json) define the exact data formats.

CVEDelta v1.0.1 does not accept SPDX, CycloneDX, `sbom-cve-check` or other
scanners. It does not download CVE databases, score risk, decide whether a
vulnerability applies to a product, author VEX documents or remediate findings.

## Verify and package the source

Full verification requires Python 3 and a C compiler as well as the pinned Go
toolchain. The [build guide](build/README.md) describes the supported Linux
amd64 environment and host alternatives. On ARM64 hosts, follow the complete
workflow in that guide for setup, verification and packaging, retaining its
explicit Docker context and QEMU setting on each command.

The commands below apply to native Linux amd64 or another amd64 host with a
prepared default Docker context. Prepare the image and dependency cache with
network access:

```sh
make setup-linux
```

Then run verification and packaging offline:

```sh
make verify-linux
make package
```

Verification checks formatting, vet, race-enabled tests, schemas, expected
output and reproduction of the pinned producer fixture. Acceptance checks the
real CLI's four exit statuses, agreement with the library in both formats,
deterministic output, examples and unchanged input bytes. The build guide also
documents `make verify` and `make acceptance` for a prepared development host.

Packaging creates `dist/package/cvedelta-v1.0.1-linux-amd64.tar.gz`, `.zip`
and `SHA256SUMS`. It checks archive contents and extracted bytes, then tests
each packaged binary's version and four comparison exit statuses. Archives
contain the binary, schemas, example inputs and guides. Full source verification
and `go run` examples require a repository checkout. Creating packages does not
publish a release.

## About Firmdura

This repository contains a standalone verification utility from
[Firmdura](https://firmdura.com). Firmdura's commercial offer is shared embedded
Linux security maintenance through versioned security layers or patch overlays
for agreed user-space components.

## Licenses and fixture sources

Original code, documentation and original fixtures use [Apache-2.0](LICENSE).
The [pinned producer fixture](testdata/provenance/producer/README.md) retains
OpenEmbedded's MIT sources and notice. It is genuine writer output generated
from invented local data, rather than a firmware build or vulnerability scan.
Binary archives retain Go runtime and standard-library notices under
`third_party/go/`. The JSON Schema validator dependency is used only for
verification.
