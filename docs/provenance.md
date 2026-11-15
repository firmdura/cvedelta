# Capture provenance from the same build

Provenance records where a report came from: the firmware configuration, build,
scanner revision, database snapshot and scan coverage. Capture that evidence
with each report so you can later compare two builds without guessing how they
were scanned.

CVEDelta checks the report's raw checksum and compares the metadata you supply.
It receives the reports and metadata documents, not the database or coverage
policy files. It therefore cannot recompute those two hashes, confirm that the
scanner used a particular database, or establish that every recipe was covered.
Matching metadata is necessary for comparability; it does not establish the
truth or completeness of a report. If historical evidence is missing, rebuild
under recorded conditions instead of substituting current or guessed values.

This documentation uses Apache-2.0. Run repository examples from the repository
root with Python 3 installed. The production capture procedure also requires
your configured Yocto build environment, Git and Python's `sqlite3` module.
Shell examples use Linux's `sha256sum`; on macOS, use `shasum -a 256` to compute
a hash and `shasum -a 256 -c` to check a checksum file.

## 1. Select the producer and report

CVEDelta supports the [Scarthgap cve-check version-1 JSON
format](https://docs.yoctoproject.org/scarthgap/dev-manual/vulnerabilities.html).
Enable cve-check and JSON output in your Yocto build configuration:

```bitbake
INHERIT += "cve-check"
CVE_CHECK_FORMAT_JSON = "1"
```

Recipe reports are written to `tmp/deploy/cve/<PN>_cve.json`, where `<PN>` is
the recipe's package name. Image reports are under
`tmp/deploy/images/<machine>/`. With `CVE_CHECK_CREATE_MANIFEST = "1"`, the
pinned producer class defaults to `${IMAGE_NAME}.json`. Check the resolved
`CVE_CHECK_MANIFEST_JSON` and `DEPLOY_DIR_IMAGE` values in your build. Resolve
symlinks to the completed build's artifact and confirm that it belongs to that
build. Use the JSON cve-check report; `sbom-cve-check` and text reports are
unsupported.

Set `OECORE` to your producer layer checkout. Record its immutable Git commit,
including any local producer changes in a committed revision:

```sh
test -z "$(git -C "$OECORE" status --porcelain)"
git -C "$OECORE" rev-parse HEAD
```

The first command must succeed: uncommitted producer changes would make the
recorded revision incomplete. A release nickname alone does not identify
modified scanner code. `scanner.revision` must account for local code and
configuration that affect producer semantics. Record all firmware source and
layer revisions in an immutable build manifest, then use the manifest's revision
or content digest as `firmware.source_revision`.

Manage `firmware.configuration_id` explicitly for the target, machine, distro,
image and relevant configuration. Reuse it only when those choices represent
the same intended firmware configuration. Give each build a unique `build_id`.
Build IDs and source revisions may differ between compared reports; a
configuration ID mismatch is invalid comparison input. Keep build IDs and
package versions out of the coverage policy.

## 2. Freeze the database before scanning

Acquiring a database is a separate preparation step that may require network
access. After preparation, stop all database writers and create a consistent,
standalone SQLite snapshot. A live SQLite main file can omit committed data
held in its write-ahead log (WAL). Python's backup API includes that data.

Set `SOURCE_DB` to the prepared database's path and `SNAPSHOT` to a new file
path chosen for this capture. The snapshot's parent directory must already
exist. Then run:

```sh
python3 - "$SOURCE_DB" "$SNAPSHOT" <<'PY'
from pathlib import Path
import sqlite3
import sys
source, target = map(Path, sys.argv[1:])
if target.exists():
    raise SystemExit('refusing to replace an existing snapshot')
with sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True) as src:
    with sqlite3.connect(target) as dst:
        src.backup(dst)
        if dst.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise SystemExit('snapshot integrity check failed')
PY
sha256sum "$SNAPSHOT"
```

Use a fresh Yocto `TMPDIR` for the build so cached scan tasks or stale report
fragments cannot replace a new scan. The pinned producer declares
`do_cve_check[depends] = "cve-update-nvd2-native:do_unpack"`. Its
[database updater](https://github.com/openembedded/openembedded-core/blob/fc4316861becc9f0d41857b49f6438929ab4c291/meta/recipes-core/meta/cve-update-nvd2-native.bb)
skips fetching and updating when `CVE_DB_UPDATE_INTERVAL = "-1"`, but `do_unpack`
still copies `CVE_CHECK_DB_DLDIR_FILE` to `CVE_CHECK_DB_FILE`.
**Setting `CVE_CHECK_DB_FILE` alone does not freeze the database.**

For this pinned producer, use the frozen snapshot as the download input and a
separate writable file as the scanner's staged input. Replace the example paths
below with the absolute paths chosen for your build:

```bitbake
CVE_DB_UPDATE_INTERVAL = "-1"
CVE_CHECK_DB_DLDIR_FILE = "/absolute/capture/snapshot.db"
CVE_CHECK_DB_FILE = "/absolute/capture/scanner.db"
```

The snapshot's parent directory must allow lock files. Reserve the capture
directory for this build and prevent concurrent updates. Keep the source and
staged paths distinct because the unpack task copies between them.

In the configured Yocto environment, stage the snapshot:

```sh
bitbake -c unpack cve-update-nvd2-native
```

Inspect `bitbake -e cve-update-nvd2-native` and `bitbake -e` for a selected
recipe. Confirm the resolved paths, update interval and scanner settings. If
you have patched the updater, inspect that code rather than assuming the same
variables still control it. Retain the resolved configuration and task logs
with the build evidence.

Set `SCANNER_DB` to the actual `CVE_CHECK_DB_FILE` path and `CAPTURE` to the
capture directory. Before the fresh image build, verify that the staged file
matches the snapshot and record its checksum. After the build, check that the
scanner file is unchanged and still matches the snapshot:

```sh
cmp "$SNAPSHOT" "$SCANNER_DB"
sha256sum "$SCANNER_DB" > "$CAPTURE/database.before.sha256"
# Run your configured image build here. All selected tasks must pass.
# For example: bitbake core-image-minimal
# Use that example target only if it is the image declared in your policy.
sha256sum -c "$CAPTURE/database.before.sha256"
cmp "$SNAPSHOT" "$SCANNER_DB"
```

An unchanged hash establishes consistency, not correct scanner behavior. Retain
the database snapshot, resolved configuration and evidence that the selected
tasks succeeded. Do not run another build or update until capture is complete.
A newly downloaded or subsequently updated database cannot describe the
conditions that produced an earlier report.

## 3. Define and serialize coverage consistently

The coverage policy must describe what the scan was intended to cover. Include:

- The image or target, machine and distro.
- Exact selected recipe names and layers, including native and multilib
  variants, plus every intentional omission and its reason.
- `CVE_CHECK_SKIP_RECIPE`, layer include and exclude lists, `CVE_CHECK_COVERAGE`,
  `CVE_CHECK_REPORT_PATCHED`, and JSON and manifest settings.
- Relevant exclusions, such as `cve-extra-exclusions.inc`, any local skip logic,
  and immutable content identities for external policy files.

Build this policy from the resolved per-recipe configuration, task graph, logs
and image selection. The report alone cannot establish which recipes were
omitted.

[coverage-source.json](../examples/quickstart/coverage-source.json) is an
original synthetic example, not production coverage evidence. Adapt its
structure to your build. The helper accepts nested objects, arrays whose
elements are all strings, and scalar values that are strings or booleans.
For example, a recipe list can contain `"meta/alpha-native"`, and an omission
list can contain `"meta/skipped: reason"`. Numbers, nulls, other array types,
duplicate object keys and a non-object root are rejected.

`examples/provenance.py coverage` sorts object keys and every string array,
then writes compact UTF-8 JSON without ASCII escaping, using LF and one final
newline. This is canonicalization: the same policy values produce the same
bytes. The helper only serializes the policy; you define its schema and are
responsible for its meaning and completeness. Keep policy entries stable when
coverage is unchanged, and preserve and reuse the resulting bytes.

To reproduce the repository example:

```sh
mkdir -p dist/provenance
python3 examples/provenance.py coverage examples/quickstart/coverage-source.json \
  > dist/provenance/coverage-policy.json
cmp dist/provenance/coverage-policy.json examples/quickstart/coverage-policy.json
sha256sum dist/provenance/coverage-policy.json
```

Set `complete:true` only after the declared selection has finished reporting
and the policy accounts for every omission. Unknown, missing or failed coverage
does not establish a complete empty scan. If coverage is uncertain, supply the
known policy and set `complete:false`; CVEDelta will produce an incomparable
observed report and exit 3.

## 4. Create the metadata document

After the build completes, preserve the raw report without reformatting it.
Set `REPORT` to that file's path, `SCANNER_DB` to the unchanged database used
for the scan, and `POLICY` to the canonical coverage-policy file. Hash the exact
files:

```sh
sha256sum "$REPORT" "$SCANNER_DB" "$POLICY"
```

Every metadata field below is mandatory. CVEDelta applies no filename, clock
or environment defaults. All hashes must contain exactly 64 lowercase
hexadecimal characters. The angle-bracket values explain the fields; replace
them with your captured values before using the document.

```json
{
  "schema_version": 1,
  "report_sha256": "<raw report SHA-256>",
  "firmware": {
    "configuration_id": "<managed target:machine:distro:image identity>",
    "build_id": "<explicit completed build label>",
    "source_revision": "<immutable firmware source/build manifest revision>"
  },
  "scanner": {"name": "yocto-cve-check", "revision": "<immutable producer revision>"},
  "database": {"sha256": "<actual scan database SHA-256>"},
  "coverage": {"scope_sha256": "<canonical policy SHA-256>", "complete": true}
}
```

[metadata-v1.schema.json](../schemas/metadata-v1.schema.json) defines the exact
structure; unknown fields are rejected. The metadata helper requires explicit
identities and a completeness value. It hashes the supplied files without
modifying them, but cannot establish that they were used together.

The following synthetic example is runnable from the repository root. It
creates metadata whose bytes match the checked-in example:

```sh
mkdir -p dist/provenance
python3 examples/provenance.py metadata \
  --report examples/quickstart/baseline.json \
  --database examples/quickstart/database.json \
  --coverage examples/quickstart/coverage-policy.json \
  --configuration-id demo:demo-machine:demo-distro:demo-image \
  --build-id demo-before --source-revision original-synthetic-before \
  --scanner-revision original-synthetic-producer-v1 --complete true \
  > dist/provenance/baseline.meta.json
cmp dist/provenance/baseline.meta.json examples/quickstart/baseline.meta.json
```

For a production report, supply the captured report, database, policy and
immutable identities from the same completed build. Synthetic values cannot
replace missing evidence. Retain each side's report, metadata, policy, database
snapshot and build evidence under your artifact retention controls. CVEDelta
reads the report and metadata streams without modifying or executing them.

## Fixture provenance

The [producer fixture](../testdata/provenance/producer/README.md) pins public
OpenEmbedded sources and retains their MIT notice. Its exact writer output is
reproduced offline using invented local data, without a full Yocto build or
real NVD database scan. The quick start and other synthetic fixtures use
Apache-2.0. Their hashes test whether metadata matches exact file bytes and
whether comparison behaves as expected. They establish no real vulnerability,
applicability, coverage or remediation claim.
