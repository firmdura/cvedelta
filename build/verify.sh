#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/.."
. build/environment.sh

# Refuse automatic toolchain or dependency downloads during verification.
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOPROXY=off GOSUMDB=off
# Mandatory verification runs the complete suite with the race defaults.
export GOFLAGS= GORACE=
go_bin=${GO:-go}
actual_version=$("$go_bin" env GOVERSION)
if [ "$actual_version" != "$CVDELTA_GO_VERSION" ]; then
    echo "verify: requires $CVDELTA_GO_VERSION; found $actual_version (use make setup-linux then make verify-foundation-linux)" >&2
    exit 1
fi
mkdir -p dist/cache/go-build dist/cache/go-mod
export GOCACHE=${GOCACHE:-"$(pwd)/dist/cache/go-build"}
export GOMODCACHE=${GOMODCACHE:-"$(pwd)/dist/cache/go-mod"}
gofmt_bin=$("$go_bin" env GOROOT)/bin/gofmt
unformatted=$(find . -type d \( -name .git -o -name dist \) -prune -o -type f -name '*.go' -exec "$gofmt_bin" -l {} +)
if [ -n "$unformatted" ]; then
    echo 'verify: gofmt is required for:' >&2
    printf '%s\n' "$unformatted" >&2
    exit 1
fi
python3 testdata/provenance/producer/reproduce.py --check
"$go_bin" vet ./...
# A broken race runtime can exit zero before testing.Main starts. Require
# actual test events in every package containing tests, not just go's exit code.
python3 - "$go_bin" <<'PY'
import json
import subprocess
import sys

go = sys.argv[1]
expected = set(subprocess.check_output(
    [go, "list", "-race", "-f", "{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}", "./..."],
    text=True,
).split())
process = subprocess.Popen(
    [go, "test", "-race", "-count=1", "-json", "./..."],
    stdout=subprocess.PIPE, text=True,
)
started, completed, passed, packages = set(), set(), set(), set()
invalid = False
for line in process.stdout:
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        print(line, end="", flush=True)
        invalid = True
        continue
    if "Output" in event:
        print(event["Output"], end="", flush=True)
    package, test, action = event.get("Package"), event.get("Test"), event.get("Action")
    if test:
        key = (package, test)
        if action == "run":
            started.add(key)
        elif action in ("pass", "skip"):
            completed.add(key)
            if action == "pass":
                passed.add(package)
    elif action == "pass":
        packages.add(package)
    if action == "fail":
        invalid = True
status = process.wait()
missing = expected - (passed & packages)
if status or invalid or missing or started != completed or not expected:
    print("verify: race tests failed or did not execute completely", file=sys.stderr)
    for package in sorted(missing):
        print(f"verify: no completed passing race tests: {package}", file=sys.stderr)
    sys.exit(1)
print(f"verify: confirmed race test execution in {len(expected)} packages")
PY
