#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/.."
. build/environment.sh
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS=
go_bin=${GO:-go}
[ "$("$go_bin" env GOVERSION)" = "$CVDELTA_GO_VERSION" ] || { echo "acceptance: requires $CVDELTA_GO_VERSION" >&2; exit 1; }
mkdir -p dist/acceptance dist/cache/go-build dist/cache/go-mod
export GOCACHE=${GOCACHE:-"$(pwd)/dist/cache/go-build"}
export GOMODCACHE=${GOMODCACHE:-"$(pwd)/dist/cache/go-mod"}
python3 testdata/provenance/producer/reproduce.py --check
"$go_bin" build -buildvcs=false -trimpath -o dist/acceptance/cvedelta ./cmd/cvedelta
export CVEDELTA_BINARY="$(pwd)/dist/acceptance/cvedelta"
"$go_bin" test -count=1 -v ./examples/acceptance
"$go_bin" run ./examples/library > dist/acceptance/library.json
python3 -m json.tool dist/acceptance/library.json > /dev/null
status=0
"$CVEDELTA_BINARY" compare --baseline examples/quickstart/baseline.json \
    --baseline-meta examples/quickstart/baseline.meta.json \
    --candidate examples/quickstart/candidate.json \
    --candidate-meta examples/quickstart/candidate.meta.json \
    --format json > dist/acceptance/cli.json || status=$?
[ "$status" -eq 1 ] || { echo 'acceptance: quick-start CLI expected exit 1' >&2; exit 1; }
cmp dist/acceptance/library.json dist/acceptance/cli.json
echo 'acceptance: real CLI outcomes, schemas, library parity and examples passed'
