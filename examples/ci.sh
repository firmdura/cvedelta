#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run from the repository root after make build. Forward compare flags.
set -eu
if [ "$#" -eq 1 ]; then
    case "$1" in
        -h|--help) exec "${CVEDELTA_BINARY:-./dist/cvedelta}" compare "$1" ;;
    esac
fi
mkdir -p dist/ci
status=0
"${CVEDELTA_BINARY:-./dist/cvedelta}" compare "$@" > dist/ci/report.json || status=$?
case "$status" in
    0) echo 'Comparable; no selected changes.' >&2 ;;
    1) echo 'Comparable; selected observed changes require review.' >&2 ;;
    2) echo 'Invalid input, configuration, tool or output error; no valid decision.' >&2 ;;
    3) echo 'Observed report retained; provenance prevents comparison gating.' >&2 ;;
    *) echo "Unexpected process failure: $status" >&2 ;;
esac
# Keep 1, 2 and 3 distinct for the caller. Report JSON is meaningful for 0/1/3;
# output errors (2) can leave partial bytes, so never consume it as a report.
exit "$status"
