# Decision policy test data

SPDX-License-Identifier: Apache-2.0

`selectors.json` contains original test cases for the change-policy syntax.
It contains no scanner data or evidence about firmware.

The tests also use the fixed expected reports in
`testdata/provenance/synthetic/` to check that policy evaluation preserves the
complete comparison and returns the exact expected decision. They inspect the
report values directly rather than deriving decisions from rendered text.
