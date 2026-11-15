# CLI test input

SPDX-License-Identifier: Apache-2.0

`malformed.json` is original synthetic input that is deliberately invalid.
It contains a harmless marker that tests use to check that command diagnostics
do not echo report contents.

Tests that run the real CLI also reuse the original provenance fixtures and
create adversarial inputs in test directories, with checksums that match those
inputs. None of this data describes a real product or scan.
