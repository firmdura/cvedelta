#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serialize explicit coverage policy or metadata; never infer provenance."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


parser = argparse.ArgumentParser(description=__doc__)
sub = parser.add_subparsers(dest="command", required=True)
coverage = sub.add_parser("coverage")
coverage.add_argument("policy", help="explicit policy JSON; arrays of strings only")
metadata = sub.add_parser("metadata")
for name in ("report", "database", "coverage", "configuration-id", "build-id", "source-revision", "scanner-revision"):
    metadata.add_argument("--" + name, required=True)
metadata.add_argument("--complete", required=True, choices=("true", "false"))
args = parser.parse_args()
if args.command == "coverage":
    # Policy is caller-defined. Sort keys and every array of strings; reject
    # other array shapes so no implicit ordering rule changes their meaning.
    def canonical(value):
        if isinstance(value, dict):
            return {k: canonical(v) for k, v in value.items()}
        if isinstance(value, list):
            if not all(isinstance(v, str) for v in value):
                raise ValueError("coverage lists must contain strings")
            return sorted(value)
        if not isinstance(value, (str, bool)):
            raise ValueError("coverage scalars must be strings or booleans")
        return value
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate coverage key: " + key)
            result[key] = value
        return result
    value = canonical(json.loads(Path(args.policy).read_text(encoding="utf-8"), object_pairs_hook=unique))
    if not isinstance(value, dict):
        parser.error("coverage policy must be an object")
else:
    for name in ("configuration_id", "build_id", "source_revision", "scanner_revision"):
        if not getattr(args, name).strip():
            parser.error(name + " must be nonblank")
    value = {"schema_version": 1, "report_sha256": sha(args.report),
             "firmware": {"configuration_id": args.configuration_id, "build_id": args.build_id,
                          "source_revision": args.source_revision},
             "scanner": {"name": "yocto-cve-check", "revision": args.scanner_revision},
             "database": {"sha256": sha(args.database)},
             "coverage": {"scope_sha256": sha(args.coverage), "complete": args.complete == "true"}}
sys.stdout.buffer.write(encode(value).encode("utf-8"))
