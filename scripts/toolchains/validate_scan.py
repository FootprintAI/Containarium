#!/usr/bin/env python3
"""Refuse a source-only Trivy report for a deployed toolchain tree."""
import json
from pathlib import Path
import sys


def extra_binaries(manifest):
    """Tree-relative paths of the executables a deployer lock added."""
    return [f"extra/{t['name']}/{b}" for t in manifest.get("tools", [])
            if t.get("source") == "extra" for b in t.get("bin", [])]


def validate(report, extra=()):
    binaries = {r["Target"] for r in report.get("Results", []) if r.get("Type") == "gobinary"}
    targets = {r["Target"] for r in report.get("Results", [])}
    for path in ("go/bin/go", "bin/buf", "staticcheck/staticcheck"):
        if not any(target == path or target.endswith("/" + path) for target in binaries):
            raise ValueError(f"missing binary scan coverage: {path}")
    for path in extra:
        if not any(target == path or target.endswith("/" + path) for target in targets):
            raise ValueError(f"missing binary scan coverage: {path}")
    print(f"Managed Go binary scan coverage: {len(binaries)} executables, {len(list(extra))} extra")


if __name__ == "__main__":
    # usage: validate_scan.py REPORT [MANIFEST]  (MANIFEST adds the extra tools' binaries)
    extra = extra_binaries(json.loads(Path(sys.argv[2]).read_text())) if len(sys.argv) > 2 else []
    validate(json.loads(Path(sys.argv[1]).read_text()), extra)
