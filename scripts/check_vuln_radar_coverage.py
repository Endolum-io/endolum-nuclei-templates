#!/usr/bin/env python3
"""Fail when a verified Vuln Radar detector is absent from this repository."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUN_ROOT = ROOT.parent / "ops" / "marketing" / "vuln-radar"
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text()) or {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    args = parser.parse_args()

    if not args.run_root.is_dir():
        print(f"error: Vuln Radar run directory is unavailable: {args.run_root}", file=sys.stderr)
        return 1

    repository = {}
    for path in sorted((ROOT / "cves").glob("*.yaml")):
        template_id = str(load(path).get("id", "")).strip()
        if template_id:
            repository[template_id] = path

    required = []
    skipped = []
    errors = []
    for path in sorted(args.run_root.glob("*/*.yaml")):
        document = load(path)
        template_id = str(document.get("id", "")).strip()
        info = document.get("info") or {}
        severity = str(info.get("severity", "")).strip().lower()
        verified = bool((info.get("metadata") or {}).get("verified"))
        if verified and severity in ALLOWED_SEVERITIES:
            required.append((template_id, path))
            if template_id not in repository:
                errors.append(f"{template_id}: missing from cves/ (source: {path})")
        else:
            skipped.append((template_id, severity or "missing", verified, path))

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"coverage passed: {len(required)} verified Vuln Radar detectors are present")
    for template_id, severity, verified, path in skipped:
        print(
            f"skipped: {template_id} ({severity}, verified={str(verified).lower()}) "
            f"does not qualify for scanner distribution: {path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
