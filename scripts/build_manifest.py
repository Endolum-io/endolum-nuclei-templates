#!/usr/bin/env python3
"""Regenerate manifest.json from the templates in cves/.

The manifest is what the scanners read. They fetch it on every scan, compare
`version` against the copy they already hold, and download the bundle only when
it differs. `version` is derived from the content itself, so it changes when and
only when a template changes and nobody has to remember to bump it.

Run with --check to verify the committed manifest matches the tree. That is what
CI does, which keeps the manifest a hand committed file rather than something a
bot writes back into the repo.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = ROOT / "cves"
MANIFEST = ROOT / "manifest.json"

# The scanners run nuclei with -severity critical,high,medium,low. A template
# outside that set loads and matches but its findings are dropped before they
# ever reach a report, so it is treated as an error here rather than shipped.
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect() -> tuple[list[dict], list[str]]:
    entries: list[dict] = []
    errors: list[str] = []
    seen_ids: dict[str, str] = {}

    for path in sorted(TEMPLATE_DIR.rglob("*.yaml")):
        rel = path.relative_to(ROOT).as_posix()
        try:
            doc = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as exc:
            errors.append(f"{rel}: not parseable as YAML: {exc}")
            continue

        template_id = str(doc.get("id", "")).strip()
        info = doc.get("info") or {}
        severity = str(info.get("severity", "")).strip().lower()

        if not template_id:
            errors.append(f"{rel}: missing id")
        elif template_id in seen_ids:
            errors.append(f"{rel}: id {template_id} already used by {seen_ids[template_id]}")
        else:
            seen_ids[template_id] = rel

        if severity not in ALLOWED_SEVERITIES:
            errors.append(
                f"{rel}: severity {severity or 'missing'} is outside "
                f"{sorted(ALLOWED_SEVERITIES)}, so the scanners would drop its findings"
            )

        entries.append({
            "path": rel,
            "id": template_id,
            "severity": severity,
            "sha256": file_sha256(path),
        })

    if not entries:
        errors.append("no templates found under cves/")

    return entries, errors


def build(entries: list[dict]) -> dict:
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(f"{entry['path']}:{entry['sha256']}\n".encode())
    return {
        "version": digest.hexdigest()[:12],
        "count": len(entries),
        "templates": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed manifest matches the tree instead of rewriting it",
    )
    args = parser.parse_args()

    entries, errors = collect()
    if errors:
        for err in errors:
            print(f"error: {err}", file=sys.stderr)
        return 1

    manifest = build(entries)
    rendered = json.dumps(manifest, indent=2) + "\n"

    if args.check:
        current = MANIFEST.read_text() if MANIFEST.exists() else ""
        if current != rendered:
            print(
                "error: manifest.json is out of date, run scripts/build_manifest.py",
                file=sys.stderr,
            )
            return 1
        print(f"manifest.json is current: version {manifest['version']}, {manifest['count']} templates")
        return 0

    MANIFEST.write_text(rendered)
    print(f"wrote manifest.json: version {manifest['version']}, {manifest['count']} templates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
