"""Apply the current identity-comparison policy to archived JSON result artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "experiments/results"


def _normalize(value: Any) -> int:
    changed = 0
    if isinstance(value, dict):
        cross_validation = value.get("cross_validation")
        categories = (
            (cross_validation or {}).get("categories")
            if isinstance(cross_validation, dict)
            else None
        )
        if isinstance(categories, dict):
            for category in ("process", "listener"):
                comparison = categories.get(category)
                if not isinstance(comparison, dict):
                    continue
                expected = {
                    "comparable": False,
                    "comparison_status": "identity_schema_incompatible",
                    "jaccard_similarity": None,
                }
                if any(comparison.get(key) != item for key, item in expected.items()):
                    comparison.update(expected)
                    changed += 1
        for child in value.values():
            changed += _normalize(child)
    elif isinstance(value, list):
        for child in value:
            changed += _normalize(child)
    return changed


def migrate(*, apply: bool) -> dict[str, int]:
    changed_files: dict[str, int] = {}
    for path in sorted(RESULTS.rglob("*.json")):
        if path.name == "research-freeze-20260923.json":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        changed = _normalize(payload)
        if changed and apply:
            path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        if changed:
            changed_files[str(path.relative_to(ROOT))] = changed
    return changed_files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="rewrite affected result artifacts")
    args = parser.parse_args()
    changed = migrate(apply=args.apply)
    print(json.dumps({"apply": args.apply, "files": changed, "file_count": len(changed)}, indent=2))


if __name__ == "__main__":
    main()
