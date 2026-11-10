"""Verify copied Windows campaign files against endpoint-recorded SHA-256 hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def verify(source_hash_file: Path, campaign_dir: Path, expected_count: int) -> dict[str, Any]:
    entries = []
    seen: set[str] = set()
    for line_number, line in enumerate(source_hash_file.read_text(encoding="utf-8-sig").splitlines(), start=1):
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+(.+)", line.strip())
        if not match:
            raise ValueError(f"Malformed source hash record at line {line_number}.")
        expected, relative = match.groups()
        relative = relative.replace("\\", "/")
        if relative in seen:
            raise ValueError(f"Duplicate source hash path: {relative}")
        seen.add(relative)
        local_path = campaign_dir / relative
        actual = digest(local_path) if local_path.is_file() else None
        entries.append({
            "relative_path": relative,
            "endpoint_sha256": expected.lower(),
            "local_sha256": actual,
            "status": "PASS" if actual == expected.lower() else "FAIL",
        })
    return {
        "schema_version": "1.0",
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "endpoint_source_hash_file_sha256": digest(source_hash_file),
        "expected_hash_records": expected_count,
        "observed_hash_records": len(entries),
        "status": "PASS" if len(entries) == expected_count and all(item["status"] == "PASS" for item in entries) else "FAIL",
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-hashes", type=Path, required=True)
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--expected-records", type=int, default=22)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.source_hashes, args.campaign_dir, args.expected_records)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "observed_hash_records": result["observed_hash_records"]}, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
